"""Generate the contract artifacts of the developer surface from the code that implements them.

``python -m acf_api.contract.generate --out protocols`` writes:

* ``api/openapi.yaml``: the REST surface, OpenAPI 3.2;
* ``api/surface.yaml``: the public operations and each of their projections;
* ``api/problems/registry.yaml``: every code, its problem type, kind, retry advice and HTTP status;
* ``api/mapping/acf.host-2.yaml``: the mapping between the public vocabularies and the host's;
* ``mcp/tools/<name>.json``: one tool definition per file, with input and output schemas;
* ``mcp/catalogue.json``: the names, annotations and schema digests of the catalogue;
* ``conformance/scenarios.json``: the client conformance suite.

``--check`` writes nothing and fails when a checked-in file differs from what the code generates, so
an encoding cannot drift from the implementation unnoticed. The contract governs both: a mismatch
between this output and the contract is a defect here, and the tests under ``tests/contract`` look
for one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic.json_schema import models_json_schema

from acf_api import __version__
from acf_api.command import model as m
from acf_api.command.answers import IDEMPOTENCY_KEY_HARD_MAX
from acf_api.command.commands import REVISION_PATTERN
from acf_api.command.errors import CODES, Code, problem_type
from acf_api.command.surface import OPERATIONS, OperationClass
from acf_api.contract import conformance
from acf_api.core.agent import catalog
from acf_api.edge.http.routes import ROUTES, QueryParam, RouteSpec

OPENAPI_VERSION: Final = "3.2.0"
#: Version of the described API: the major is the path prefix, and a minor is an additive change.
API_DOCUMENT_VERSION: Final = "1.0.0"
_REF: Final = "#/components/schemas/{model}"

_VIEWS: Final = (
    m.Operation,
    m.Sandbox,
    m.Snapshot,
    m.Execution,
    m.OutputChunk,
    m.SandboxList,
    m.SnapshotList,
    m.OperationList,
    m.AgentCredential,
    m.AgentCredentialList,
    m.WhoAmI,
    m.Info,
    m.Problem,
)
_BODIES: Final = (
    m.SandboxSpec,
    m.TargetBody,
    m.ExecSpec,
    m.SnapshotSpec,
    m.RestoreSpec,
    m.MintAgentCredentialSpec,
    m.Grant,
)

_PATH_PARAMS: Final[dict[str, tuple[str, str]]] = {
    "project": (
        m.PROJECT_ID_PATTERN,
        "The project the request acts in. It must be the project the credential is bound to.",
    ),
    "sandbox": (r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}$", "A sandbox identifier. A read also accepts a sandbox name."),
    "snapshot": (m.SNAPSHOT_ID_PATTERN, "A snapshot identifier."),
    "execution": (m.EXECUTION_ID_PATTERN, "An execution identifier."),
    "operation": (m.OPERATION_ID_PATTERN, "An operation identifier."),
    "credential": (m.CREDENTIAL_ID_PATTERN, "A credential identifier."),
}


def _components() -> dict[str, Any]:
    pairs = [(model, "serialization") for model in _VIEWS] + [(model, "validation") for model in _BODIES]
    _, top = models_json_schema(pairs, ref_template=_REF)  # type: ignore[arg-type]
    schemas: dict[str, Any] = dict(sorted(top.get("$defs", {}).items()))
    return schemas


def _query_schema(param: QueryParam) -> dict[str, Any]:
    if param.kind == "generation":
        return {"oneOf": [{"type": "integer", "minimum": 1}, {"type": "string", "const": "current"}]}
    if param.kind == "stream":
        return {"type": "string", "enum": ["stdout", "stderr"], "default": "stdout"}
    if param.kind == "int":
        schema: dict[str, Any] = {"type": "integer"}
        if param.minimum is not None:
            schema["minimum"] = param.minimum
        if param.maximum is not None:
            schema["maximum"] = param.maximum
        return schema
    return {"type": "string", "maxLength": 512}


def _parameters(route: RouteSpec) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name in route.path_params:
        pattern, description = _PATH_PARAMS[name]
        out.append(
            {
                "name": name,
                "in": "path",
                "required": True,
                "description": description,
                "schema": {"type": "string", "pattern": pattern},
            }
        )
    out.extend(
        {
            "name": q.name,
            "in": "query",
            "required": q.required,
            "description": q.description,
            "schema": _query_schema(q),
        }
        for q in route.query
    )
    if route.operation.keyed:
        out.append({"$ref": "#/components/parameters/IdempotencyKey"})
    if route.accepts_if_match:
        out.append({"$ref": "#/components/parameters/IfMatch"})
    out.append({"$ref": "#/components/parameters/Traceparent"})
    return out


def _view_ref(route: RouteSpec) -> dict[str, Any]:
    return {"$ref": _REF.format(model=route.view.__name__)}


def _success(route: RouteSpec) -> dict[str, Any]:
    content = {"application/json": {"schema": _view_ref(route)}}
    common = {"X-Request-Id": {"$ref": "#/components/headers/RequestId"}}
    if route.answers_operation:
        replayed = {"Idempotent-Replayed": {"$ref": "#/components/headers/IdempotentReplayed"}}
        return {
            "200": {
                "description": "The operation, in a state in which it has ended.",
                "headers": {**common, **replayed},
                "content": content,
            },
            "202": {
                "description": (
                    "The operation, accepted and not ended within the wait. Follow it at `Location`, "
                    "not sooner than `Retry-After`."
                ),
                "headers": {
                    **common,
                    **replayed,
                    "Location": {"$ref": "#/components/headers/Location"},
                    "Retry-After": {"$ref": "#/components/headers/RetryAfter"},
                },
                "content": content,
            },
        }
    headers: dict[str, Any] = dict(common)
    if route.view in {m.Sandbox}:
        headers["ETag"] = {"$ref": "#/components/headers/ETag"}
    return {str(route.success_status): {"description": "Success.", "headers": headers, "content": content}}


def _error_statuses() -> dict[int, list[str]]:
    by_status: dict[int, list[str]] = {}
    for code, info in CODES.items():
        if info.kind is None or info.http_status is None:
            continue
        by_status.setdefault(info.http_status, []).append(code.value)
    return dict(sorted(by_status.items()))


def _error_responses() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for status in _error_statuses():
        out[str(status)] = {"$ref": f"#/components/responses/Problem{status}"}
    return out


def _problem_responses() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for status, codes in _error_statuses().items():
        headers: dict[str, Any] = {"X-Request-Id": {"$ref": "#/components/headers/RequestId"}}
        if any(CODES[Code(c)].retry_after for c in codes):
            headers["Retry-After"] = {"$ref": "#/components/headers/RetryAfter"}
        if status == 401:  # noqa: PLR2004 - the status that carries a challenge
            headers["WWW-Authenticate"] = {"schema": {"type": "string"}, "description": "The challenge."}
        out[f"Problem{status}"] = {
            "description": "An error answer. `code` is authoritative; this status is a hint. Codes: "
            + ", ".join(codes)
            + ".",
            "headers": headers,
            "content": {"application/problem+json": {"schema": {"$ref": _REF.format(model="Problem")}}},
        }
    return out


def _operation(route: RouteSpec) -> dict[str, Any]:
    op = route.operation
    item: dict[str, Any] = {
        "operationId": op.method,
        "summary": op.summary,
        "tags": [op.method.split(".", 1)[0]],
        "x-acf-class": op.operation_class.value,
        "parameters": _parameters(route),
    }
    if op.reversibility is not None:
        item["x-acf-reversibility"] = op.reversibility.value
    if route.body is not None:
        item["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": {"$ref": _REF.format(model=route.body.__name__)}}},
        }
    item["responses"] = {**_success(route), **_error_responses()}
    item["security"] = [{}, {"bearer": []}] if route.anonymous else [{"bearer": []}]
    return item


def build_openapi() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for route in ROUTES:
        paths.setdefault(route.path, {})[route.method.lower()] = _operation(route)
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "Agent Compute Fabric public API",
            "version": API_DOCUMENT_VERSION,
            "summary": "Sandboxes, executions, snapshots and operations for developers and agents.",
            "description": (
                "Every mutation is an operation that may outlive the request that started it. A mutation carries "
                "an `Idempotency-Key`; repeating the request with the same key and the same body never creates a "
                "second operation. An unsuccessful answer is one of two kinds: `REFUSED` (nothing exists) or "
                "`UNRESOLVED` (the platform could not establish whether the request was accepted). Clients decide "
                "from `kind`, `code` and `retry`, never from the HTTP status alone, and treat an operation in state "
                "`UNKNOWN` as neither success nor failure. Request bodies are strict: a member the schema does not "
                "define, or a repeated member name, is refused."
            ),
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "servers": [{"url": "/", "description": "The address the operator of the deployment chose."}],
        "tags": [
            {"name": "sandbox"},
            {"name": "execution"},
            {"name": "snapshot"},
            {"name": "operation"},
            {"name": "agent_credential"},
            {"name": "auth"},
            {"name": "platform"},
        ],
        "paths": dict(sorted(paths.items())),
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A platform API key. Never accepted in a URL.",
                }
            },
            "parameters": {
                "IdempotencyKey": {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": True,
                    "description": (
                        "One key per intent, created before the first attempt and reused by every retry. "
                        "Characters 0x21 to 0x7E, compared byte for byte."
                    ),
                    "schema": {"type": "string", "minLength": 1, "maxLength": IDEMPOTENCY_KEY_HARD_MAX},
                },
                "IfMatch": {
                    "name": "If-Match",
                    "in": "header",
                    "required": False,
                    "description": "The `ETag` of the sandbox as last read. A stronger precondition than the generation.",
                    "schema": {"type": "string"},
                },
                "Traceparent": {
                    "name": "traceparent",
                    "in": "header",
                    "required": False,
                    "description": "W3C trace context. An invalid value is ignored, never an error.",
                    "schema": {"type": "string"},
                },
            },
            "headers": {
                "RequestId": {
                    "description": "The request id. Quote it when asking for help.",
                    "schema": {"type": "string"},
                },
                "Location": {"description": "Where to follow the operation.", "schema": {"type": "string"}},
                "RetryAfter": {"description": "Seconds to wait before asking again.", "schema": {"type": "integer"}},
                "IdempotentReplayed": {
                    "description": "`true` when the answer reports work that existed before this request.",
                    "schema": {"type": "string", "enum": ["true"]},
                },
                "ETag": {
                    "description": "Opaque validator of the resource. Compare for equality only.",
                    "schema": {"type": "string", "pattern": REVISION_PATTERN.replace("^", '^"').replace("$", '"$')},
                },
            },
            "responses": _problem_responses(),
            "schemas": _components(),
        },
    }


def build_surface() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "api_version": m.API_VERSION,
        "operations": [
            {
                "method": op.method,
                "class": op.operation_class.value,
                "rest": f"{op.http_method} {op.path}",
                "tool": op.tool,
                "sdk": op.sdk,
                "cli": op.cli,
                "idempotency_key": op.keyed,
                "reversibility": op.reversibility.value if op.reversibility is not None else None,
                "reaches_host": op.host_method is not None,
                "summary": op.summary,
            }
            for op in OPERATIONS
        ],
        "classes": {
            OperationClass.GRANTING.value: "creates privilege or work; subject to every check of the pipeline",
            OperationClass.CONTAINMENT.value: "removes privilege; never refused for load",
            OperationClass.READ.value: "served from the host every time",
            OperationClass.PLATFORM.value: "changes the platform's own records; reaches no host",
        },
    }


def build_problems() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kinds": {
            "REFUSED": "the request was not accepted; nothing exists",
            "UNRESOLVED": "the platform could not establish whether the request was accepted",
        },
        "retry": {
            "SAME_REQUEST_LATER": "repeat the same request, with the same idempotency key, later",
            "AFTER_CHANGE": "change something first",
            "NEVER": "do not repeat it",
        },
        "codes": [
            {
                "code": info.code.value,
                "type": problem_type(info.code.value),
                "title": info.title,
                "decided_by": info.decided_by,
                "kind": info.kind.value if info.kind is not None else None,
                "retry": info.retry.value,
                "http_status": info.http_status,
                "retry_after": info.retry_after,
                "sdk_exception": info.sdk_exception,
                "error_answer": info.kind is not None,
            }
            for info in CODES.values()
        ],
    }


def mapping_text() -> str:
    return (resources.files("acf_api.core.host") / "data" / "mapping.acf.host-2.yaml").read_text(encoding="utf-8")


def build_tool(spec: catalog.ToolSpec) -> dict[str, Any]:
    definition = catalog.definition(spec)
    return {
        "name": definition.name,
        "title": definition.title,
        "description": definition.description,
        "inputSchema": definition.input_schema,
        "outputSchema": definition.output_schema,
        "annotations": {
            "title": definition.title,
            "readOnlyHint": definition.read_only,
            "destructiveHint": definition.destructive,
            "idempotentHint": definition.idempotent,
            "openWorldHint": definition.open_world,
        },
        "x-acf-method": spec.operation.method,
        "x-acf-class": spec.operation.operation_class.value,
        "x-acf-reversibility": spec.operation.reversibility.value if spec.operation.reversibility is not None else None,
    }


def _json(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _yaml(header: str, value: object) -> str:
    body = yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=120, default_flow_style=False)
    return header + body


_GENERATED: Final = (
    "# Generated from the implementation. Do not edit: run `make platform-artifacts`.\n"
    "# The contract governs this file; a difference between the two is a defect in the encoding.\n"
)


def build_all() -> dict[str, str]:
    """Every artifact, by its path under the output directory."""
    files: dict[str, str] = {
        "api/openapi.yaml": _yaml(_GENERATED, build_openapi()),
        "api/surface.yaml": _yaml(_GENERATED, build_surface()),
        "api/problems/registry.yaml": _yaml(_GENERATED, build_problems()),
        "api/mapping/acf.host-2.yaml": mapping_text(),
    }
    catalogue: list[dict[str, Any]] = []
    for name, spec in catalog.TOOLS.items():
        text = _json(build_tool(spec))
        files[f"mcp/tools/{name}.json"] = text
        annotations = spec.operation.annotations
        catalogue.append(
            {
                "name": name,
                "method": spec.operation.method,
                "class": spec.operation.operation_class.value,
                "creates_operation": spec.creates_operation,
                "readOnlyHint": annotations.read_only if annotations else None,
                "destructiveHint": annotations.destructive if annotations else None,
                "idempotentHint": annotations.idempotent if annotations else None,
                "openWorldHint": annotations.open_world if annotations else None,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
    files["conformance/scenarios.json"] = _json(conformance.build())
    files["mcp/catalogue.json"] = _json(
        {
            "schema_version": 1,
            "generator": f"acf-api {__version__}",
            "protocol_revision": "2026-07-28",
            "tools": catalogue,
        }
    )
    return files


def write(out: Path) -> list[str]:
    written: list[str] = []
    for relative, text in build_all().items():
        path = out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(relative)
    return written


def check(out: Path) -> list[str]:
    """Paths whose checked-in content differs from what the code generates, or that are missing or stale."""
    expected = build_all()
    stale = [
        rel for rel, text in expected.items() if not (out / rel).is_file() or (out / rel).read_text("utf-8") != text
    ]
    tools_dir = out / "mcp" / "tools"
    if tools_dir.is_dir():
        stale.extend(
            f"mcp/tools/{p.name} (no such tool)"
            for p in sorted(tools_dir.glob("*.json"))
            if f"mcp/tools/{p.name}" not in expected
        )
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acf-api-artifacts", description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, required=True, help="the `protocols` directory")
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a checked-in file differs")
    args = parser.parse_args(argv)
    if args.check:
        stale = check(args.out)
        if stale:
            sys.stderr.write("the checked-in contract artifacts differ from what the code generates:\n")
            sys.stderr.writelines(f"  {s}\n" for s in stale)
            sys.stderr.write("run `make platform-artifacts` and commit the result\n")
            return 1
        sys.stdout.write(f"{args.out} is up to date\n")
        return 0
    for relative in write(args.out):
        sys.stdout.write(f"wrote {args.out / relative}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
