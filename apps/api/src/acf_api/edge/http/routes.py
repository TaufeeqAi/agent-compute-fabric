"""The REST routes, as data.

Each row joins a public operation to its HTTP encoding: which path and query parameters it takes,
which body, which view it answers with, and how those become one command. The HTTP adapter serves
this table and the OpenAPI generator describes it, so the two cannot drift apart.

Nothing here decides anything. A row turns caller bytes into a command, and the core decides.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from pydantic import TypeAdapter

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.surface import BY_METHOD, PublicOperation

ParamKind = Literal["int", "str", "generation", "stream"]


@dataclass(frozen=True, slots=True)
class QueryParam:
    name: str
    kind: ParamKind
    description: str
    required: bool = False
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True, slots=True)
class Inputs:
    """What the adapter extracted from one request, already decoded and bounded."""

    path: Mapping[str, str]
    query: Mapping[str, Any]
    body: Any
    if_match: str | None


Builder = Callable[[Inputs], c.Command]


@dataclass(frozen=True, slots=True)
class RouteSpec:
    operation: PublicOperation
    #: The request body model. ``None``: the route takes no body, and one that is sent is refused.
    body: type[m.RequestModel] | None
    #: The view the route answers with on success.
    view: type[m.ViewModel]
    build: Builder
    query: tuple[QueryParam, ...] = ()
    accepts_if_match: bool = False
    #: The route answers an operation: 200 when it has ended, 202 with ``Location`` otherwise.
    answers_operation: bool = False
    #: Status of a successful answer that is not an operation.
    success_status: int = 200
    #: The route may be called without a credential.
    anonymous: bool = False
    path_params: tuple[str, ...] = field(default=())

    @property
    def method(self) -> str:
        return self.operation.http_method

    @property
    def path(self) -> str:
        return self.operation.path


_WAIT: Final = QueryParam(
    "wait",
    "int",
    "Seconds to wait for the operation to end. 0 answers at once. The platform caps it at its `public_wait_max`.",
    minimum=0,
    maximum=3600,
)
_LIMIT: Final = QueryParam("limit", "int", "Page size.", minimum=1, maximum=m.MAX_PAGE_SIZE)
_CURSOR: Final = QueryParam("cursor", "str", "Opaque position returned as `next_cursor` by an earlier page.")
_GENERATION: Final = QueryParam(
    "expected_generation",
    "generation",
    "The generation the request acts on: an integer, or the literal `current`.",
    required=True,
)

_GENERATION_ADAPTER: Final[TypeAdapter[int | Literal["current"]]] = TypeAdapter(m.ExpectedGeneration)


def _op(method: str) -> PublicOperation:
    return BY_METHOD[method]


def _create_sandbox(i: Inputs) -> c.Command:
    return c.CreateSandbox(project=i.path["project"], spec=i.body, wait=i.query.get("wait"))


def _start_sandbox(i: Inputs) -> c.Command:
    return c.StartSandbox(
        project=i.path["project"],
        sandbox_id=i.path["sandbox"],
        expected_generation=i.body.expected_generation,
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _stop_sandbox(i: Inputs) -> c.Command:
    return c.StopSandbox(
        project=i.path["project"],
        sandbox_id=i.path["sandbox"],
        expected_generation=i.body.expected_generation,
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _destroy_sandbox(i: Inputs) -> c.Command:
    return c.DestroySandbox(
        project=i.path["project"],
        sandbox_id=i.path["sandbox"],
        expected_generation=i.query["expected_generation"],
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _exec(i: Inputs) -> c.Command:
    return c.Exec(
        project=i.path["project"],
        sandbox_id=i.path["sandbox"],
        spec=i.body,
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _cancel_execution(i: Inputs) -> c.Command:
    return c.CancelExecution(project=i.path["project"], execution_id=i.path["execution"], wait=i.query.get("wait"))


def _create_snapshot(i: Inputs) -> c.Command:
    return c.CreateSnapshot(
        project=i.path["project"],
        sandbox_id=i.path["sandbox"],
        spec=i.body,
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _restore_snapshot(i: Inputs) -> c.Command:
    return c.RestoreSnapshot(
        project=i.path["project"],
        snapshot_id=i.path["snapshot"],
        spec=i.body,
        if_match=i.if_match,
        wait=i.query.get("wait"),
    )


def _delete_snapshot(i: Inputs) -> c.Command:
    return c.DeleteSnapshot(
        project=i.path["project"],
        snapshot_id=i.path["snapshot"],
        snapshot_generation=i.query["snapshot_generation"],
        wait=i.query.get("wait"),
    )


def _get_operation(i: Inputs) -> c.Command:
    return c.GetOperation(project=i.path["project"], operation_id=i.path["operation"], wait=i.query.get("wait"))


def _list_operations(i: Inputs) -> c.Command:
    return c.ListOperations(project=i.path["project"], limit=i.query.get("limit"), cursor=i.query.get("cursor"))


def _get_sandbox(i: Inputs) -> c.Command:
    return c.GetSandbox(project=i.path["project"], sandbox=i.path["sandbox"])


def _list_sandboxes(i: Inputs) -> c.Command:
    return c.ListSandboxes(project=i.path["project"], limit=i.query.get("limit"), cursor=i.query.get("cursor"))


def _list_snapshots(i: Inputs) -> c.Command:
    return c.ListSnapshots(project=i.path["project"], limit=i.query.get("limit"), cursor=i.query.get("cursor"))


def _get_execution(i: Inputs) -> c.Command:
    return c.GetExecution(project=i.path["project"], execution_id=i.path["execution"])


def _get_execution_output(i: Inputs) -> c.Command:
    return c.GetExecutionOutput(
        project=i.path["project"],
        execution_id=i.path["execution"],
        stream=m.OutputStream(i.query.get("stream", "stdout")),
        offset=i.query.get("offset", 0),
        max_bytes=i.query.get("max_bytes"),
    )


def _mint(i: Inputs) -> c.Command:
    return c.MintAgentCredential(project=i.path["project"], spec=i.body)


def _list_credentials(i: Inputs) -> c.Command:
    return c.ListAgentCredentials(project=i.path["project"])


def _revoke(i: Inputs) -> c.Command:
    return c.RevokeAgentCredential(project=i.path["project"], credential_id=i.path["credential"])


def _whoami(_: Inputs) -> c.Command:
    return c.WhoAmI()


def _info(_: Inputs) -> c.Command:
    return c.Info()


ROUTES: Final[tuple[RouteSpec, ...]] = (
    RouteSpec(
        _op("sandbox.create"),
        m.SandboxSpec,
        m.Operation,
        _create_sandbox,
        query=(_WAIT,),
        answers_operation=True,
        path_params=("project",),
    ),
    RouteSpec(
        _op("sandbox.list"), None, m.SandboxList, _list_sandboxes, query=(_LIMIT, _CURSOR), path_params=("project",)
    ),
    RouteSpec(_op("sandbox.get"), None, m.Sandbox, _get_sandbox, path_params=("project", "sandbox")),
    RouteSpec(
        _op("sandbox.start"),
        m.TargetBody,
        m.Operation,
        _start_sandbox,
        query=(_WAIT,),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "sandbox"),
    ),
    RouteSpec(
        _op("sandbox.stop"),
        m.TargetBody,
        m.Operation,
        _stop_sandbox,
        query=(_WAIT,),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "sandbox"),
    ),
    RouteSpec(
        _op("sandbox.destroy"),
        None,
        m.Operation,
        _destroy_sandbox,
        query=(_GENERATION, _WAIT),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "sandbox"),
    ),
    RouteSpec(
        _op("execution.create"),
        m.ExecSpec,
        m.Operation,
        _exec,
        query=(_WAIT,),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "sandbox"),
    ),
    RouteSpec(
        _op("snapshot.create"),
        m.SnapshotSpec,
        m.Operation,
        _create_snapshot,
        query=(_WAIT,),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "sandbox"),
    ),
    RouteSpec(_op("execution.get"), None, m.Execution, _get_execution, path_params=("project", "execution")),
    RouteSpec(
        _op("execution.output"),
        None,
        m.OutputChunk,
        _get_execution_output,
        query=(
            QueryParam("stream", "stream", "Which stream: `stdout` (the default) or `stderr`."),
            QueryParam("offset", "int", "Byte offset into the stored output of the stream.", minimum=0),
            QueryParam(
                "max_bytes",
                "int",
                "At most this many bytes. The platform caps it at its `output_chunk_max`.",
                minimum=1,
                maximum=16_777_216,
            ),
        ),
        path_params=("project", "execution"),
    ),
    RouteSpec(
        _op("execution.cancel"),
        None,
        m.Operation,
        _cancel_execution,
        query=(_WAIT,),
        answers_operation=True,
        path_params=("project", "execution"),
    ),
    RouteSpec(
        _op("snapshot.list"), None, m.SnapshotList, _list_snapshots, query=(_LIMIT, _CURSOR), path_params=("project",)
    ),
    RouteSpec(
        _op("snapshot.restore"),
        m.RestoreSpec,
        m.Operation,
        _restore_snapshot,
        query=(_WAIT,),
        accepts_if_match=True,
        answers_operation=True,
        path_params=("project", "snapshot"),
    ),
    RouteSpec(
        _op("snapshot.delete"),
        None,
        m.Operation,
        _delete_snapshot,
        query=(
            QueryParam(
                "snapshot_generation",
                "int",
                "Generation of the snapshot, as its view shows it.",
                required=True,
                minimum=1,
            ),
            _WAIT,
        ),
        answers_operation=True,
        path_params=("project", "snapshot"),
    ),
    RouteSpec(
        _op("operation.list"),
        None,
        m.OperationList,
        _list_operations,
        query=(_LIMIT, _CURSOR),
        path_params=("project",),
    ),
    RouteSpec(
        _op("operation.get"), None, m.Operation, _get_operation, query=(_WAIT,), path_params=("project", "operation")
    ),
    RouteSpec(
        _op("agent_credential.mint"),
        m.MintAgentCredentialSpec,
        m.AgentCredential,
        _mint,
        success_status=201,
        path_params=("project",),
    ),
    RouteSpec(_op("agent_credential.list"), None, m.AgentCredentialList, _list_credentials, path_params=("project",)),
    RouteSpec(_op("agent_credential.revoke"), None, m.AgentCredential, _revoke, path_params=("project", "credential")),
    RouteSpec(_op("platform.info"), None, m.Info, _info, anonymous=True),
    RouteSpec(_op("auth.whoami"), None, m.WhoAmI, _whoami),
)


def parse_generation(text: str) -> int | Literal["current"]:
    """The ``expected_generation`` of a query string: digits, or the literal ``current``."""
    if text == "current":
        return "current"
    if not text.isascii() or not text.isdigit() or len(text) > 20:  # noqa: PLR2004 - digits of a u64
        msg = "expected_generation must be a positive integer or `current`"
        raise ValueError(msg)
    return _GENERATION_ADAPTER.validate_python(int(text))
