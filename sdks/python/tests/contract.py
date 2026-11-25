"""The generated OpenAPI document of the API, as a judge of every request the tests make.

The scripted server of ``support`` asks this module about each request it sees, in every test: is there
such a route, are these its query parameters, is this a body its schema accepts, and does it carry an
idempotency key exactly when the route takes one. The API refuses a body with a member its schema does
not define, so a typo in a member name is caught here and not in production.

The document is the artifact under ``protocols/api``. It is read, never edited.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml
from jsonschema import Draft202012Validator

REPOSITORY: Final = Path(__file__).resolve().parents[3]
OPENAPI: Final = REPOSITORY / "protocols" / "api" / "openapi.yaml"
REGISTRY: Final = REPOSITORY / "protocols" / "api" / "problems" / "registry.yaml"

_METHODS: Final = ("get", "post", "delete", "put", "patch")
_WHOLE: Final = re.compile(r"-?[0-9]+")


@dataclass(frozen=True)
class Route:
    """One operation of the document."""

    method: str
    template: str
    pattern: re.Pattern[str]
    query: dict[str, dict[str, Any]]
    required_query: frozenset[str]
    keyed: bool
    body_schema: dict[str, Any] | None


class Contract:
    """The OpenAPI document, loaded once."""

    def __init__(self) -> None:
        self.document: dict[str, Any] = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
        self.schemas: dict[str, dict[str, Any]] = self.document["components"]["schemas"]
        self.routes = [
            self._route(method, template, operation)
            for template, item in self.document["paths"].items()
            for method, operation in item.items()
            if method in _METHODS
        ]

    def _resolve(self, node: dict[str, Any]) -> dict[str, Any]:
        """Follow a ``$ref`` into the document."""
        while "$ref" in node:
            target: Any = self.document
            for part in node["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            node = target
        return node

    def _route(self, method: str, template: str, operation: dict[str, Any]) -> Route:
        parameters = [self._resolve(parameter) for parameter in operation.get("parameters", [])]
        query = {p["name"]: p["schema"] for p in parameters if p["in"] == "query"}
        required = frozenset(p["name"] for p in parameters if p["in"] == "query" and p.get("required"))
        keyed = any(p["in"] == "header" and p["name"] == "Idempotency-Key" for p in parameters)
        body = operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
        pattern = re.compile(re.sub(r"\{[^/}]+\}", "[^/]+", template))
        return Route(method.upper(), template, pattern, query, required, keyed, body)

    def validator(self, schema: dict[str, Any]) -> Draft202012Validator:
        """A validator for a schema of the document, with the document's components in reach of its ``$ref``s."""
        return Draft202012Validator({**schema, "components": self.document["components"]})

    def judge(
        self, method: str, raw_path: str, query: Mapping[str, str], headers: Mapping[str, str], body: bytes
    ) -> list[str]:
        """Everything about a request that the document does not allow. Empty: the request is one of the API's."""
        routes = [route for route in self.routes if route.method == method and route.pattern.fullmatch(raw_path)]
        if len(routes) != 1:
            return [f"{method} {raw_path} is not a route of the API"]
        route = routes[0]
        where = f"{method} {route.template}"
        problems = [f"{where}: query parameter {name} is not defined" for name in query if name not in route.query]
        problems += [f"{where}: query parameter {name} is required" for name in route.required_query - set(query)]
        for name, text in query.items():
            if name in route.query and not self._query_value_fits(route.query[name], text):
                problems.append(f"{where}: query parameter {name}={text!r} does not fit its schema")
        key = headers.get("idempotency-key")
        if route.keyed and key is None:
            problems.append(f"{where}: an Idempotency-Key is required")
        if not route.keyed and key is not None:
            problems.append(f"{where}: this route takes no Idempotency-Key")
        return problems + self._judge_body(route, where, body)

    def _query_value_fits(self, schema: dict[str, Any], text: str) -> bool:
        """A query value is text; it fits if the text, or the integer it spells, is valid for the schema."""
        validator = self.validator(schema)
        candidates: list[Any] = [text]
        if _WHOLE.fullmatch(text):
            candidates.append(int(text))
        return any(validator.is_valid(candidate) for candidate in candidates)

    def _judge_body(self, route: Route, where: str, body: bytes) -> list[str]:
        if route.body_schema is None:
            return [f"{where}: this route takes no body"] if body else []
        if not body:
            return [f"{where}: a body is required"]
        errors = sorted(self.validator(route.body_schema).iter_errors(json.loads(body)), key=str)
        return [f"{where}: body: {error.message}" for error in errors]


CONTRACT: Final = Contract()


def registry_rows() -> dict[str, dict[str, Any]]:
    """The problem registry of the API: code -> its row."""
    document = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    return {row["code"]: row for row in document["codes"]}
