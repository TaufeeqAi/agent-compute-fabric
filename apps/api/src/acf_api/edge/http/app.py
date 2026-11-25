"""The REST adapter: the public resource model over HTTP.

It runs in an edge process and decides nothing. For each request, in this order:

    transport bounds -> route and API version -> the credential check, asked of the core
      -> size-bounded read of the body -> strict decoding and schema validation -> one command

and then it renders the core's answer. The order matters in two places. The credential is checked
*before* a body is read, so that an unauthenticated caller cannot make the edge parse. And the body is
bounded *before* it is parsed, so that an oversize body costs a count and nothing else.

What it renders:

* a view, with ``200``; or, for an operation, ``200`` when it has ended and ``202`` with ``Location``
  and ``Retry-After`` when it has not. An operation that ended ``FAILED`` or ``UNKNOWN`` is still an
  operation: an accepted request never produces an error answer;
* an error answer, as an RFC 9457 problem document whose extension members carry ``code``, ``kind`` and
  ``retry``. The HTTP status is derived from the code and is a hint only.

When the core does not answer a mutating command, the command client answers ``OUTCOME_UNRESOLVED``
for it, never a refusal. Nothing in this module turns that into anything else.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import Any, Final

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.routing import Route

from acf_api.command import model as m
from acf_api.command import strictjson
from acf_api.command.answers import (
    IDEMPOTENCY_KEY_HARD_MAX,
    IDEMPOTENCY_KEY_PATTERN,
    TRACEPARENT_PATTERN,
    Answer,
    ClientInfo,
    ErrorAnswer,
    RequestContext,
    ViewAnswer,
)
from acf_api.command.client import CoreClient, may_create_work, new_request_id, unresolved
from acf_api.command.commands import COMMAND_ADAPTER, REVISION_PATTERN, Command
from acf_api.command.errors import CODES, Code, Kind, Retry, http_status, problem_type
from acf_api.edge.config import Limits
from acf_api.edge.http.routes import ROUTES, Inputs, RouteSpec, parse_generation

_LOG: Final = logging.getLogger("acf_api.edge")
_KEY: Final = re.compile(IDEMPOTENCY_KEY_PATTERN)
_TRACEPARENT: Final = re.compile(TRACEPARENT_PATTERN)
_REVISION: Final = re.compile(REVISION_PATTERN)
_CLIENT: Final = re.compile(r"^[A-Za-z0-9 ._/+-]*$")
#: Query parameters that would carry a credential. A credential is never accepted in a URL.
_CREDENTIAL_PARAMS: Final = frozenset({"access_token", "api_key", "apikey", "key", "token", "authorization"})
_JSON: Final = "application/json"
_PROBLEM: Final = "application/problem+json"
API_VERSION_PREFIX: Final = "/" + m.API_VERSION


class _Refusal(Exception):
    """A request the edge itself refuses: malformed, oversize, or not addressed to a route. Nothing was sent."""

    def __init__(
        self, code: Code, message: str, *, reason: str | None = None, headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.message = message
        self.reason = reason
        self.headers = headers or {}


def problem(
    error: m.ErrorBody, *, retry_after_s: int | None = None, headers: Mapping[str, str] | None = None
) -> Response:
    """An error answer as a problem document. ``code`` is authoritative; the status is a hint."""
    status = http_status(error.code, error.retry)
    info = CODES.get(Code(error.code)) if error.code in Code.__members__ else None
    title = info.title if info is not None else "A failure class this version does not know"
    body = m.Problem(
        type=problem_type(error.code),
        title=title,
        status=status,
        detail=error.message,
        instance=f"urn:acf:request:{error.request_id}",
        **error.model_dump(),
    )
    out = {"X-Request-Id": error.request_id, "Cache-Control": "no-store", **(headers or {})}
    if retry_after_s is not None:
        out["Retry-After"] = str(retry_after_s)
    if status == 401 and "WWW-Authenticate" not in out:  # noqa: PLR2004 - the status that carries a challenge
        out["WWW-Authenticate"] = "Bearer"
    return Response(
        strictjson.dumps(body.model_dump(mode="json", exclude_none=True)),
        status_code=status,
        media_type=_PROBLEM,
        headers=out,
    )


def _edge_problem(refusal: _Refusal, request_id: str) -> Response:
    info = CODES[refusal.code]
    error = m.ErrorBody(
        code=refusal.code.value,
        kind=(info.kind or Kind.REFUSED).value,
        retry=info.retry.value,
        message=refusal.message,
        request_id=request_id,
        reason=refusal.reason,
    )
    return problem(error, headers=refusal.headers)


def bearer(request: Request) -> str | None:
    """The credential of a request: the ``Authorization: Bearer`` header and nothing else."""
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not value or len(value) > 16 * 1024 or not value.isascii():
        return None
    return value


def client_info(request: Request) -> ClientInfo:
    """What the client says it is, from ``User-Agent``. Bounded, checked, and used for audit only."""
    agent = request.headers.get("user-agent", "")
    name, _, version = agent.partition("/")
    name, version = name.strip()[:64], version.split(" ", 1)[0].strip()[:32]
    if not _CLIENT.fullmatch(name) or not _CLIENT.fullmatch(version):
        return ClientInfo()
    return ClientInfo(name=name, version=version)


def trace_parent(request: Request) -> str | None:
    """A valid W3C trace parent, or nothing. An invalid one is ignored, never an error."""
    value = request.headers.get("traceparent")
    return value if value is not None and _TRACEPARENT.fullmatch(value) else None


async def read_bounded(request: Request, limit: int, timeout_s: float) -> bytes:
    """The body of a request, refused the moment it exceeds ``limit`` or takes longer than ``timeout_s``."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise _Refusal(Code.REQUEST_TOO_LARGE, f"the request body exceeds {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    try:
        async with asyncio.timeout(timeout_s):
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise _Refusal(Code.REQUEST_TOO_LARGE, f"the request body exceeds {limit} bytes")
                chunks.append(chunk)
    except TimeoutError as e:
        raise _Refusal(Code.INVALID_REQUEST, "the request body did not arrive in time", reason="slow_body") from e
    return b"".join(chunks)


def _query(request: Request, route: RouteSpec) -> dict[str, Any]:  # noqa: PLR0912 - one branch per kind of parameter and per way one can be wrong
    """The query parameters of a route, strictly: none unknown, none repeated, each of its type."""
    known = {q.name: q for q in route.query}
    out: dict[str, Any] = {}
    for name, value in request.query_params.multi_items():
        if name.lower() in _CREDENTIAL_PARAMS:
            raise _Refusal(Code.INVALID_REQUEST, "a credential is never accepted in a URL", reason="credential_in_url")
        spec = known.get(name)
        if spec is None:
            raise _Refusal(
                Code.INVALID_REQUEST, "the request carries a query parameter this route does not define", reason="query"
            )
        if name in out:
            raise _Refusal(Code.INVALID_REQUEST, f"the query parameter `{name}` is repeated", reason="query")
        try:
            if spec.kind == "int":
                if not value.isascii() or not value.isdigit() or len(value) > 12:  # noqa: PLR2004
                    raise ValueError
                number = int(value)
                if (spec.minimum is not None and number < spec.minimum) or (
                    spec.maximum is not None and number > spec.maximum
                ):
                    raise ValueError
                out[name] = number
            elif spec.kind == "generation":
                out[name] = parse_generation(value)
            elif spec.kind == "stream":
                if value not in {"stdout", "stderr"}:
                    raise ValueError
                out[name] = value
            else:
                if not value or len(value) > 512:  # noqa: PLR2004
                    raise ValueError
                out[name] = value
        except ValueError as e:
            raise _Refusal(Code.INVALID_REQUEST, f"the query parameter `{name}` is not valid", reason="query") from e
    missing = [q.name for q in route.query if q.required and q.name not in out]
    if missing:
        raise _Refusal(Code.INVALID_REQUEST, f"the query parameter `{missing[0]}` is required", reason="query")
    return out


def _if_match(request: Request, route: RouteSpec) -> str | None:
    value = request.headers.get("if-match")
    if value is None:
        return None
    if not route.accepts_if_match:
        raise _Refusal(Code.INVALID_REQUEST, "this route takes no If-Match", reason="if_match")
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':  # noqa: PLR2004
        stripped = stripped[1:-1]
    if not _REVISION.fullmatch(stripped):
        raise _Refusal(
            Code.INVALID_REQUEST, "If-Match must carry one entity tag as this API returned it", reason="if_match"
        )
    return stripped


def _idempotency_key(request: Request, route: RouteSpec) -> str | None:
    value = request.headers.get("idempotency-key")
    if not route.operation.keyed:
        return None
    if value is None:
        raise _Refusal(Code.INVALID_REQUEST, "this request needs an Idempotency-Key header", reason="idempotency_key")
    if not 1 <= len(value) <= IDEMPOTENCY_KEY_HARD_MAX or not _KEY.fullmatch(value):
        raise _Refusal(
            Code.INVALID_REQUEST,
            f"Idempotency-Key must be 1 to {IDEMPOTENCY_KEY_HARD_MAX} characters in the range 0x21 to 0x7E",
            reason="idempotency_key",
        )
    return value


def _schema_members(schema: object, into: set[str]) -> set[str]:
    """Every member name a JSON schema defines, at any depth."""
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            into.update(str(name) for name in properties)
        for value in schema.values():
            _schema_members(value, into)
    elif isinstance(schema, list):
        for value in schema:
            _schema_members(value, into)
    return into


#: The member names of the public model. A refusal may name these; it never names what a caller chose.
_MEMBERS: Final = frozenset(_schema_members(COMMAND_ADAPTER.json_schema(by_alias=True), set()))


def _where(e: ValidationError) -> str:
    """Where a request is wrong, in the schema's own names: never a value, and never a name the caller sent.

    The path of a validation error holds the caller's own words in two places: the name of a member the
    schema does not define, and the key of a mapping. Both are left out, so that a refusal cannot repeat
    what was sent, whatever it was.
    """
    places: set[str] = set()
    for err in e.errors(include_url=False, include_context=False, include_input=False):
        path = ".".join(p for p in err["loc"] if isinstance(p, str) and p in _MEMBERS) or "body"
        places.add(f"{path} (holds a member the schema does not define)" if err["type"] == "extra_forbidden" else path)
    return ", ".join(sorted(places)[:8])


async def _body(request: Request, route: RouteSpec, limits: Limits) -> m.RequestModel | None:
    raw = await read_bounded(request, limits.max_public_request_bytes, limits.body_read_timeout)
    if route.body is None:
        if raw.strip():
            raise _Refusal(Code.INVALID_REQUEST, "this route takes no body", reason="body")
        return None
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != _JSON:
        raise _Refusal(Code.INVALID_REQUEST, "the body must be application/json", reason="content_type")
    try:
        # First the strict profile: a repeated member name is refused before the schema is consulted.
        strictjson.loads_object(raw)
        return route.body.model_validate_json(raw)
    except strictjson.StrictJsonError as e:
        raise _Refusal(Code.INVALID_REQUEST, str(e), reason="json") from e
    except ValidationError as e:
        raise _Refusal(
            Code.INVALID_REQUEST, f"the body does not fit the schema of this route: {_where(e)}", reason="schema"
        ) from e


def render(answer: Answer, route: RouteSpec, request: Request) -> Response:
    """The HTTP form of the core's answer. No decision is taken here."""
    if isinstance(answer, ErrorAnswer):
        headers = {"WWW-Authenticate": answer.challenge.www_authenticate} if answer.challenge is not None else None
        return problem(answer.error, retry_after_s=answer.retry_after_s, headers=headers)
    if not isinstance(answer, ViewAnswer):
        raise TypeError(type(answer).__name__)
    headers = {"X-Request-Id": request.state.request_id, "Cache-Control": "no-store"}
    status = route.success_status
    if route.answers_operation:
        if answer.replayed:
            headers["Idempotent-Replayed"] = "true"
        if not answer.terminal:
            status = 202
            operation_id = str(answer.body.get("operation_id", ""))
            headers["Location"] = (
                f"{API_VERSION_PREFIX}/projects/{request.path_params['project']}/operations/{operation_id}"
            )
            headers["Retry-After"] = str(answer.retry_after_s or 1)
    elif answer.retry_after_s is not None:
        headers["Retry-After"] = str(answer.retry_after_s)
    if answer.etag is not None:
        headers["ETag"] = f'"{answer.etag}"'
    return Response(strictjson.dumps(answer.body), status_code=status, media_type=_JSON, headers=headers)


def _endpoint(route: RouteSpec, core: CoreClient, limits: Limits) -> Callable[[Request], Awaitable[Response]]:
    async def endpoint(request: Request) -> Response:
        request_id = new_request_id()
        request.state.request_id = request_id
        try:
            for name in request.query_params:
                if name.lower() in _CREDENTIAL_PARAMS:
                    raise _Refusal(
                        Code.INVALID_REQUEST, "a credential is never accepted in a URL", reason="credential_in_url"
                    )
            credential = bearer(request)
            waits = [limits.public_wait_max]
            budget_ms = int((max(waits) + limits.edge_core_deadline_margin) * 1000)
            ctx = RequestContext(
                request_id=request_id,
                traceparent=trace_parent(request),
                budget_ms=budget_ms,
                interface="rest",
                interface_version=m.API_VERSION,
                client=client_info(request),
            )
            if credential is not None or not route.anonymous:
                # Authentication precedes decoding: the core is asked before a body is read.
                verified = await core.verify(credential, ctx)
                if isinstance(verified, ErrorAnswer):
                    return render(verified, route, request)
            query = _query(request, route)
            key = _idempotency_key(request, route)
            if_match = _if_match(request, route)
            body = await _body(request, route, limits)
            try:
                command = route.build(Inputs(request.path_params, query, body, if_match))
            except ValidationError as e:
                raise _Refusal(
                    Code.INVALID_REQUEST, f"the request does not fit this route: {_where(e)}", reason="schema"
                ) from e
            handling = asyncio.create_task(core.handle(credential, ctx, command, key))
            gone = asyncio.create_task(_disconnected(request))
            done, _ = await asyncio.wait({handling, gone}, return_when=asyncio.FIRST_COMPLETED)
            if handling not in done:
                # The caller went away. The wait is abandoned, and that cancels nothing.
                handling.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await handling
                return Response(status_code=499)
            gone.cancel()
            try:
                return render(handling.result(), route, request)
            except Exception as e:
                # Whatever fails here fails after the command was passed on.
                fields = {"path_template": route.path, "error": type(e).__name__}
                _LOG.error("unexpected_error", extra={"fields": fields})
                return _failed_after_passing_on(command, ctx, key, route, request)
        except _Refusal as refusal:
            return _edge_problem(refusal, request_id)
        except ClientDisconnect:
            return Response(status_code=499)

    return endpoint


def _failed_after_passing_on(
    command: Command, ctx: RequestContext, key: str | None, route: RouteSpec, request: Request
) -> Response:
    """What a caller is told when the edge itself fails after the command left it.

    The core may have carried the command out. So for a command that can create something the answer is
    "unresolved", exactly as if no answer had come: the caller repeats the request with its key, and the
    ledger resolves it. It is never "refused". A read changed nothing whatever happened to it.
    """
    if may_create_work(command):
        return render(unresolved(ctx, key), route, request)
    failed = _Refusal(Code.INTERNAL_ERROR, "the edge failed while it rendered the answer; the read changed nothing")
    return _edge_problem(failed, ctx.request_id)


async def _disconnected(request: Request) -> None:
    while not await request.is_disconnected():  # noqa: ASYNC110 - the framework answers the question and offers no event to wait for
        await asyncio.sleep(0.25)


def _not_found(_request: Request, _: Exception) -> Response:
    return _edge_problem(_Refusal(Code.NOT_FOUND, "no such route in this version of the API"), new_request_id())


def _method_not_allowed(_request: Request, exc: Exception) -> Response:
    headers = dict(getattr(exc, "headers", None) or {})
    return _edge_problem(
        _Refusal(Code.INVALID_REQUEST, "this route does not answer that method", reason="method", headers=headers),
        new_request_id(),
    )


def _http_error(request: Request, exc: Exception) -> Response:
    status = exc.status_code if isinstance(exc, HTTPException) else 500
    if status == 404:  # noqa: PLR2004
        return _not_found(request, exc)
    if status == 405:  # noqa: PLR2004
        return _method_not_allowed(request, exc)
    return _edge_problem(
        _Refusal(Code.INVALID_REQUEST, "the request could not be read", reason="http"), new_request_id()
    )


def _unexpected(request: Request, _: Exception) -> Response:
    _LOG.error("unexpected_error", extra={"fields": {"path_template": request.scope.get("route_template", "")}})
    error = m.ErrorBody(
        code=Code.INTERNAL_ERROR.value,
        kind=Kind.REFUSED.value,
        retry=Retry.AFTER_CHANGE.value,
        message="the edge failed before the request was passed on; nothing was sent",
        request_id=getattr(request.state, "request_id", new_request_id()),
    )
    return problem(error)


async def _healthz(_: Request) -> Response:
    """Liveness of this edge process alone. It says nothing about the core or the host."""
    headers = {"X-Request-Id": new_request_id(), "Cache-Control": "no-store"}
    return Response(b'{"status":"ok"}', media_type=_JSON, headers=headers)


def create_app(core: CoreClient, limits: Limits) -> Starlette:
    """The ASGI application of the REST adapter, over one client of the command interface."""
    routes = [
        Route(spec.path, _endpoint(spec, core, limits), methods=[spec.method], name=spec.operation.method)
        for spec in ROUTES
    ]
    routes.append(Route("/healthz", _healthz, methods=["GET"]))

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        yield
        await core.aclose()

    app = Starlette(
        routes=routes,
        exception_handlers={HTTPException: _http_error, Exception: _unexpected},
        lifespan=lifespan,
    )
    # A path is a route or it is not. The framework's default would answer a path that differs from a
    # route by a trailing slash with a redirect: an answer that is no problem document, carries no
    # request id, and repeats the caller's query string in `Location`.
    app.router.redirect_slashes = False
    return app
