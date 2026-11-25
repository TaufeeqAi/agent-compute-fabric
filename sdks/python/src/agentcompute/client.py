"""The clients: :class:`Fabric`, which blocks, and :class:`AsyncFabric`, which is awaited.

Both are configured the same way and behave the same way; every rule they follow is written once, in
the transport, and each client only runs it. A client reads three environment variables and nothing
else, holds one credential, talks to one endpoint and keeps no copy of the server's state.

What a client refuses at construction, before any request can be made:

* no key, or no base URL;
* a base URL that carries a credential (user information) or a query string: a credential is never
  accepted in a URL, because URLs end up in logs;
* a base URL that is not ``https``, unless it is ``http`` to a loopback address or the caller passed
  ``allow_insecure_http=True``: a key sent over plain HTTP is a key shown to the network.
"""

from __future__ import annotations

import ipaddress
import math
import os
import ssl
from typing import Any, Final, Self
from urllib.parse import urlsplit

import httpx2

from agentcompute._binding import AsyncBinder, SyncBinder
from agentcompute._transport import AsyncDriver, Engine, Flow, Request, SyncDriver, identifier
from agentcompute._version import __version__
from agentcompute.auth import AsyncAuth, Auth
from agentcompute.errors import ConfigurationError
from agentcompute.execution import AsyncExecutions, Executions
from agentcompute.operation import AsyncOperations, Operations
from agentcompute.sandbox import AsyncSandboxes, Sandboxes
from agentcompute.snapshot import AsyncSnapshots, Snapshots
from agentcompute.types import Info, WhoAmI

__all__ = ["AsyncFabric", "Fabric"]

ENV_API_KEY: Final = "ACF_API_KEY"
ENV_BASE_URL: Final = "ACF_BASE_URL"
ENV_PROJECT: Final = "ACF_PROJECT"
ENV_CA_FILE: Final = "ACF_CA_FILE"

#: One HTTP request. Longer than the longest wait the server grants, plus its own margin.
DEFAULT_TIMEOUT: Final = 120.0
DEFAULT_MAX_RETRIES: Final = 2
#: How long one call follows one operation: 30 minutes.
DEFAULT_FOLLOW_MAX: Final = 1800.0
#: How long one request may be retried: a day less an hour, so that the platform still remembers the
#: key when the last attempt arrives.
DEFAULT_RETRY_TOTAL_MAX: Final = 82_800.0

_USER_AGENT: Final = f"agent-compute-python/{__version__}"
_FIRST_VISIBLE: Final = "\x21"
_LAST_VISIBLE: Final = "\x7e"


def _credential(api_key: str | None) -> str:
    """The key to use. No message from here ever repeats any part of it."""
    key = api_key if api_key is not None else os.environ.get(ENV_API_KEY)
    if not key:
        raise ConfigurationError(f"no API key: pass api_key, or set {ENV_API_KEY}")
    if not isinstance(key, str) or not all(_FIRST_VISIBLE <= character <= _LAST_VISIBLE for character in key):
        raise ConfigurationError(
            "the API key holds a character no key has (a space, a line break or a non-ASCII character): "
            "check how it was copied"
        )
    return key


def _trust(ca_file: str | os.PathLike[str] | None) -> ssl.SSLContext | None:
    """Whom to believe about the platform's certificate, when the caller says: the authorities of one file.

    With a file, its authorities are the only ones believed, and the system's own are not consulted: a
    platform that somebody runs for themselves is usually certified by an authority of their own, and its
    client should believe that one and no other. Without a file the HTTP library's default applies.
    """
    named = ca_file if ca_file is not None else os.environ.get(ENV_CA_FILE) or None
    if named is None:
        return None
    refusal = ConfigurationError(
        f"ca_file is not a file of certificates this client can read: give the path of a PEM file, "
        f"as ca_file or in {ENV_CA_FILE}"
    )
    try:
        return ssl.create_default_context(cafile=os.fspath(named))
    except (OSError, ValueError, TypeError):
        # A missing file, a file that holds no certificate, and a value that is no path. ssl.SSLError is an OSError.
        raise refusal from None


def _is_loopback(host: str) -> bool:
    """Whether the host is this machine, by its literal form. No name is resolved to find out."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _endpoint(base_url: str | None, *, allow_insecure_http: bool) -> str:
    """The base URL to use, without a trailing slash. No message from here repeats the URL: it may hold a secret."""
    url = base_url if base_url is not None else os.environ.get(ENV_BASE_URL)
    if not url:
        raise ConfigurationError(f"no base URL: pass base_url, or set {ENV_BASE_URL}")
    if any(character.isspace() or not character.isprintable() for character in url):
        # A URL parser removes a tab or a line break without saying so, and the address that is then used is
        # not the one that was written. An address is used as it was written, or not at all.
        raise ConfigurationError("base_url must not contain a space, a line break or a character that does not show")
    try:
        parts = urlsplit(url)
        host, _port = parts.hostname, parts.port
        # What the HTTP library will be given: it is stricter about a host name and about length, and its
        # refusal belongs here, where a caller expects it, and not in the middle of a first request.
        httpx2.URL(url)
    except (ValueError, AttributeError, httpx2.InvalidURL):
        raise ConfigurationError("base_url is not a URL this client can read") from None
    if parts.username is not None or parts.password is not None:
        raise ConfigurationError(
            "base_url must not carry user information: a credential is never accepted in a URL. "
            f"Pass the key as api_key, or set {ENV_API_KEY}"
        )
    if "?" in url or "#" in url:
        raise ConfigurationError(
            "base_url must not carry a query string or a fragment: a credential is never accepted in a URL, "
            "and nothing else belongs there"
        )
    if not host:
        raise ConfigurationError("base_url must name a host, for example https://acf.example")
    scheme = parts.scheme.lower()
    if scheme == "http":
        if not (allow_insecure_http or _is_loopback(host)):
            raise ConfigurationError(
                "base_url must be https: over plain http the key is readable by the network. "
                "http is accepted for a loopback address, or with allow_insecure_http=True"
            )
    elif scheme != "https":
        raise ConfigurationError("base_url must be an https URL (or http to a loopback address)")
    return url.rstrip("/")


def _project(project: str | None) -> str | None:
    """The project named by the caller or the environment. ``None``: ask the credential on first need."""
    named = project if project is not None else os.environ.get(ENV_PROJECT)
    if named is None or named == "":
        return None
    try:
        return identifier(named, what="project")
    except ValueError as error:
        raise ConfigurationError(f"{error}; it is a project identifier, for example prj_...") from None


def _seconds(value: float, what: str, *, zero: bool) -> float:
    acceptable = not isinstance(value, bool) and isinstance(value, int | float) and math.isfinite(value)
    if not acceptable or value < 0 or (value == 0 and not zero):
        least = "zero or more" if zero else "more than zero"
        raise ConfigurationError(f"{what} must be a finite number of seconds, {least}")
    return float(value)


def _engine(
    api_key: str | None,
    *,
    base_url: str | None,
    project: str | None,
    timeout: float,
    max_retries: int,
    follow_max: float,
    retry_total_max: float,
    allow_insecure_http: bool,
) -> Engine:
    """Read the configuration, refuse what cannot work, and build the engine of one client."""
    if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
        raise ConfigurationError("max_retries must be an integer, zero or more")
    endpoint = _endpoint(base_url, allow_insecure_http=allow_insecure_http)
    headers = httpx2.Headers(
        {
            "Authorization": f"Bearer {_credential(api_key)}",
            "User-Agent": _USER_AGENT,
            "Accept": "application/json, application/problem+json",
        }
    )
    return Engine(
        base_url=endpoint,
        headers=headers,
        project=_project(project),
        timeout=_seconds(timeout, "timeout", zero=False),
        max_retries=max_retries,
        follow_max=_seconds(follow_max, "follow_max", zero=True),
        retry_total_max=_seconds(retry_total_max, "retry_total_max", zero=True),
    )


def _own_client(ca_file: str | os.PathLike[str] | None) -> dict[str, Any]:
    """How the HTTP client this SDK builds is set up.

    The environment is not trusted for proxies or for the general certificate variables: a variable that
    another program set must not move this connection or change whom it believes. The one setting of
    trust is this SDK's own, ``ca_file``.
    """
    trust = _trust(ca_file)
    return {"trust_env": False} if trust is None else {"trust_env": False, "verify": trust}


def _not_both(ca_file: str | os.PathLike[str] | None) -> None:
    """``ca_file`` sets up the client this SDK builds. A client the caller built is the caller's to set up."""
    if ca_file is not None:
        raise ConfigurationError(
            "ca_file configures the HTTP client this SDK builds; an http_client of your own is configured "
            "by you. Pass one of the two"
        )


def _info(engine: Engine) -> Flow[Info]:
    answer = yield from engine.perform(Request("GET", "/v1/info"))
    return Info(answer.body, request_id=answer.request_id)


class Fabric:
    """The synchronous client.

    ``api_key`` comes from the argument or ``ACF_API_KEY``, ``base_url`` from the argument or
    ``ACF_BASE_URL``, ``project`` from the argument or ``ACF_PROJECT``, and otherwise from the
    credential itself, asked once. ``ca_file``, or ``ACF_CA_FILE``, names a PEM file of certificate
    authorities: with it, those are the only ones believed about the platform's certificate. Nothing else
    is read from the environment: no proxy settings and none of the general certificate variables. Pass
    an ``http_client`` configured the way you need for those.

    ``timeout`` bounds each HTTP request, ``max_retries`` the retries of one request, ``follow_max`` how
    long a call follows one operation (every call that follows takes its own ``follow_max`` as well), and
    ``retry_total_max`` the time spent retrying one request.

    A client may be shared between threads. Close it, or use it as a context manager, when it built its
    own HTTP client; an ``http_client`` that was passed in is left open for whoever owns it.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        project: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        follow_max: float = DEFAULT_FOLLOW_MAX,
        retry_total_max: float = DEFAULT_RETRY_TOTAL_MAX,
        allow_insecure_http: bool = False,
        ca_file: str | os.PathLike[str] | None = None,
        http_client: httpx2.Client | None = None,
    ) -> None:
        engine = _engine(
            api_key,
            base_url=base_url,
            project=project,
            timeout=timeout,
            max_retries=max_retries,
            follow_max=follow_max,
            retry_total_max=retry_total_max,
            allow_insecure_http=allow_insecure_http,
        )
        if http_client is not None and not isinstance(http_client, httpx2.Client):
            raise ConfigurationError("http_client must be an httpx2.Client (AsyncFabric takes an httpx2.AsyncClient)")
        if http_client is None:
            http = httpx2.Client(**_own_client(ca_file))
        else:
            _not_both(ca_file)
            http = http_client
        self._driver = SyncDriver(engine, http, owns_http=http_client is None)
        binder = SyncBinder(self._driver)
        self.sandboxes: Final = Sandboxes(binder)
        self.snapshots: Final = Snapshots(binder)
        self.executions: Final = Executions(binder)
        self.operations: Final = Operations(binder)
        self.auth: Final = Auth(binder)

    def whoami(self) -> WhoAmI:
        """The calling credential's principal, project and effective grants. Same as ``auth.whoami()``."""
        return self.auth.whoami()

    def info(self) -> Info:
        """Platform info: the API versions, whether it serves, and what it offers this caller."""
        return self._driver.run("info", _info(self._driver.engine))

    def close(self) -> None:
        """Release the connections, if this client built its own HTTP client."""
        self._driver.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        engine = self._driver.engine
        return f"{type(self).__name__}(base_url={engine.base_url!r}, project={engine.project!r})"


class AsyncFabric:
    """The asynchronous client: the same surface as :class:`Fabric`, every method awaited.

    Listings are asynchronous iterators (``async for sandbox in fabric.sandboxes.list()``). A client may
    be shared between tasks. Cancelling a task that awaits a call stops the waiting; it cancels nothing
    on the platform.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        project: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        follow_max: float = DEFAULT_FOLLOW_MAX,
        retry_total_max: float = DEFAULT_RETRY_TOTAL_MAX,
        allow_insecure_http: bool = False,
        ca_file: str | os.PathLike[str] | None = None,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        engine = _engine(
            api_key,
            base_url=base_url,
            project=project,
            timeout=timeout,
            max_retries=max_retries,
            follow_max=follow_max,
            retry_total_max=retry_total_max,
            allow_insecure_http=allow_insecure_http,
        )
        if http_client is not None and not isinstance(http_client, httpx2.AsyncClient):
            raise ConfigurationError("http_client must be an httpx2.AsyncClient (Fabric takes an httpx2.Client)")
        if http_client is None:
            http = httpx2.AsyncClient(**_own_client(ca_file))
        else:
            _not_both(ca_file)
            http = http_client
        self._driver = AsyncDriver(engine, http, owns_http=http_client is None)
        binder = AsyncBinder(self._driver)
        self.sandboxes: Final = AsyncSandboxes(binder)
        self.snapshots: Final = AsyncSnapshots(binder)
        self.executions: Final = AsyncExecutions(binder)
        self.operations: Final = AsyncOperations(binder)
        self.auth: Final = AsyncAuth(binder)

    async def whoami(self) -> WhoAmI:
        """The calling credential's principal, project and effective grants. Same as ``auth.whoami()``."""
        return await self.auth.whoami()

    async def info(self) -> Info:
        """Platform info: the API versions, whether it serves, and what it offers this caller."""
        return await self._driver.run("info", _info(self._driver.engine))

    async def aclose(self) -> None:
        """Release the connections, if this client built its own HTTP client."""
        await self._driver.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        engine = self._driver.engine
        return f"{type(self).__name__}(base_url={engine.base_url!r}, project={engine.project!r})"
