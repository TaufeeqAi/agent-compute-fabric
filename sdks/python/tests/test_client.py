"""The clients: what they read, what they refuse at construction, and where their requests can go.

One endpoint, one credential, one header. Nothing an answer says, and nothing a caller's HTTP client was
configured with, can send a request or the key anywhere else.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
from pathlib import Path
from typing import Any

import httpx2
import pytest

import authorities
from agentcompute import AsyncFabric, ConfigurationError, Fabric, UnexpectedResponseError, __version__
from support import (
    BASE_URL,
    CANARY_KEY,
    OP,
    PROJECT,
    SBX,
    Exchange,
    Harness,
    Script,
    done,
    ex,
    operation,
    reply,
    sandbox,
)


def _client_type(harness: Harness) -> type[Fabric] | type[AsyncFabric]:
    return AsyncFabric if harness.is_async else Fabric


def _close(harness: Harness, closable: Fabric | AsyncFabric | httpx2.Client | httpx2.AsyncClient) -> None:
    if isinstance(closable, AsyncFabric | httpx2.AsyncClient):
        harness.run(closable.aclose())
    else:
        closable.close()


def _build(harness: Harness, *args: Any, **options: Any) -> Fabric | AsyncFabric:
    """A client that builds its own HTTP client, closed again at once: nothing is sent."""
    fabric = _client_type(harness)(*args, **options)
    _close(harness, fabric)
    return fabric


# --------------------------------------------------------------------------------------- what is read
def test_the_key_the_base_url_and_the_project_come_from_the_environment(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.setenv("ACF_PROJECT", PROJECT)
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    fabric = harness.client(script, api_key=None, base_url=None, project=None)
    assert harness.run(fabric.sandboxes.get(SBX)).sandbox_id == SBX


def test_arguments_win_over_the_environment(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACF_API_KEY", "acf1_dev_from_the_environment")
    monkeypatch.setenv("ACF_BASE_URL", "https://environment.example")
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    fabric = harness.client(script)
    harness.run(fabric.sandboxes.get(SBX))
    assert "https://acf.test" in repr(fabric)


@pytest.mark.parametrize("missing", ["ACF_API_KEY", "ACF_BASE_URL"])
def test_a_missing_key_or_base_url_is_refused_at_construction(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.delenv(missing)
    with pytest.raises(ConfigurationError, match=missing):
        _client_type(harness)()


@pytest.mark.parametrize("empty", ["ACF_API_KEY", "ACF_BASE_URL"])
def test_an_empty_variable_is_a_missing_one(harness: Harness, monkeypatch: pytest.MonkeyPatch, empty: str) -> None:
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.setenv(empty, "")
    with pytest.raises(ConfigurationError, match=empty):
        _client_type(harness)()


def test_nothing_else_is_read_from_the_environment(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """Proxy and certificate variables would move the connection, or its trust, without the caller saying so."""
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "SSL_CERT_FILE"):
        monkeypatch.setenv(name, "http://proxy.example:3128")
    fabric = _build(harness, CANARY_KEY, base_url="https://acf.example")
    assert fabric._driver._http.trust_env is False


# ------------------------------------------------------------------------------- whom the client believes
def _built_with(harness: Harness, monkeypatch: pytest.MonkeyPatch, **options: Any) -> dict[str, Any]:
    """Build a client that makes its own HTTP client, and say how that HTTP client was set up."""
    seen: list[dict[str, Any]] = []
    kind = httpx2.AsyncClient if harness.is_async else httpx2.Client

    class Recording(kind):  # type: ignore[misc, valid-type]
        def __init__(self, **settings: Any) -> None:
            seen.append(settings)
            super().__init__(**settings)

    monkeypatch.setattr(httpx2, kind.__name__, Recording)
    _build(harness, CANARY_KEY, base_url=BASE_URL, **options)
    (settings,) = seen
    return settings


def _authorities_of(context: ssl.SSLContext) -> list[str]:
    """The common names of the authorities a context believes."""
    names: list[str] = []
    for certificate in context.get_ca_certs():
        subject: Any = certificate["subject"]
        names.extend(value for part in subject for name, value in part if name == "commonName")
    return sorted(names)


@pytest.fixture
def authority(tmp_path: Path) -> Path:
    path = tmp_path / "authority.pem"
    path.write_text(authorities.ONE, encoding="ascii")
    return path


def test_without_a_ca_file_the_http_librarys_own_trust_applies(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ACF_CA_FILE", raising=False)
    assert _built_with(harness, monkeypatch) == {"trust_env": False}


@pytest.mark.parametrize("how", ["argument", "argument-as-text", "environment"])
def test_with_a_ca_file_its_authorities_are_the_only_ones_believed(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, authority: Path, how: str
) -> None:
    """A platform somebody runs for themselves is certified by their own authority: that one, and no other."""
    if how == "environment":
        monkeypatch.setenv("ACF_CA_FILE", str(authority))
        settings = _built_with(harness, monkeypatch)
    else:
        monkeypatch.delenv("ACF_CA_FILE", raising=False)
        settings = _built_with(harness, monkeypatch, ca_file=authority if how == "argument" else str(authority))
    assert settings["trust_env"] is False
    context = settings["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert _authorities_of(context) == [authorities.ONE_NAME], "the system's authorities were not loaded beside it"
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_the_argument_wins_over_the_environment_for_the_ca_file_too(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, authority: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.pem"
    other.write_text(authorities.TWO, encoding="ascii")
    monkeypatch.setenv("ACF_CA_FILE", str(other))
    assert _authorities_of(_built_with(harness, monkeypatch, ca_file=authority)["verify"]) == [authorities.ONE_NAME]


def test_a_file_of_several_authorities_is_believed_as_a_whole(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    both = tmp_path / "both.pem"
    both.write_text(authorities.ONE + authorities.TWO, encoding="ascii")
    found = _authorities_of(_built_with(harness, monkeypatch, ca_file=both)["verify"])
    assert found == [authorities.ONE_NAME, authorities.TWO_NAME]


@pytest.mark.parametrize("wrong", ["missing", "empty", "not-certificates", "a-directory", "a-number"])
def test_a_ca_file_that_cannot_be_used_is_refused_at_construction_and_never_ignored(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, wrong: str
) -> None:
    """Falling back to the system's authorities would believe exactly the ones the caller meant to exclude."""
    path: Any = tmp_path / "authority.pem"
    if wrong == "empty":
        path.write_text("", encoding="ascii")
    elif wrong == "not-certificates":
        path.write_text("these are words, not certificates\n", encoding="ascii")
    elif wrong == "a-directory":
        path.mkdir()
    elif wrong == "a-number":
        path = 7
    for by_environment in (False, True):
        if by_environment and wrong == "a-number":
            continue
        options: dict[str, Any] = {}
        if by_environment:
            monkeypatch.setenv("ACF_CA_FILE", str(path))
        else:
            monkeypatch.delenv("ACF_CA_FILE", raising=False)
            options["ca_file"] = path
        with pytest.raises(ConfigurationError, match="ca_file is not a file of certificates") as refused:
            _client_type(harness)(CANARY_KEY, base_url=BASE_URL, **options)
        assert "ACF_CA_FILE" in str(refused.value)


def test_an_empty_variable_names_no_ca_file(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACF_CA_FILE", "")
    assert _built_with(harness, monkeypatch) == {"trust_env": False}


def test_a_ca_file_and_a_client_of_the_callers_own_are_one_setting_too_many(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, authority: Path
) -> None:
    own: Any = httpx2.AsyncClient() if harness.is_async else httpx2.Client()
    try:
        with pytest.raises(ConfigurationError, match="Pass one of the two"):
            _client_type(harness)(CANARY_KEY, base_url=BASE_URL, ca_file=authority, http_client=own)
        # The variable is ambient: beside a client the caller built, it is not consulted at all.
        monkeypatch.setenv("ACF_CA_FILE", str(authority.with_name("no-such-file.pem")))
        fabric = _client_type(harness)(CANARY_KEY, base_url=BASE_URL, http_client=own)
        assert fabric._driver._http is own
    finally:
        _close(harness, own)


# -------------------------------------------------------------------------------- what is refused
@pytest.mark.parametrize(
    "base_url",
    [
        "https://acf.example",
        "https://acf.example/",
        "https://acf.example:8443/gateway/acf",
        "HTTPS://ACF.EXAMPLE",
        "http://localhost:8080",
        "http://LOCALHOST",
        "http://127.0.0.1:8080",
        "http://127.8.9.10",
        "http://[::1]:8080",
    ],
)
def test_https_anywhere_and_http_to_this_machine_are_accepted(harness: Harness, base_url: str) -> None:
    fabric = _build(harness, CANARY_KEY, base_url=base_url)
    assert fabric._driver.engine.base_url == base_url.rstrip("/")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://acf.example",
        "http://10.0.0.5:8080",
        "http://192.168.1.10",
        "http://localhost.example",
        "http://[2001:db8::1]",
        "http://0.0.0.0:8080",
    ],
)
def test_plain_http_to_another_machine_is_refused_unless_asked_for(harness: Harness, base_url: str) -> None:
    with pytest.raises(ConfigurationError, match="must be https"):
        _client_type(harness)(CANARY_KEY, base_url=base_url)
    fabric = _build(harness, CANARY_KEY, base_url=base_url, allow_insecure_http=True)
    assert fabric._driver.engine.base_url == base_url


@pytest.mark.parametrize(
    ("base_url", "message"),
    [
        ("https://developer:secret@acf.example", "user information"),
        ("https://developer@acf.example", "user information"),
        ("https://:secret@acf.example", "user information"),
        ("https://acf.example?token=abc", "query string"),
        ("https://acf.example/?", "query string"),
        ("https://acf.example/#section", "query string or a fragment"),
        ("ftp://acf.example", "https URL"),
        ("ws://acf.example", "https URL"),
        ("fabric.internal", "name a host"),
        ("//acf.example", "https URL"),
        ("https://", "name a host"),
        ("https:///v1", "name a host"),
        ("https://acf.example:notaport", "not a URL"),
        ("https://[::1", "not a URL"),
        # What a URL parser would tidy away without a word. The address used would not be the one written.
        ("https://acf.exam\nple", "must not contain a space, a line break"),
        ("https://acf.exam\tple", "must not contain a space, a line break"),
        ("https://acf.example\n", "must not contain a space, a line break"),
        (" https://acf.example", "must not contain a space, a line break"),
        ("https://acf exam.ple", "must not contain a space, a line break"),
        ("https://acf.example/\N{NO-BREAK SPACE}v1", "must not contain a space, a line break"),
        ("https://acf.example/\N{ZERO WIDTH SPACE}v1", "a character that does not show"),
        ("https://\N{RIGHT-TO-LEFT OVERRIDE}acf.example", "a character that does not show"),
        ("https://acf.example/\x00", "a character that does not show"),
        ("https://acf.example/\x7f", "a character that does not show"),
        # What only the HTTP library refuses: said here, as a configuration error, and not by the first request.
        ("https://\N{SNOWMAN}-.example", "not a URL"),
        ("https://acf.example/" + "a" * 70_000, "not a URL"),
    ],
)
def test_a_base_url_that_cannot_be_an_endpoint_is_refused_whatever_else_is_said(
    harness: Harness, base_url: str, message: str
) -> None:
    for allow in (False, True):
        with pytest.raises(ConfigurationError, match=message) as raised:
            _client_type(harness)(CANARY_KEY, base_url=base_url, allow_insecure_http=allow)
        # The message names an example endpoint; apart from a bare scheme, nothing of the bad URL is in it.
        assert base_url == "https://" or base_url not in str(raised.value)
        assert "acf.exam" not in str(raised.value).replace("https://acf.example", "")


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"timeout": 0}, "timeout must be"),
        ({"timeout": -1}, "timeout must be"),
        ({"timeout": float("inf")}, "timeout must be"),
        ({"timeout": "120"}, "timeout must be"),
        ({"timeout": True}, "timeout must be"),
        ({"max_retries": -1}, "max_retries must be"),
        ({"max_retries": 1.5}, "max_retries must be"),
        ({"max_retries": True}, "max_retries must be"),
        ({"follow_max": -1}, "follow_max must be"),
        ({"follow_max": float("nan")}, "follow_max must be"),
        ({"retry_total_max": -1}, "retry_total_max must be"),
        ({"project": 7}, "project must be"),
        ({"project": ".."}, "project must name one record"),
    ],
)
def test_settings_that_cannot_work_are_refused_at_construction(
    harness: Harness, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        _client_type(harness)(CANARY_KEY, base_url=BASE_URL, **options)


def test_each_client_takes_the_http_client_of_its_own_kind(harness: Harness) -> None:
    wrong: Any = httpx2.Client() if harness.is_async else httpx2.AsyncClient()
    with pytest.raises(ConfigurationError, match="http_client must be"):
        _client_type(harness)(CANARY_KEY, base_url=BASE_URL, http_client=wrong)
    _close(harness, wrong)


def test_a_configuration_error_is_raised_before_any_request(harness: Harness) -> None:
    script = harness.script()
    with pytest.raises(ConfigurationError):
        harness.client(script, base_url="http://acf.example")
    assert script.seen == []


# --------------------------------------------------------------------------------------- what is sent
def test_every_request_says_what_client_it_is_and_nothing_about_the_machine(harness: Harness) -> None:
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    harness.run(harness.client(script).sandboxes.get(SBX))
    headers = script.seen[0].headers
    assert headers["user-agent"] == f"agent-compute-python/{__version__}"
    assert headers["accept"] == "application/json, application/problem+json"
    assert set(headers) == {"host", "accept", "accept-encoding", "connection", "user-agent", "authorization"}


def test_the_timeout_bounds_each_request(harness: Harness) -> None:
    seen: list[Any] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.extensions["timeout"])
        return httpx2.Response(200, json=sandbox())

    harness.run(harness.client(handler).sandboxes.get(SBX))
    harness.run(harness.client(handler, timeout=7.5).sandboxes.get(SBX))
    assert seen[0] == {"connect": 120.0, "read": 120.0, "write": 120.0, "pool": 120.0}
    assert seen[1] == {"connect": 7.5, "read": 7.5, "write": 7.5, "pool": 7.5}


def test_a_base_url_with_a_path_keeps_its_path(harness: Harness) -> None:
    expected = {"method": "GET", "path": f"/acf/eu/v1/projects/{PROJECT}/sandboxes/{SBX}"}
    script = harness.script(Exchange(expected, reply(200, sandbox())), base_url="https://gateway.test/acf/eu")
    fabric = harness.client(script, base_url="https://gateway.test/acf/eu/")
    assert harness.run(fabric.sandboxes.get(SBX)).sandbox_id == SBX


# ------------------------------------------------------------------- nothing goes anywhere else
def test_an_operation_is_followed_at_the_endpoint_whatever_its_location_says(harness: Harness) -> None:
    accepted = reply(
        202,
        operation("sandbox.create", "ACCEPTED"),
        location=f"https://elsewhere.example/v1/projects/{PROJECT}/operations/{OP}",
        retry_after="1",
    )
    script = harness.script(
        ex("POST", "/sandboxes", accepted),
        ex("GET", f"/operations/{OP}", reply(200, done("sandbox.create", "sandbox", sandbox("READY")))),
    )
    fabric = harness.client(script)
    harness.run(fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False))
    # The scripted server fails any request to another origin; both requests reached it.
    assert len(script.seen) == 2


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed(harness: Harness, status: int) -> None:
    redirect = {"status": status, "headers": {"location": "https://elsewhere.example/v1/info"}, "content": b""}
    script = harness.script(ex("GET", "/v1/info", redirect))
    with pytest.raises(UnexpectedResponseError) as raised:
        harness.run(harness.client(script).info())
    assert raised.value.status == status
    assert len(script.seen) == 1


@pytest.mark.parametrize(
    "operation_id",
    ["https://elsewhere.example/steal", "//elsewhere.example/steal", "../../../auth/whoami", "a/b?c=d#e"],
)
def test_an_identifier_from_an_answer_cannot_move_a_request_to_another_route_or_origin(
    harness: Harness, operation_id: str
) -> None:
    accepted = reply(202, operation("sandbox.create", "ACCEPTED", operation_id=operation_id), retry_after="1")
    ended = done("sandbox.create", "sandbox", sandbox("READY"), operation_id=operation_id)
    script = harness.script(
        ex("POST", "/sandboxes", accepted), ex("GET", f"/operations/{operation_id}", reply(200, ended))
    )
    harness.run(harness.client(script).sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False))
    followed = script.seen[1].raw_path
    assert followed.startswith(f"/v1/projects/{PROJECT}/operations/")
    assert followed.count("/") == 5
    assert "/../" not in followed
    assert not followed.endswith("/..")


@pytest.mark.parametrize("operation_id", ["..", ".", ""])
def test_an_operation_that_names_itself_with_a_dot_segment_is_not_followed(harness: Harness, operation_id: str) -> None:
    accepted = reply(202, operation("sandbox.create", "ACCEPTED", operation_id=operation_id), retry_after="1")
    script = harness.script(ex("POST", "/sandboxes", accepted))
    with pytest.raises(UnexpectedResponseError, match="'operation_id'"):
        harness.run(harness.client(script).sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False))
    assert len(script.seen) == 1


def test_what_a_callers_http_client_was_configured_with_cannot_redirect_the_key(harness: Harness) -> None:
    """A base URL, credentials, cookies and redirect-following set on the HTTP client do not apply."""
    script = Script([ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox()))])
    settings: dict[str, Any] = {
        "transport": httpx2.MockTransport(script.handler),
        "base_url": "https://elsewhere.example/api",
        "auth": ("someone", "else"),
        "follow_redirects": True,
        "headers": {"X-Extra": "1"},
    }
    fabric: Fabric | AsyncFabric
    if harness.is_async:
        fabric = AsyncFabric(CANARY_KEY, base_url=BASE_URL, project=PROJECT, http_client=httpx2.AsyncClient(**settings))
    else:
        fabric = Fabric(CANARY_KEY, base_url=BASE_URL, project=PROJECT, http_client=httpx2.Client(**settings))
    harness.virtualize(fabric)
    harness.run(fabric.sandboxes.get(SBX))
    script.finish()
    assert script.seen[0].headers["authorization"] == f"Bearer {CANARY_KEY}"
    _close(harness, fabric._driver._http)


# ------------------------------------------------------------------------------------------- lifetime
def test_closing_a_client_closes_the_http_client_it_built(harness: Harness) -> None:
    fabric = _client_type(harness)(CANARY_KEY, base_url=BASE_URL)
    http = fabric._driver._http
    assert not http.is_closed
    _close(harness, fabric)
    assert http.is_closed


def test_a_client_is_a_context_manager(harness: Harness) -> None:
    if harness.is_async:

        async def scenario() -> httpx2.AsyncClient:
            async with AsyncFabric(CANARY_KEY, base_url=BASE_URL) as fabric:
                return fabric._driver._http

        assert harness.run(scenario()).is_closed
    else:
        with Fabric(CANARY_KEY, base_url=BASE_URL) as fabric:
            http = fabric._driver._http
        assert http.is_closed


def test_an_http_client_that_was_passed_in_is_left_open_for_its_owner(harness: Harness) -> None:
    fabric = harness.client(harness.script())
    http = fabric._driver._http
    _close(harness, fabric)
    assert not http.is_closed


def test_the_repr_of_a_client_shows_where_it_points_and_not_the_key(harness: Harness) -> None:
    fabric = harness.client(harness.script())
    name = "AsyncFabric" if harness.is_async else "Fabric"
    assert repr(fabric) == f"{name}(base_url='https://acf.test', project='{PROJECT}')"


# ------------------------------------------------------------------------------------------- sharing
def test_one_client_serves_many_callers_at_once(harness: Harness) -> None:
    """Threads for the synchronous client, tasks for the asynchronous one."""
    counted = {"requests": 0}
    lock = threading.Lock()

    def handler(request: httpx2.Request) -> httpx2.Response:
        with lock:
            counted["requests"] += 1
        return httpx2.Response(200, json=sandbox())

    fabric = harness.client(handler)
    results: list[str] = []
    if isinstance(fabric, AsyncFabric):
        shared = fabric

        async def together() -> list[str]:
            found = await asyncio.gather(*[shared.sandboxes.get(SBX) for _ in range(32)])
            return [item.sandbox_id for item in found]

        results = harness.run(together())
    else:
        blocking = fabric

        def one() -> None:
            results.append(blocking.sandboxes.get(SBX).sandbox_id)

        threads = [threading.Thread(target=one) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert results == [SBX] * 32
    assert counted["requests"] == 32
