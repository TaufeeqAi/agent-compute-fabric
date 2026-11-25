"""``acf mcp`` as an agent host starts it: which key it accepts, where its words go, how it stops.

An agent acts through an agent key and never through a developer's. The command proves that before it
reads a single message: by the marker of the key, which needs no request, and then by asking the
platform when the address of the public API is known. Everything this tool has to say goes to standard
error, because standard output belongs to the protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import signal
import ssl
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

import authorities
from agentcompute_cli import credentials
from agentcompute_cli import mcp as relay_command
from agentcompute_cli.credentials import CredentialStore, Profile
from support import AGENT_KEY, BASE_URL, CANARY_KEY, MCP_URL, PROJECT, Cli, FakeStream, Json, ex, refusal, reply, whoami

MESSAGE: Json = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    },
}
LINE = json.dumps(MESSAGE).encode() + b"\n"
ANSWER: Json = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "tools": []}}
AGENT = {"ACF_API_KEY": AGENT_KEY}
IS_AGENT = ex("GET", "/v1/auth/whoami", reply(200, whoami("agent")))
MCP = ["mcp", "--endpoint", MCP_URL]

needs_posix = pytest.mark.skipif(os.name != "posix", reason="signals are delivered to a handler on POSIX only")


class Endpoint:
    """A scripted MCP endpoint that remembers what it was sent."""

    def __init__(self) -> None:
        self.seen: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.seen.append(request)
        return httpx2.Response(200, json=ANSWER)


def never(_: httpx2.Request) -> Any:
    raise AssertionError("the relay was not expected to send anything")


# --------------------------------------------------------------------------------------------- the key
@pytest.mark.parametrize(
    "key",
    [CANARY_KEY, "acf1_dev_" + "x" * 40, "acf2_dev_abc_def", "acf1_ops_abc_def", "eyJhbGciOiJSUzI1NiJ9.e30.sig",
     "agt_acf1_looks_alike", "acf1_agt"],
    ids=["developer", "developer-long", "later-format", "another-kind", "a-token", "marker-misplaced", "marker-cut"],
)  # fmt: skip
def test_a_key_that_is_not_an_agent_key_is_refused_without_a_single_request(cli: Cli, key: str) -> None:
    run = cli.run(MCP, env={"ACF_API_KEY": key}, stdin=LINE, api_key=key, endpoint=never)
    assert run.exit_code == 2
    assert run.requests == [], "the marker of the key says enough: nobody is asked"
    assert run.stdout == ""
    assert "an agent acts through an agent key" in run.stderr
    assert "acf auth agent-key create --label NAME --lifetime 1h" in run.stderr.splitlines()[-1]
    assert key not in run.stderr


def test_an_agent_key_is_checked_with_the_platform_and_the_relay_starts(cli: Cli) -> None:
    endpoint = Endpoint()
    run = cli.run(MCP, IS_AGENT, env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=endpoint)
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == json.dumps(ANSWER, separators=(",", ":")).encode() + b"\n"
    assert run.stderr == ""
    (posted,) = endpoint.seen
    assert str(posted.url) == MCP_URL
    assert posted.headers["authorization"] == f"Bearer {AGENT_KEY}"
    assert posted.content == LINE.rstrip(b"\n")


def test_a_later_format_of_agent_key_is_an_agent_key(cli: Cli) -> None:
    key = "acf2_agt_" + "y" * 40
    run = cli.run(MCP, IS_AGENT, env={"ACF_API_KEY": key}, stdin=LINE, api_key=key, endpoint=Endpoint())
    assert run.exit_code == 0, run.stderr


def test_a_key_that_wears_the_marker_and_is_no_agent_key_is_refused_before_any_message_is_read(cli: Cli) -> None:
    is_developer = ex("GET", "/v1/auth/whoami", reply(200, whoami("developer")))
    run = cli.run(MCP, is_developer, env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 2
    assert "the platform says the key in use is not an agent key" in run.stderr
    assert run.stdout == ""
    last = run.stderr.splitlines()[-1]
    assert "No message was read or relayed" in last
    assert "acf auth agent-key create --label NAME --lifetime 1h" in last
    assert "Nothing was sent" not in run.stderr, "the platform was asked who the key is"


@pytest.mark.parametrize(
    "key",
    [
        AGENT_KEY + "\n",
        "acf1_agt_with a space_" + "z" * 20,
        "acf1_agt_cl\N{LATIN SMALL LETTER E WITH ACUTE}_" + "z" * 20,
    ],
    ids=["line-break", "space", "not-ascii"],
)
def test_a_key_with_a_character_no_key_has_is_refused_before_it_could_reach_a_header(cli: Cli, key: str) -> None:
    """Also where the address of the public API is not known, and nothing but this command looks at the key."""
    for base_url in (BASE_URL, None):
        environment = {"ACF_API_KEY": key, "ACF_BASE_URL": base_url}
        run = cli.run(MCP, env=environment, stdin=LINE, api_key=key, endpoint=never)
        assert run.exit_code == 2
        assert "the key in use holds a character no key has" in run.stderr
        assert "Check how it was copied into ACF_API_KEY" in run.stderr.splitlines()[-1]
        assert run.requests == []
        assert run.stdout == ""
        assert key.strip() not in run.stderr


def test_a_key_the_platform_does_not_know_does_not_start_a_relay(cli: Cli) -> None:
    unknown = ex("GET", "/v1/auth/whoami", refusal("UNAUTHENTICATED"))
    run = cli.run(MCP, unknown, env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 3
    assert run.stdout == ""


def test_without_the_address_of_the_public_api_the_marker_is_what_there_is(cli: Cli) -> None:
    endpoint = Endpoint()
    run = cli.run(MCP, env={**AGENT, "ACF_BASE_URL": None}, stdin=LINE, api_key=AGENT_KEY, endpoint=endpoint)
    assert run.exit_code == 0, run.stderr
    assert run.requests == [], "nobody could be asked, and the endpoint itself still decides"
    assert len(endpoint.seen) == 1


# --------------------------------------------------------------------------------------- configuration
def test_the_key_the_endpoint_and_the_address_can_all_come_from_the_stored_profile(cli: Cli) -> None:
    CredentialStore(cli.credentials_file).put("agent", Profile(AGENT_KEY, BASE_URL, PROJECT, MCP_URL))
    endpoint = Endpoint()
    run = cli.run(
        ["mcp", "--profile", "agent"],
        IS_AGENT,
        env={"ACF_API_KEY": None, "ACF_BASE_URL": None, "ACF_PROJECT": None},
        stdin=LINE,
        api_key=AGENT_KEY,
        endpoint=endpoint,
    )
    assert run.exit_code == 0, run.stderr
    assert str(endpoint.seen[0].url) == MCP_URL


def _names(trust: ssl.SSLContext | None) -> list[str]:
    assert trust is not None
    names: list[str] = []
    for certificate in trust.get_ca_certs():
        subject: Any = certificate["subject"]
        names.extend(value for part in subject for name, value in part if name == "commonName")
    return sorted(names)


def test_the_relay_believes_the_authorities_that_were_named_and_no_others(cli: Cli, tmp_path: Path) -> None:
    """From the environment, or from the profile together with the endpoint the profile holds."""
    one, two = tmp_path / "one.pem", tmp_path / "two.pem"
    one.write_text(authorities.ONE, encoding="ascii")
    two.write_text(authorities.TWO, encoding="ascii")
    CredentialStore(cli.credentials_file).put("agent", Profile(AGENT_KEY, BASE_URL, PROJECT, MCP_URL, str(one)))
    stored = {"ACF_API_KEY": None, "ACF_BASE_URL": None, "ACF_PROJECT": None}
    for env, wanted in ((stored, authorities.ONE_NAME), ({**stored, "ACF_CA_FILE": str(two)}, authorities.TWO_NAME)):
        run = cli.run(
            ["mcp", "--profile", "agent"], IS_AGENT, env=env, stdin=LINE, api_key=AGENT_KEY, endpoint=Endpoint()
        )
        assert run.exit_code == 0, run.stderr
        trust = cli.relay_trust[-1]
        assert _names(trust) == [wanted], "the system's authorities were not loaded beside it"
        assert trust is not None
        assert (trust.verify_mode, trust.check_hostname) == (ssl.CERT_REQUIRED, True)
        assert cli.clients[-1][0].ca_file in {str(one), str(two)}, "the key was checked believing the same ones"


def test_stored_authorities_are_not_used_for_an_endpoint_the_profile_does_not_hold(cli: Cli, tmp_path: Path) -> None:
    one = tmp_path / "one.pem"
    one.write_text(authorities.ONE, encoding="ascii")
    CredentialStore(cli.credentials_file).put("default", Profile(AGENT_KEY, BASE_URL, PROJECT, MCP_URL, str(one)))
    run = cli.run(
        ["mcp", "--endpoint", "https://elsewhere.test/mcp"],
        IS_AGENT,
        env=AGENT,
        stdin=LINE,
        api_key=AGENT_KEY,
        endpoint=Endpoint(),
    )
    assert run.exit_code == 0, run.stderr
    assert cli.relay_trust == [None]


def test_without_authorities_the_relay_keeps_the_default_and_reads_nothing_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []

    class Recording(httpx2.AsyncClient):
        def __init__(self, **settings: Any) -> None:
            seen.append(settings)
            super().__init__(**settings)

    monkeypatch.setattr(httpx2, "AsyncClient", Recording)
    for name in ("SSL_CERT_FILE", "HTTPS_PROXY"):
        monkeypatch.setenv(name, "/nowhere")
    asyncio.run(relay_command.new_http_client().aclose())
    assert relay_command.trust_of(None) is None
    assert seen[0]["trust_env"] is False
    assert seen[0]["follow_redirects"] is False
    assert "verify" not in seen[0]


def test_a_file_that_holds_no_certificate_does_not_start_a_relay(cli: Cli, tmp_path: Path) -> None:
    """Falling back to the system's authorities would believe exactly the ones its author meant to exclude."""
    words = tmp_path / "words.pem"
    words.write_text("no certificate here\n", encoding="ascii")
    run = cli.run(MCP, env={**AGENT, "ACF_CA_FILE": str(words)}, stdin=LINE, api_key=AGENT_KEY, endpoint=Endpoint())
    assert run.exit_code == 2
    assert "holds no certificate this tool can read" in run.stderr
    assert run.requests == []
    assert cli.relay_trust == []
    assert run.stdout == ""


def test_the_endpoint_is_the_flag_then_the_environment_then_the_profile(cli: Cli) -> None:
    CredentialStore(cli.credentials_file).put(
        "default", Profile(AGENT_KEY, BASE_URL, PROJECT, "https://stored.test/mcp")
    )
    environment = {**AGENT, "ACF_MCP_URL": "https://env.test/mcp"}
    for args, env, wanted in (
        (["mcp"], AGENT, "https://stored.test/mcp"),
        (["mcp"], environment, "https://env.test/mcp"),
        (MCP, environment, MCP_URL),
    ):
        endpoint = Endpoint()
        run = cli.run(args, IS_AGENT, env=env, stdin=LINE, api_key=AGENT_KEY, endpoint=endpoint)
        assert run.exit_code == 0, run.stderr
        assert str(endpoint.seen[0].url) == wanted


def test_no_endpoint_is_a_usage_error_that_says_where_to_give_one(cli: Cli) -> None:
    run = cli.run(["mcp"], env=AGENT, stdin=LINE, endpoint=never)
    assert run.exit_code == 2
    assert "the address of the platform's MCP endpoint is not known" in run.stderr
    last = run.stderr.splitlines()[-1]
    assert "--endpoint" in last
    assert "ACF_MCP_URL" in last


def test_no_key_is_a_usage_error_that_says_how_to_mint_one(cli: Cli) -> None:
    run = cli.run(MCP, env={"ACF_API_KEY": None}, stdin=LINE, endpoint=never)
    assert run.exit_code == 2
    assert "there is no agent key to relay with" in run.stderr
    assert "acf auth agent-key create" in run.stderr.splitlines()[-1]


@pytest.mark.parametrize(
    "address",
    [
        "http://mcp.acf.example/mcp",
        f"https://x:{AGENT_KEY}@mcp.acf.example/mcp",
        f"https://mcp.acf.example/mcp?key={AGENT_KEY}",
    ],
    ids=["plain-http", "user-information", "query"],
)
def test_an_endpoint_a_key_may_not_be_sent_to_is_refused_before_anything_is_sent(cli: Cli, address: str) -> None:
    run = cli.run(["mcp", "--endpoint", address], env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 2
    assert run.requests == []
    assert AGENT_KEY not in run.stderr


@pytest.mark.parametrize(
    "address",
    [
        MCP_URL + "\n",
        " " + MCP_URL,
        "https://mcp.acf.test/m cp",
        "https://mcp.acf.test\t.elsewhere.example/mcp",
        "https://mcp.acf.test/\N{ZERO WIDTH SPACE}mcp",
        "https://mcp.acf.test\N{NO-BREAK SPACE}/mcp",
    ],
    ids=["line-break", "leading-space", "space", "tab", "zero-width", "no-break-space"],
)
def test_an_endpoint_address_with_a_character_no_url_has_is_refused_and_not_tidied(cli: Cli, address: str) -> None:
    """One parser would drop such a character without a word and another would not: the two must read one address."""
    run = cli.run(["mcp"], env={**AGENT, "ACF_MCP_URL": address}, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 2
    assert "holds a space, a line break or another character no URL has" in run.stderr
    assert run.requests == []
    assert "\N{ZERO WIDTH SPACE}" not in run.stderr


def test_an_address_of_the_public_api_with_a_line_break_does_not_start_a_relay(cli: Cli) -> None:
    environment = {**AGENT, "ACF_BASE_URL": BASE_URL + "\n"}
    run = cli.run(MCP, env=environment, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 2
    assert "the address of the platform holds a space, a line break" in run.stderr
    assert run.requests == []
    assert run.stdout == ""


@pytest.mark.parametrize(
    "address",
    ["https://\N{SNOWMAN}.-x.example/mcp", "https://mcp.acf.test/" + "p" * 70_000],
    ids=["a-host-that-is-no-name", "too-long"],
)
def test_an_endpoint_address_the_http_library_cannot_read_is_refused_at_the_start(cli: Cli, address: str) -> None:
    """Otherwise it would fail at the first message, inside the relay, where nobody is told what to change."""
    run = cli.run(["mcp", "--endpoint", address], env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=never)
    assert run.exit_code == 2
    assert "the address of the MCP endpoint is not a URL this tool can read" in run.stderr
    assert "ACF_MCP_URL" in run.stderr.splitlines()[-1]
    assert run.requests == []
    assert run.stdout == ""


# ---------------------------------------------------------------------------------- the two streams
def test_standard_output_carries_messages_of_the_protocol_and_nothing_else(cli: Cli) -> None:
    lines = b"this is not json\n" + LINE + b"\n" + json.dumps({**MESSAGE, "id": 2}).encode() + b"\n"

    async def endpoint(request: httpx2.Request) -> httpx2.Response:
        rpc_id = json.loads(request.content)["id"]
        if rpc_id == 2:
            return httpx2.Response(502, content=b"<html>bad gateway</html>")
        return httpx2.Response(200, json={**ANSWER, "id": rpc_id})

    run = cli.run(MCP, IS_AGENT, env=AGENT, stdin=lines, api_key=AGENT_KEY, endpoint=endpoint)
    assert run.exit_code == 0, run.stderr
    written = [json.loads(line) for line in run.stdout_bytes.splitlines()]
    assert len(written) == 3
    assert all(message["jsonrpc"] == "2.0" for message in written), "every line is a message"
    assert sorted(message["id"] is None for message in written) == [False, False, True]
    assert all(line.startswith("acf mcp: ") for line in run.stderr.splitlines()), "its own words go to standard error"
    assert "is not JSON" in run.stderr
    assert "HTTP 502" in run.stderr
    assert AGENT_KEY not in run.stdout + run.stderr


class _GoneBytes(io.BytesIO):
    def write(self, _data: Any) -> int:
        raise BrokenPipeError(32, "Broken pipe")


class _Gone(FakeStream):
    """Standard output whose reader went away."""

    def __init__(self) -> None:
        super().__init__()
        self._gone = _GoneBytes()

    @property
    def buffer(self) -> io.BytesIO:
        return self._gone


def test_141_when_nobody_reads_the_answers_any_more(cli: Cli) -> None:
    run = cli.run(MCP, IS_AGENT, env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=Endpoint(), stdout=_Gone())
    assert run.exit_code == 141


# -------------------------------------------------------------------------------------------- stopping
class Hanging:
    """An endpoint that never answers, and does one thing when it is first asked."""

    def __init__(self, on_request: Any) -> None:
        self.seen: list[Json] = []
        self._on_request = on_request

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.seen.append(json.loads(request.content))
        self._on_request()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@needs_posix
@pytest.mark.parametrize(("signum", "status"), [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_a_signal_stops_the_relay_and_cancels_nothing(cli: Cli, signum: signal.Signals, status: int) -> None:
    endpoint = Hanging(lambda: os.kill(os.getpid(), signum))
    call = {**MESSAGE, "method": "tools/call", "params": {**MESSAGE["params"], "name": "sandbox_exec", "arguments": {}}}
    run = cli.run(
        MCP, IS_AGENT, env=AGENT, stdin=json.dumps(call).encode() + b"\n", api_key=AGENT_KEY, endpoint=endpoint
    )
    assert run.exit_code == status
    assert run.stdout == ""
    assert "acf mcp: stopped. Nothing was cancelled" in run.stderr
    assert "acf exec cancel EXECUTION" in run.stderr
    assert len(endpoint.seen) == 1, "no cancel was sent for the call that was in flight"


# ----------------------------------------------------------------------------- the program as a process
#: The program itself, relaying to an address of this machine where nobody listens. No test here sends
#: a message that would be posted, so nothing is ever sent there.
PROGRAM = [sys.executable, "-m", "agentcompute_cli", "mcp", "--endpoint", "http://127.0.0.1:9/mcp"]
NOT_A_MESSAGE = b"this is not json\n"


@pytest.fixture
def program(tmp_path: Path) -> Iterator[subprocess.Popen[bytes]]:
    """The real program, started as an agent host starts it: pipes for its three streams. Never left running."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("ACF_")}
    home = str(tmp_path)
    environment |= {"ACF_API_KEY": AGENT_KEY, "XDG_CONFIG_HOME": home, "APPDATA": home, "HOME": home}
    # The program under test, run by the interpreter that runs the tests: nothing here comes from outside.
    process = subprocess.Popen(  # noqa: S603
        PROGRAM, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
    )
    try:
        yield process
    finally:
        process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()


def answered(process: subprocess.Popen[bytes]) -> Json:
    """Write a line that is no message and read what the relay answers: it is then up, and nothing was posted."""
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(NOT_A_MESSAGE)
    process.stdin.flush()
    answer: Json = json.loads(process.stdout.readline())
    return answer


def ended(process: subprocess.Popen[bytes]) -> tuple[int, str]:
    """Wait for the program to end by itself, its input still open, and give its status and what it said."""
    assert process.stderr is not None
    status = process.wait(timeout=30)
    return status, process.stderr.read().decode()


@needs_posix
@pytest.mark.parametrize(("signum", "status"), [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_the_program_stops_cleanly_on_a_signal_while_its_input_is_still_open(
    program: subprocess.Popen[bytes], signum: signal.Signals, status: int
) -> None:
    """An agent host stops its tools with a signal and keeps their input open.

    A thread of the relay is waiting for input at that moment, and an interpreter that shuts down
    around a thread that holds a lock on the input ends by aborting the process.
    """
    assert answered(program)["error"]["code"] == -32700
    program.send_signal(signum)
    exit_status, said = ended(program)
    assert exit_status == status, said
    assert "acf mcp: stopped. Nothing was cancelled" in said
    assert "Fatal Python error" not in said
    assert "Traceback" not in said


@needs_posix
def test_the_program_exits_141_when_its_reader_goes_away_while_its_input_is_still_open(
    program: subprocess.Popen[bytes],
) -> None:
    """The status has to survive the interpreter's own last flush to the pipe nobody reads."""
    assert answered(program)["id"] is None
    assert program.stdout is not None
    assert program.stdin is not None
    program.stdout.close()
    program.stdin.write(NOT_A_MESSAGE)
    program.stdin.flush()
    exit_status, said = ended(program)
    assert exit_status == 141, said
    assert "Fatal Python error" not in said
    assert "Traceback" not in said
    assert "Exception ignored" not in said


def test_the_program_ends_with_0_when_its_input_is_closed(program: subprocess.Popen[bytes]) -> None:
    out, err = program.communicate(NOT_A_MESSAGE, timeout=30)
    assert program.returncode == 0, err.decode()
    assert json.loads(out)["error"]["code"] == -32700
    assert err.decode().splitlines() == [
        "acf mcp: a line of input is not JSON: answered with an error, and not relayed"
    ]


@needs_posix
def test_where_no_handler_can_be_registered_an_interruption_does_the_same(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other branch: no handler of this tool's own, and the interruption arrives as Python delivers it.

    It takes a real signal to interrupt a real event loop, so the branch for systems without such
    handlers is run on a system that has them, told that it has none.
    """
    monkeypatch.setattr(credentials, "is_posix", lambda: False)
    endpoint = Hanging(lambda: os.kill(os.getpid(), signal.SIGINT))
    run = cli.run(MCP, IS_AGENT, env=AGENT, stdin=LINE, api_key=AGENT_KEY, endpoint=endpoint)
    assert run.exit_code == 130
    assert run.stdout == ""
    assert "acf mcp: stopped. Nothing was cancelled" in run.stderr
    assert len(endpoint.seen) == 1
