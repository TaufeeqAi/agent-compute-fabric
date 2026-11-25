"""``acf mcp``: run the stdio relay of the platform's agent endpoint.

An agent host starts this command and speaks the Model Context Protocol to it over standard input and
output. Standard output therefore carries protocol messages and nothing else, ever: every word of this
tool's own goes to standard error.

**An agent acts through an agent key.** Before a single message is read, the key is checked to be one
of kind ``agent``: first by the kind marker every key carries, which needs no request, and then, when
the address of the public API is known, by asking the platform who the key is. With any other key the
relay does not start. That is a convenience for the developer, who would otherwise hand an agent host
their own authority without meaning to; the platform's own refusal is the control.

**Stopping cancels nothing.** A closed input is a disconnect: what was read is carried to its end. An
interruption stops the relay at once. Neither cancels an execution on the platform.
"""

from __future__ import annotations

import asyncio
import re
import signal
import ssl
import sys
from typing import Annotated, Any, BinaryIO, Final

import httpx2
import typer

from agentcompute_cli import common, credentials, render
from agentcompute_cli.common import ProfileOpt, guard
from agentcompute_cli.outcome import CliError, ExitCode, UsageError
from agentcompute_cli.relay import Relay, stdin_lines

__all__ = ["REQUEST_TIMEOUT", "mcp", "new_http_client", "trust_of"]

#: Seconds the endpoint has for each step of one exchange: longer than the longest wait of a tool call,
#: and than the pause between two signs of life on a stream that is still open.
REQUEST_TIMEOUT: Final = 120.0

#: The kind marker of a key: ``acf<format version>_<kind>_...``.
_KEY_KIND: Final = re.compile(r"acf[0-9]+_(?P<kind>[a-z]+)_", re.ASCII)
#: What a key is made of: visible ASCII. Nothing else can be sent in a header, and no key has it.
_KEY_CHARACTERS: Final = re.compile(r"[\x21-\x7e]+", re.ASCII)
_AGENT_MARKER: Final = "agt"
_AGENT_KIND: Final = "agent"
_SIGNAL_BASE: Final = 128
_MINT: Final = (
    "Mint a key for the agent: acf auth agent-key create --label NAME --lifetime 1h. "
    f"Then give it to the agent host as {credentials.ENV_API_KEY}."
)
_STOPPED: Final = (
    "stopped. Nothing was cancelled: an execution that was started through this relay keeps running. "
    "`acf exec cancel EXECUTION` cancels one"
)


def _log(text: str) -> None:
    render.line(f"acf mcp: {text}", err=True)


def trust_of(ca_file: str | None) -> ssl.SSLContext | None:
    """Whom the relay believes about the endpoint's certificate, when a file of authorities was named.

    The authorities of that file and no others: the system's own are not consulted. A file that holds no
    certificate is a usage error, and is never passed over in favour of the system's authorities, which
    are exactly the ones its author meant to exclude.
    """
    if ca_file is None:
        return None
    try:
        return ssl.create_default_context(cafile=ca_file)
    except (OSError, ValueError):
        raise UsageError(
            "the file of certificate authorities holds no certificate this tool can read",
            next_step=f"Check {credentials.ENV_CA_FILE} or the stored profile: each names a PEM file.",
        ) from None


def new_http_client(trust: ssl.SSLContext | None = None) -> httpx2.AsyncClient:
    """The one place the relay's HTTP client is built, so that a test can hand it a scripted transport.

    Nothing is taken from the environment: no proxy and none of the general certificate variables. The
    key goes where the configuration says and nowhere else, and whom to believe there is ``trust``, or
    the HTTP library's default without one.
    """
    settings: dict[str, Any] = {
        "trust_env": False,
        "follow_redirects": False,
        "timeout": httpx2.Timeout(REQUEST_TIMEOUT),
    }
    if trust is not None:
        settings["verify"] = trust
    return httpx2.AsyncClient(**settings)


def _relayable(address: str) -> str:
    """The address, once the HTTP library has read it too: a usage error now, not a failure at the first message."""
    try:
        read = httpx2.URL(address)
    except httpx2.InvalidURL:
        read = None
    if read is None or read.scheme not in {"http", "https"} or not read.host:
        raise UsageError(
            "the address of the MCP endpoint is not a URL this tool can read",
            next_step=f"Check --endpoint, {credentials.ENV_MCP_URL} or the stored profile.",
        )
    return address


def _require_agent_key(settings: credentials.RelaySettings) -> None:
    """Refuse to go on with a key that is not an agent's. No request is made for a key whose marker says so."""
    if _KEY_CHARACTERS.fullmatch(settings.api_key) is None:
        raise UsageError(
            "the key in use holds a character no key has: a space, a line break or a non-ASCII character",
            next_step=f"Check how it was copied into {credentials.ENV_API_KEY} or into the stored profile.",
        )
    marker = _KEY_KIND.match(settings.api_key)
    if marker is None or marker["kind"] != _AGENT_MARKER:
        raise UsageError(
            "acf mcp relays for an agent, and an agent acts through an agent key: the key in use is not one",
            next_step=_MINT,
        )
    if settings.base_url is None:
        return
    stated = credentials.Settings(settings.api_key, settings.base_url, None, {}, settings.ca_file)
    with common.new_fabric(stated, timeout=None) as fabric:
        kind = fabric.whoami().credential.kind
    if kind != _AGENT_KIND:
        # Not a UsageError: the platform was asked who the key is, so "nothing was sent" would not be true.
        raise CliError(
            "acf mcp relays for an agent, and the platform says the key in use is not an agent key",
            exit_code=ExitCode.USAGE,
            next_step=f"No message was read or relayed. {_MINT}",
        )


class _Output:
    """Standard output of the relay: one whole line per call, and the knowledge that the reader went away."""

    def __init__(self, stream: BinaryIO, stop: asyncio.Task[int]) -> None:
        self._stream = stream
        self._stop = stop
        self.reader_gone = False

    def __call__(self, line: bytes) -> None:
        if self.reader_gone:
            return
        try:
            self._stream.write(line)
            self._stream.flush()
        except BrokenPipeError:
            # Nobody reads the answers any more, so there is nothing left to relay for.
            self.reader_gone = True
            self._stop.cancel()


async def _serve(settings: credentials.RelaySettings, endpoint: str, trust: ssl.SSLContext | None) -> int:
    """Relay until the input ends or the process is told to stop. Returns the exit status.

    A reader of standard output that went away is raised as what it is, a broken pipe, and so reaches
    the one place that ends a command for it.
    """
    task = asyncio.current_task()
    if task is None:
        raise RuntimeError("the relay runs inside a task")
    stopped: list[int] = []

    def stop(signum: int) -> None:
        stopped.append(signum)
        task.cancel()

    if credentials.is_posix():
        # Elsewhere there is no such registration, and an interruption arrives as KeyboardInterrupt.
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(signum, stop, signum)
    output = _Output(sys.stdout.buffer, task)
    async with new_http_client(trust) as http:
        relay = Relay(endpoint=endpoint, api_key=settings.api_key, http=http, write=output, log=_log)
        try:
            await relay.run(stdin_lines(sys.stdin.buffer))
        except asyncio.CancelledError:
            if output.reader_gone:
                # Not a status of its own here: what handles a broken pipe also keeps the interpreter
                # from failing on the same pipe once more when it flushes at exit.
                raise BrokenPipeError from None
            if not stopped:
                raise
            _log(_STOPPED)
            return _SIGNAL_BASE + stopped[0]
    return int(ExitCode.OK)


@guard
def mcp(
    endpoint: Annotated[
        str | None,
        typer.Option(
            "--endpoint",
            metavar="URL",
            help="Address of the platform's MCP endpoint. Default: $ACF_MCP_URL, else the stored profile's.",
            show_default=False,
        ),
    ] = None,
    profile: ProfileOpt = None,
) -> None:
    """Relay the Model Context Protocol between standard input and output and the platform's MCP endpoint.

    For an agent host that starts its tools as programs. The key comes from $ACF_API_KEY or the stored
    profile and has to be an agent key: mint one with `acf auth agent-key create`.
    """
    settings = credentials.resolve_relay(endpoint=endpoint, profile=profile)
    render.protect(settings.api_key)
    address = _relayable(credentials.endpoint_address(settings.endpoint))
    trust = trust_of(settings.ca_file)
    _require_agent_key(settings)
    try:
        status = asyncio.run(_serve(settings, address, trust))
    except KeyboardInterrupt:
        _log(_STOPPED)
        status = int(ExitCode.INTERRUPTED)
    if status:
        raise typer.Exit(status)
