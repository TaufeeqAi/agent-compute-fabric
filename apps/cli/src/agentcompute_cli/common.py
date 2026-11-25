"""What every command shares: its options, its connection to the platform, and how it ends.

A command is a thin thing: it turns its options into one call of the SDK and shows what came back. What
it has in common with every other command lives here, so that each rule is written once:

* the options every command takes, and the ones every command that changes something takes;
* :func:`connect`, which builds the SDK client from flags, environment and the stored profile;
* :class:`Session`, through which every call of the SDK is made, which prints a result as JSON or for
  people, and which knows what ``--no-wait`` means;
* :func:`guard`, which turns whatever ends a command into a message and an exit status.

**One key per command.** A command that changes something gives its call an idempotency key before
anything is sent: the one the caller passed, or one it makes. The key is therefore known whatever
happens next, including Ctrl-C, and every message that says "ask again" can name it.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import sys
import traceback
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final

import typer
from agentcompute import Fabric, FabricError, Operation, OperationStillRunningError, View

from agentcompute_cli import credentials, render, units, views
from agentcompute_cli.outcome import ArgumentError, CliError, ExitCode, Report, UsageError, describe

__all__ = [
    "BaseUrlOpt",
    "Common",
    "FollowMaxOpt",
    "GenerationOpt",
    "Intent",
    "JsonOpt",
    "KeyOpt",
    "NoWaitOpt",
    "ProfileOpt",
    "ProjectOpt",
    "Session",
    "TimeoutOpt",
    "VerboseOpt",
    "connect",
    "guard",
    "new_fabric",
    "note",
]

# ------------------------------------------------------------------------------------------- options
JsonOpt = Annotated[
    bool,
    typer.Option("--json", help="Print one JSON document: the answer exactly as the platform sent it."),
]
ProfileOpt = Annotated[
    str | None,
    typer.Option(
        "--profile",
        metavar="NAME",
        help="The stored profile to use. Default: $ACF_PROFILE, else `default`.",
        show_default=False,
    ),
]
BaseUrlOpt = Annotated[
    str | None,
    typer.Option(
        "--base-url",
        metavar="URL",
        help="Address of the platform's public API. Default: $ACF_BASE_URL, else the stored profile's.",
        show_default=False,
    ),
]
ProjectOpt = Annotated[
    str | None,
    typer.Option(
        "--project",
        metavar="PROJECT",
        help="The project to act in. Default: $ACF_PROJECT, else the project the key belongs to.",
        show_default=False,
    ),
]
VerboseOpt = Annotated[
    bool,
    typer.Option("--verbose", help="Write the request id of every answer, and every retry, to standard error."),
]
TimeoutOpt = Annotated[
    str | None,
    typer.Option(
        "--timeout",
        metavar="DURATION",
        help="How long one HTTP request may take: 90, 90s, 2m. Default: 120s. It does not bound an operation.",
        show_default=False,
    ),
]
KeyOpt = Annotated[
    str | None,
    typer.Option(
        "--idempotency-key",
        metavar="KEY",
        help="The idempotency key of this request. Repeating a command with the same key and the same "
        "arguments returns the same operation: nothing runs twice. Default: a new key.",
        show_default=False,
    ),
]
FollowMaxOpt = Annotated[
    str | None,
    typer.Option(
        "--follow-max",
        metavar="DURATION",
        help="How long to follow the operation before reporting it as still running: 90s, 10m, 2h. "
        "Default: 30m. The operation itself is not affected.",
        show_default=False,
    ),
]
NoWaitOpt = Annotated[
    bool,
    typer.Option(
        "--no-wait",
        help="Do not wait for the operation: ask the platform to answer at once, print the operation "
        "as that answer shows it, and exit.",
    ),
]
GenerationOpt = Annotated[
    str | None,
    typer.Option(
        "--generation",
        metavar="N|current",
        help="Act only on this generation of the sandbox, or on whatever is there with `current`. "
        "Default: the generation read just before.",
        show_default=False,
    ),
]

_SDK_LOGGER: Final = "agentcompute"


@dataclass(frozen=True, slots=True)
class Common:
    """The options every command that calls the API takes."""

    as_json: bool
    profile: str | None
    base_url: str | None
    project: str | None
    verbose: bool
    #: How long one HTTP request may take, as typed.
    timeout: str | None


@dataclass(frozen=True, slots=True)
class Intent:
    """How one command that changes something wants its operation issued and followed."""

    #: The idempotency key of the call: the caller's, or one made before anything was sent.
    key: str
    #: Seconds to follow the operation. ``None``: the SDK's own bound.
    follow_max: float | None
    no_wait: bool


class _Invocation:
    """What the handler of errors has to know about the command that is running."""

    __slots__ = ("key",)

    def __init__(self) -> None:
        #: The idempotency key of the call the command makes, once it has one.
        self.key: str | None = None


_INVOCATION: Final = _Invocation()


def note(text: str) -> None:
    """One line of this tool's own on standard error. What it quotes must have been made safe."""
    render.line(f"acf: {text}", err=True)


# --------------------------------------------------------------------------------------- the session
def new_fabric(settings: credentials.Settings, *, timeout: float | None) -> Fabric:
    """The one place a client is built, so that a test can hand it a scripted transport.

    Only what was configured is passed on: for everything else the SDK's own default applies, and whom to
    believe about the platform's certificate is the SDK's to work out from the file that was named.
    """
    options: dict[str, Any] = {}
    if timeout is not None:
        options["timeout"] = timeout
    if settings.ca_file is not None:
        options["ca_file"] = settings.ca_file
    return Fabric(settings.api_key, base_url=settings.base_url, project=settings.project, **options)


class _Records(logging.Handler):
    """Shows the SDK's own records on standard error: each retry, with its attempt number and its reason."""

    def emit(self, record: logging.LogRecord) -> None:
        note(render.safe_line(record.getMessage()))


@contextlib.contextmanager
def _sdk_records() -> Iterator[None]:
    logger = logging.getLogger(_SDK_LOGGER)
    handler = _Records(level=logging.INFO)
    before = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(before)


class Session:
    """One command's connection to the platform, and the way that command reports."""

    def __init__(self, fabric: Fabric, common: Common) -> None:
        self.fabric: Final = fabric
        self.as_json: Final = common.as_json
        self.verbose: Final = common.verbose
        self._traced: set[str] = set()

    def trace(self, request_id: str | None) -> None:
        """With ``--verbose``: the identifier of the request an answer belongs to, once."""
        if self.verbose and request_id is not None and request_id not in self._traced:
            self._traced.add(request_id)
            note(f"request {render.safe_line(request_id, limit=render.IDENTIFIER_MAX)}")

    def show(self, view: View, human: Callable[[], None]) -> None:
        """One result: its JSON as received, or what ``human`` prints."""
        self.trace(view.request_id)
        if self.as_json:
            render.write_json(view.raw)
        else:
            human()

    def show_all(self, items: Sequence[View], human: Callable[[], None]) -> None:
        """A listing: one JSON array of the items as received, or what ``human`` prints."""
        for item in items:
            self.trace(item.request_id)
        if self.as_json:
            render.write_json([item.raw for item in items])
        else:
            human()

    def intend(self, idempotency_key: str | None, follow_max: str | None, no_wait: bool) -> Intent:
        """Fix how this command issues its operation, and above all its key, before anything is sent."""
        if no_wait and follow_max is not None:
            raise UsageError("--no-wait and --follow-max say two different things about waiting: give one of them")
        key = idempotency_key if idempotency_key is not None else str(uuid.uuid4())
        _INVOCATION.key = key
        if self.verbose:
            note(f"idempotency key {render.safe_line(key)}")
        if no_wait:
            return Intent(key, 0.0, no_wait=True)
        bound = None if follow_max is None else units.duration(follow_max, option="--follow-max")
        return Intent(key, bound, no_wait=False)

    def call[**P, T](self, method: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
        """Make one call of the SDK. Every call a command makes goes through here.

        The SDK refuses an argument with ``ValueError`` before it sends the request, in words fit to be
        shown. Around its own call is the one place where a ``ValueError`` is known to mean that. From
        anywhere else it would be a defect, and it is left to be reported as one.
        """
        try:
            return method(*args, **kwargs)
        except ValueError as refused:
            raise ArgumentError(str(refused)) from None

    def issue[T](self, intent: Intent, call: Callable[[], T]) -> T | None:
        """Make the one call of a command that changes something.

        With ``--no-wait``, an operation that has not ended is not an error: it is printed, and ``None``
        is returned. An operation that ended without success is raised either way.
        """
        try:
            return self.call(call)
        except OperationStillRunningError as still:
            if not intent.no_wait:
                raise
            self._operation(still.operation)
            return None

    def conclude(self, intent: Intent, view: View, operation: Operation | None, human: Callable[[], None]) -> None:
        """Report what a command that changes something produced: the resource, or with ``--no-wait`` the operation."""
        if intent.no_wait and operation is not None:
            self._operation(operation)
            return
        self.show(view, human)
        if operation is not None and not self.as_json:
            note(views.operation_line(operation))

    def _operation(self, operation: Operation) -> None:
        self.show(operation, functools.partial(views.show_operation, operation))


@contextlib.contextmanager
def connect(common: Common) -> Iterator[Session]:
    """The session of one command: configuration resolved, key protected, client built and closed after."""
    timeout = None if common.timeout is None else units.duration(common.timeout, option="--timeout")
    settings = credentials.resolve(base_url=common.base_url, project=common.project, profile=common.profile)
    render.protect(settings.api_key)
    if common.verbose:
        for what, source in settings.sources.items():
            note(f"{what}: from {source}")
    with contextlib.ExitStack() as stack:
        fabric = new_fabric(settings, timeout=timeout)
        stack.callback(fabric.close)
        if common.verbose:
            stack.enter_context(_sdk_records())
        yield Session(fabric, common)


# ----------------------------------------------------------------------------------------- the guard
def say(report: Report, *, as_json: bool, verbose: bool) -> None:
    """A failure, on standard error.

    With ``--json`` and an answer of the API to show, the first line is that answer as one line of JSON.
    The words follow in every case, and they end with what to do next.
    """
    if as_json and report.document is not None:
        render.line(render.json_line(report.document), err=True)
    render.line(f"error: {render.safe_line(report.headline)}", err=True)
    for detail in report.details:
        render.line(f"  {render.safe_line(detail)}", err=True)
    render.line(f"  next: {render.safe_line(report.next_step)}", err=True)
    if verbose and report.request_id is not None:
        note(f"request {render.safe_line(report.request_id, limit=render.IDENTIFIER_MAX)}")


def _discard_stdout() -> None:
    """Point standard output at nothing, so that the interpreter's own flush at exit cannot fail a second time."""
    with contextlib.suppress(OSError, ValueError):
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, sys.stdout.fileno())
        os.close(null)


def guard[**P, R](command: Callable[P, R]) -> Callable[P, R]:
    """Run a command, and turn whatever ends it into a message and the exit status that states it.

    What the SDK raises, what this tool refuses and an interruption are reported, each with what to do
    next. Anything else is a defect, of this tool or of a library under it, and it is shown as one:
    its traceback first, with the key taken out of it. It still ends with a status this tool chose. The
    interpreter's own status for an exception nobody caught is 1, and for ``acf exec run`` that status
    says that the command ran and did not exit with status 0.
    """

    @functools.wraps(command)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        as_json = kwargs.get("as_json") is True
        verbose = kwargs.get("verbose") is True
        try:
            try:
                result = command(*args, **kwargs)
                # A reader that went away is noticed here, not when the interpreter exits.
                sys.stdout.flush()
            except (typer.Exit, BrokenPipeError):
                raise
            except (FabricError, CliError, KeyboardInterrupt) as error:
                report = describe(error, key=_INVOCATION.key)
                say(report, as_json=as_json, verbose=verbose)
                raise typer.Exit(int(report.exit_code)) from None
            except Exception as defect:
                render.line(render.safe_text("".join(traceback.format_exception(defect))).rstrip("\n"), err=True)
                report = describe(defect, key=_INVOCATION.key)
                say(report, as_json=as_json, verbose=verbose)
                raise typer.Exit(int(report.exit_code)) from None
        except BrokenPipeError:
            # `acf ... | head`: stop quietly with the conventional status, as other tools do.
            _discard_stdout()
            raise typer.Exit(int(ExitCode.READER_GONE)) from None
        finally:
            _INVOCATION.key = None
            render.unprotect()
        return result

    return wrapper
