"""Sandboxes: creating them, and acting on one through a handle.

A handle is a view of a sandbox plus the means to act on it. Three rules shape it:

* **It acts on an identifier.** ``sandboxes.get("name")`` resolves the name once. From then on the
  handle acts on the identifier it found, so that a name which later comes to mean another sandbox cannot
  capture a command meant for this one. ``refresh()`` notices such a change and refuses to follow it
  unless told to.
* **It states what it saw.** Every mutation carries the generation of the view the handle holds. If the
  sandbox was restored in the meantime, the platform refuses with ``REVISION_CONFLICT`` and the caller
  refreshes and decides. ``"current"`` is sent only when the caller passes that word.
* **It is updated by answers, not by assumptions.** After a mutation that returns the sandbox, the
  handle holds the view of that answer.

``sandboxes.create()`` is the one call that is more than one operation: the platform creates and starts
in two, so this client issues both, under keys derived from one, and cleans up if the second fails.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final, Literal, Self

from agentcompute import _keys
from agentcompute._resources import Generation, Seed, expected_generation, produced, read_sandbox
from agentcompute._transport import Engine, Flow, Request, encode, identifier, segment
from agentcompute._units import (
    argument_vector,
    count,
    environment,
    flag,
    mebibytes,
    network_spec,
    seconds,
    shell_vector,
    text,
)
from agentcompute.errors import (
    FabricError,
    NameReboundError,
    OperationFailedError,
    OutcomeUnknownError,
    RefusedError,
    SandboxStartError,
    UnexpectedResponseError,
)
from agentcompute.types import Operation, SandboxView, SnapshotView

if TYPE_CHECKING:
    from agentcompute._binding import AsyncBinder, SyncBinder
    from agentcompute.execution import AsyncExecution, Execution
    from agentcompute.snapshot import AsyncSnapshot, Snapshot

__all__ = ["AsyncSandbox", "AsyncSandboxes", "Sandbox", "Sandboxes"]

#: ``"none"``, or an allowlist: ``{"mode": "allowlist", "entries": [{"name": ..., "ports": [...]}, ...]}``.
type NetworkSpec = Literal["none"] | Mapping[str, Any]
type StartFailurePolicy = Literal["destroy", "keep"]

_COLLECTION: Final = "/sandboxes"
_POLICIES: Final = ("destroy", "keep")


class _SandboxFlows(SandboxView):
    """A sandbox handle without a way to run its flows: what the two clients share."""

    __slots__ = ("_engine", "_resolved_name", "operation")

    def __init__(self, engine: Engine, seed: Seed, *, resolved_name: str | None = None) -> None:
        super().__init__(seed.raw, request_id=seed.request_id)
        self._engine = engine
        #: The operation whose answer this view came from. ``None`` when the view was read.
        self.operation = seed.operation
        # The name this handle was obtained by, if it was obtained by a name. Never used as a target.
        self._resolved_name = resolved_name

    def _adopt(self, seed: Seed) -> None:
        """Take a newer view of the same sandbox."""
        if SandboxView(seed.raw).sandbox_id != self.sandbox_id:
            raise UnexpectedResponseError(
                "the server answered with another sandbox than the one that was asked about",
                request_id=seed.request_id,
            )
        self.raw = seed.raw
        self.request_id = seed.request_id
        self.operation = seed.operation

    def _path(self) -> Flow[str]:
        return (yield from self._engine.project_path()) + f"{_COLLECTION}/{segment(self.sandbox_id)}"

    def _refresh(self, rebind: object) -> Flow[None]:
        rebinding = flag(rebind, what="rebind")
        name = self._resolved_name
        if name is None:
            self._adopt((yield from read_sandbox(self._engine, self.sandbox_id)))
            return
        # The handle came from a name, so the name is looked up again: this is where a name that now
        # belongs to another sandbox is noticed. The handle itself never acts on the name.
        seed = yield from read_sandbox(self._engine, name)
        found = SandboxView(seed.raw).sandbox_id
        if found != self.sandbox_id and not rebinding:
            raise NameReboundError(
                f"the name {name!r} now belongs to sandbox {found}, not to {self.sandbox_id} which this "
                "handle acts on. The handle was left as it was. Pass rebind=True to refresh() to move it",
                name=name,
                sandbox_id=self.sandbox_id,
                rebound_to=found,
            )
        self.raw = seed.raw
        self.request_id = seed.request_id
        self.operation = None

    def _settled(self, mutation: Flow[Operation], key: str) -> Flow[None]:
        """Run a mutation that returns this sandbox, judge its outcome and take the view of its answer."""
        operation = yield from mutation
        self._engine.settle(operation, key=key)
        self._adopt(produced(self._engine, operation, "sandbox"))

    def _lifecycle(
        self, action: str, generation: Generation | None, idempotency_key: str | None, follow_max: float | None
    ) -> Flow[None]:
        """``start`` and ``stop``: the body is the generation the request acts on."""
        body = encode({"expected_generation": expected_generation(generation, self.raw.get("generation"))})
        key = _keys.for_call(idempotency_key)
        within = self._engine.follow_bound(follow_max)
        path = (yield from self._path()) + f"/{action}"
        request = Request("POST", path, body=body, key=key)
        yield from self._settled(self._engine.operate(request, within=within), key)

    def _destroy(
        self, generation: Generation | None, idempotency_key: str | None, follow_max: float | None
    ) -> Flow[None]:
        query = (("expected_generation", str(expected_generation(generation, self.raw.get("generation")))),)
        key = _keys.for_call(idempotency_key)
        within = self._engine.follow_bound(follow_max)
        path = yield from self._path()
        request = Request("DELETE", path, query=query, key=key)
        yield from self._settled(self._engine.operate(request, within=within), key)

    def _exec(
        self,
        argv: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str] | None,
        timeout: int | str | None,
        generation: Generation | None,
        idempotency_key: str | None,
        follow_max: float | None,
    ) -> Flow[Seed]:
        body: dict[str, Any] = {
            "expected_generation": expected_generation(generation, self.raw.get("generation")),
            "argv": argv,
        }
        if cwd is not None:
            body["cwd"] = text(cwd, what="cwd")
        if env is not None:
            body["env"] = environment(env)
        if timeout is not None:
            body["timeout_seconds"] = seconds(timeout, what="timeout")
        payload = encode(body)
        key = _keys.for_call(idempotency_key)
        engine = self._engine
        within = engine.follow_bound(follow_max)
        path = (yield from self._path()) + "/executions"
        operation = yield from engine.operate(Request("POST", path, body=payload, key=key), within=within)
        engine.settle(operation, key=key)
        return produced(engine, operation, "execution")

    def _snapshot(
        self, name: str | None, generation: Generation | None, idempotency_key: str | None, follow_max: float | None
    ) -> Flow[Seed]:
        body: dict[str, Any] = {"expected_generation": expected_generation(generation, self.raw.get("generation"))}
        if name is not None:
            body["name"] = text(name, what="name")
        payload = encode(body)
        key = _keys.for_call(idempotency_key)
        engine = self._engine
        within = engine.follow_bound(follow_max)
        path = (yield from self._path()) + "/snapshots"
        operation = yield from engine.operate(Request("POST", path, body=payload, key=key), within=within)
        engine.settle(operation, key=key)
        return produced(engine, operation, "snapshot")

    def _restore(
        self,
        snapshot: SnapshotView,
        generation: Generation | None,
        idempotency_key: str | None,
        follow_max: float | None,
    ) -> Flow[None]:
        if not isinstance(snapshot, SnapshotView):
            # The restore names the snapshot's generation, which only a view of the snapshot knows.
            raise ValueError(
                "restore takes a snapshot handle: get one from sandbox.snapshot() or from fabric.snapshots.get()"
            )
        target = {
            "kind": "existing",
            "sandbox_id": self.sandbox_id,
            "expected_generation": expected_generation(generation, self.raw.get("generation")),
        }
        body = encode({"snapshot_generation": snapshot.snapshot_generation, "target": target})
        key = _keys.for_call(idempotency_key)
        engine = self._engine
        within = engine.follow_bound(follow_max)
        path = (yield from engine.project_path()) + f"/snapshots/{segment(snapshot.snapshot_id)}/restore"
        request = Request("POST", path, body=body, key=key)
        yield from self._settled(engine.operate(request, within=within), key)


class Sandbox(_SandboxFlows):
    """A handle on one sandbox. Obtained from ``fabric.sandboxes``.

    Every attribute of the view is here (``state``, ``generation``, ``resources``, ...), and ``raw`` is
    the JSON as received. The methods act on the sandbox and return when their operation has ended.
    """

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder, seed: Seed, *, resolved_name: str | None = None) -> None:
        super().__init__(binder.driver.engine, seed, resolved_name=resolved_name)
        self._binder = binder

    def start(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Start a sandbox that was created and has not been started. A stopped sandbox is not started again."""
        self._binder.driver.run("sandbox.start", self._lifecycle("start", generation, idempotency_key, follow_max))
        return self

    def exec(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | str | None = None,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Execution:
        """Run one command, given as its argument vector, and return it once it has ended.

        The command is executed directly, never through a shell. An exit status other than 0 is a
        result: look at ``status`` and ``exit_code``. ``timeout`` bounds the command on the host; it has
        nothing to do with how long this call waits.
        """
        flow = self._exec(
            argument_vector(argv),
            cwd=cwd,
            env=env,
            timeout=timeout,
            generation=generation,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.execution(self._binder.driver.run("sandbox.exec", flow))

    def exec_shell(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | str | None = None,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Execution:
        """Run a command line through the sandbox's shell: sends ``["/bin/sh", "-c", command]``."""
        flow = self._exec(
            shell_vector(command),
            cwd=cwd,
            env=env,
            timeout=timeout,
            generation=generation,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.execution(self._binder.driver.run("sandbox.exec_shell", flow))

    def snapshot(
        self,
        name: str | None = None,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Snapshot:
        """Take a snapshot of the sandbox."""
        flow = self._snapshot(name, generation, idempotency_key, follow_max)
        return self._binder.snapshot(self._binder.driver.run("sandbox.snapshot", flow))

    def restore(
        self,
        snapshot: SnapshotView,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Restore a snapshot into this sandbox, in place. The sandbox gets a new generation.

        ``snapshot`` is a snapshot handle, from ``sandbox.snapshot()`` or ``fabric.snapshots.get()``.
        """
        self._binder.driver.run("sandbox.restore", self._restore(snapshot, generation, idempotency_key, follow_max))
        return self

    def stop(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Stop the sandbox. A running execution is cancelled."""
        self._binder.driver.run("sandbox.stop", self._lifecycle("stop", generation, idempotency_key, follow_max))
        return self

    def destroy(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Destroy the sandbox. It is never resurrected."""
        self._binder.driver.run("sandbox.destroy", self._destroy(generation, idempotency_key, follow_max))
        return self

    def refresh(self, *, rebind: bool = False) -> Self:
        """Read the sandbox again and update this handle.

        A handle obtained by a name looks the name up again. If the name now belongs to another sandbox
        this raises ``NameReboundError`` and leaves the handle as it was, unless ``rebind=True``, which
        moves the handle to that sandbox.
        """
        self._binder.driver.run("sandbox.refresh", self._refresh(rebind))
        return self


class AsyncSandbox(_SandboxFlows):
    """A handle on one sandbox. Obtained from ``fabric.sandboxes``.

    Every attribute of the view is here (``state``, ``generation``, ``resources``, ...), and ``raw`` is
    the JSON as received. The methods act on the sandbox and return when their operation has ended.
    Cancelling a task that awaits one of them stops the waiting and cancels nothing on the platform.
    """

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder, seed: Seed, *, resolved_name: str | None = None) -> None:
        super().__init__(binder.driver.engine, seed, resolved_name=resolved_name)
        self._binder = binder

    async def start(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Start a sandbox that was created and has not been started. A stopped sandbox is not started again."""
        flow = self._lifecycle("start", generation, idempotency_key, follow_max)
        await self._binder.driver.run("sandbox.start", flow)
        return self

    async def exec(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | str | None = None,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> AsyncExecution:
        """Run one command, given as its argument vector, and return it once it has ended.

        The command is executed directly, never through a shell. An exit status other than 0 is a
        result: look at ``status`` and ``exit_code``. ``timeout`` bounds the command on the host; it has
        nothing to do with how long this call waits.
        """
        flow = self._exec(
            argument_vector(argv),
            cwd=cwd,
            env=env,
            timeout=timeout,
            generation=generation,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.execution(await self._binder.driver.run("sandbox.exec", flow))

    async def exec_shell(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | str | None = None,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> AsyncExecution:
        """Run a command line through the sandbox's shell: sends ``["/bin/sh", "-c", command]``."""
        flow = self._exec(
            shell_vector(command),
            cwd=cwd,
            env=env,
            timeout=timeout,
            generation=generation,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.execution(await self._binder.driver.run("sandbox.exec_shell", flow))

    async def snapshot(
        self,
        name: str | None = None,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> AsyncSnapshot:
        """Take a snapshot of the sandbox."""
        flow = self._snapshot(name, generation, idempotency_key, follow_max)
        return self._binder.snapshot(await self._binder.driver.run("sandbox.snapshot", flow))

    async def restore(
        self,
        snapshot: SnapshotView,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Restore a snapshot into this sandbox, in place. The sandbox gets a new generation.

        ``snapshot`` is a snapshot handle, from ``sandbox.snapshot()`` or ``fabric.snapshots.get()``.
        """
        flow = self._restore(snapshot, generation, idempotency_key, follow_max)
        await self._binder.driver.run("sandbox.restore", flow)
        return self

    async def stop(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Stop the sandbox. A running execution is cancelled."""
        flow = self._lifecycle("stop", generation, idempotency_key, follow_max)
        await self._binder.driver.run("sandbox.stop", flow)
        return self

    async def destroy(
        self,
        *,
        generation: Generation | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Self:
        """Destroy the sandbox. It is never resurrected."""
        await self._binder.driver.run("sandbox.destroy", self._destroy(generation, idempotency_key, follow_max))
        return self

    async def refresh(self, *, rebind: bool = False) -> Self:
        """Read the sandbox again and update this handle.

        A handle obtained by a name looks the name up again. If the name now belongs to another sandbox
        this raises ``NameReboundError`` and leaves the handle as it was, unless ``rebind=True``, which
        moves the handle to that sandbox.
        """
        await self._binder.driver.run("sandbox.refresh", self._refresh(rebind))
        return self


# ------------------------------------------------------------------------------------------- the collection
def _create(
    engine: Engine,
    *,
    image: str,
    cpu: int,
    memory: int | str,
    disk: int | str,
    network: NetworkSpec | None,
    name: str | None,
    lifetime: int | str | None,
    start: bool,
    on_start_failure: StartFailurePolicy,
    idempotency_key: str | None,
    follow_max: float | None,
) -> Flow[Seed]:
    """Create a sandbox and, unless told otherwise, start it. Everything is checked before any request."""
    body: dict[str, Any] = {
        "image": text(image, what="image"),
        "resources": {
            "vcpus": count(cpu, what="cpu"),
            "memory_mib": mebibytes(memory, what="memory"),
            "disk_mib": mebibytes(disk, what="disk"),
        },
    }
    # A member the caller did not set is not sent: the platform's default applies, and it is the
    # platform that knows it. `start` is never sent at all, because this client starts the sandbox itself.
    if network is not None:
        body["network"] = network_spec(network)
    if name is not None:
        body["name"] = text(name, what="name")
    if lifetime is not None:
        body["lifetime_seconds"] = seconds(lifetime, what="lifetime")
    payload = encode(body)
    starting = flag(start, what="start")
    if on_start_failure not in _POLICIES:
        raise ValueError(f'on_start_failure must be "destroy" or "keep", not {on_start_failure!r}')
    # The key must leave room for the suffixes of the start and of the destroy, whether or not this
    # call starts the sandbox: the same key then means the same sequence in every call that resumes it.
    key = _keys.for_call(idempotency_key, limit=_keys.CREATE_KEY_MAX_LENGTH)
    within = engine.follow_bound(follow_max)

    collection = (yield from engine.project_path()) + _COLLECTION
    operation = yield from engine.operate(Request("POST", collection, body=payload, key=key), within=within)
    engine.settle(operation, key=key)
    created = produced(engine, operation, "sandbox")
    if not starting:
        return created
    view = SandboxView(created.raw)
    path = f"{collection}/{segment(view.sandbox_id)}"
    keep = on_start_failure == "keep"
    return (yield from _start_created(engine, path, view, key=key, within=within, keep=keep))


def _start_created(engine: Engine, path: str, view: SandboxView, *, key: str, within: float, keep: bool) -> Flow[Seed]:
    """The second operation of ``create``: start what was created, and apply the caller's policy if that fails."""
    sandbox_id, generation = view.sandbox_id, view.generation
    start = _keys.start_key(key)
    request = Request("POST", f"{path}/start", body=encode({"expected_generation": generation}), key=start)
    try:
        operation = yield from engine.operate(request, within=within)
        engine.settle(operation, key=start)
    except (RefusedError, OperationFailedError, OutcomeUnknownError) as start_error:
        # The start was refused, or ended without success. The sandbox exists and is not running.
        failure = yield from _after_failed_start(
            engine, path, view, key=key, within=within, keep=keep, start_error=start_error
        )
        raise failure from start_error
    except FabricError as error:
        # Neither refused nor ended: still running, unresolved, or unreachable. It may yet succeed, so
        # nothing is assumed and nothing is destroyed. The same call with the same key picks the
        # sequence up where it stopped.
        error.add_note(
            f"Sandbox {sandbox_id} was created, and whether its start succeeded is not established. "
            f"Call sandboxes.create() again with idempotency_key={key!r} and the same arguments to resume."
        )
        raise
    return produced(engine, operation, "sandbox")


def _after_failed_start(
    engine: Engine,
    path: str,
    view: SandboxView,
    *,
    key: str,
    within: float,
    keep: bool,
    start_error: RefusedError | OperationFailedError | OutcomeUnknownError,
) -> Flow[SandboxStartError]:
    """Apply ``on_start_failure`` and build the error that names both outcomes."""
    sandbox_id = view.sandbox_id
    what = f"sandbox {sandbox_id} was created, and its start did not succeed ({start_error})"
    if keep:
        return SandboxStartError(
            f"{what}. It was kept, as asked: start it again or destroy it, or it exists until its lifetime ends",
            sandbox_id=sandbox_id,
            start_error=start_error,
            cleanup="kept",
        )
    destroy = _keys.destroy_key(key)
    # The destroy names the generation this client saw: the start did not succeed, so the sandbox is
    # still the one that was created.
    query = (("expected_generation", str(view.generation)),)
    try:
        operation = yield from engine.operate(Request("DELETE", path, query=query, key=destroy), within=within)
        engine.settle(operation, key=destroy)
    except FabricError as destroy_error:
        return SandboxStartError(
            f"{what}. Destroying it did not succeed either ({destroy_error}): "
            "it may exist until it is destroyed or its lifetime ends",
            sandbox_id=sandbox_id,
            start_error=start_error,
            cleanup="destroy_failed",
            destroy_error=destroy_error,
        )
    return SandboxStartError(
        f"{what}. It was destroyed", sandbox_id=sandbox_id, start_error=start_error, cleanup="destroyed"
    )


def _get(engine: Engine, sandbox: str) -> Flow[tuple[Seed, str | None]]:
    """Read a sandbox by identifier or name, and say whether it was a name that found it."""
    wanted = identifier(sandbox, what="sandbox")
    seed = yield from read_sandbox(engine, wanted)
    return seed, None if SandboxView(seed.raw).sandbox_id == wanted else wanted


def _unread(sandbox_id: str) -> Seed:
    return Seed({"sandbox_id": identifier(sandbox_id, what="sandbox_id")}, None)


class Sandboxes:
    """``fabric.sandboxes``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder) -> None:
        self._binder = binder

    def create(
        self,
        image: str,
        *,
        cpu: int,
        memory: int | str,
        disk: int | str,
        network: NetworkSpec | None = None,
        name: str | None = None,
        lifetime: int | str | None = None,
        start: bool = True,
        on_start_failure: StartFailurePolicy = "destroy",
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Sandbox:
        """Create a sandbox and start it. Returns when it has started.

        ``memory`` and ``disk`` are integers in MiB or strings such as ``"4GiB"``; ``lifetime`` is an
        integer in seconds or a string such as ``"2h"``. ``network`` is ``"none"``, which is also what
        a sandbox gets when nothing is passed, or an allowlist.

        With ``start=False`` only the create is issued. If the start is refused or fails,
        ``on_start_failure`` decides: ``"destroy"`` destroys the sandbox, ``"keep"`` leaves it; either
        way ``SandboxStartError`` says what happened to it. Pass ``idempotency_key`` (at most 247
        characters) to make the whole sequence resumable from another process.
        """
        driver = self._binder.driver
        flow = _create(
            driver.engine,
            image=image,
            cpu=cpu,
            memory=memory,
            disk=disk,
            network=network,
            name=name,
            lifetime=lifetime,
            start=start,
            on_start_failure=on_start_failure,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.sandbox(driver.run("sandboxes.create", flow))

    def get(self, sandbox: str) -> Sandbox:
        """Read one sandbox by its identifier or its name. A name is resolved here, once."""
        driver = self._binder.driver
        seed, resolved_name = driver.run("sandboxes.get", _get(driver.engine, sandbox))
        return self._binder.sandbox(seed, resolved_name=resolved_name)

    def list(self) -> Iterator[Sandbox]:
        """Every sandbox of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in driver.run("sandboxes.list", driver.engine.collect(_COLLECTION)):
            yield self._binder.sandbox(Seed(raw, request_id))

    def handle(self, sandbox_id: str) -> Sandbox:
        """A handle on a sandbox that was not read: no request is made.

        Its view holds the identifier and nothing else until ``refresh()``. It has seen no generation,
        so every mutation through it must say ``generation=`` itself.
        """
        return self._binder.sandbox(_unread(sandbox_id))


class AsyncSandboxes:
    """``fabric.sandboxes``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder) -> None:
        self._binder = binder

    async def create(
        self,
        image: str,
        *,
        cpu: int,
        memory: int | str,
        disk: int | str,
        network: NetworkSpec | None = None,
        name: str | None = None,
        lifetime: int | str | None = None,
        start: bool = True,
        on_start_failure: StartFailurePolicy = "destroy",
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> AsyncSandbox:
        """Create a sandbox and start it. Returns when it has started.

        ``memory`` and ``disk`` are integers in MiB or strings such as ``"4GiB"``; ``lifetime`` is an
        integer in seconds or a string such as ``"2h"``. ``network`` is ``"none"``, which is also what
        a sandbox gets when nothing is passed, or an allowlist.

        With ``start=False`` only the create is issued. If the start is refused or fails,
        ``on_start_failure`` decides: ``"destroy"`` destroys the sandbox, ``"keep"`` leaves it; either
        way ``SandboxStartError`` says what happened to it. Pass ``idempotency_key`` (at most 247
        characters) to make the whole sequence resumable from another process.
        """
        driver = self._binder.driver
        flow = _create(
            driver.engine,
            image=image,
            cpu=cpu,
            memory=memory,
            disk=disk,
            network=network,
            name=name,
            lifetime=lifetime,
            start=start,
            on_start_failure=on_start_failure,
            idempotency_key=idempotency_key,
            follow_max=follow_max,
        )
        return self._binder.sandbox(await driver.run("sandboxes.create", flow))

    async def get(self, sandbox: str) -> AsyncSandbox:
        """Read one sandbox by its identifier or its name. A name is resolved here, once."""
        driver = self._binder.driver
        seed, resolved_name = await driver.run("sandboxes.get", _get(driver.engine, sandbox))
        return self._binder.sandbox(seed, resolved_name=resolved_name)

    async def list(self) -> AsyncIterator[AsyncSandbox]:
        """Every sandbox of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in await driver.run("sandboxes.list", driver.engine.collect(_COLLECTION)):
            yield self._binder.sandbox(Seed(raw, request_id))

    def handle(self, sandbox_id: str) -> AsyncSandbox:
        """A handle on a sandbox that was not read: no request is made.

        Its view holds the identifier and nothing else until ``refresh()``. It has seen no generation,
        so every mutation through it must say ``generation=`` itself.
        """
        return self._binder.sandbox(_unread(sandbox_id))
