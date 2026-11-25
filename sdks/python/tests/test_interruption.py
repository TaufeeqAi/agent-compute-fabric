"""Giving up cancels nothing.

A timeout, a cancelled task, Ctrl-C: each stops the waiting of this client and nothing more. The
operation goes on, on the platform, and is found again by its identifier or by the key of the call.
Cancelling an execution is an explicit call, and no code path of this package makes it for the caller.

The same tests show a second rule: only failures of the HTTP exchange are ever retried. An exception of
any other kind passes through, once.
"""

from __future__ import annotations

import asyncio
from typing import Any, NoReturn

import httpx2
import pytest

from agentcompute import AsyncFabric
from support import BASE_URL, CANARY_KEY, EXE, OP3, PROJECT, SBX, Harness, Script, done, ex, execution, operation, reply

_TARGET = {"sandbox_id": SBX, "generation": 1, "execution_id": EXE}
_ACCEPTED = reply(202, operation("execution.create", "IN_PROGRESS", operation_id=OP3, target=_TARGET), retry_after="1")
_RAN = reply(200, done("execution.create", "execution", execution(), operation_id=OP3, target=_TARGET))


def _interrupt(harness: Harness) -> type[BaseException]:
    """What an interruption looks like to each client: Ctrl-C when it blocks, a cancellation when it awaits."""
    return asyncio.CancelledError if harness.is_async else KeyboardInterrupt


def test_an_interruption_while_waiting_ends_the_call_and_sends_nothing_more(harness: Harness) -> None:
    script = harness.script(ex("POST", f"/sandboxes/{SBX}/executions", _ACCEPTED))
    fabric = harness.client(script)
    interruption = _interrupt(harness)

    def interrupted(_: float) -> NoReturn:
        raise interruption

    async def cancelled(_: float) -> NoReturn:
        raise interruption

    if isinstance(fabric, AsyncFabric):
        fabric._driver.sleep = cancelled
    else:
        fabric._driver.sleep = interrupted
    handle = fabric.sandboxes.handle(SBX)
    with pytest.raises(interruption):
        harness.run(handle.exec(["sleep", "600"], generation=1, idempotency_key="key-1"))
    # One request was made: the one that started the command. No cancel followed the interruption.
    assert [(seen.method, seen.path.rsplit("/", 1)[1]) for seen in script.seen] == [("POST", "executions")]


def test_an_interruption_during_a_request_is_not_retried(harness: Harness) -> None:
    interruption = _interrupt(harness)
    calls = {"count": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls["count"] += 1
        raise interruption

    fabric = harness.client(handler)
    with pytest.raises(interruption):
        harness.run(fabric.sandboxes.handle(SBX).exec(["true"], generation=1))
    assert calls["count"] == 1


@pytest.mark.parametrize("error", [RuntimeError("a bug in a transport"), OSError("disk full"), LookupError("codec")])
def test_an_exception_that_is_not_a_failure_of_the_exchange_passes_through_once(
    harness: Harness, error: Exception
) -> None:
    """No layer retries "on every exception"."""
    calls = {"count": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls["count"] += 1
        raise error

    fabric = harness.client(handler, max_retries=5)
    with pytest.raises(type(error)) as raised:
        harness.run(fabric.sandboxes.get(SBX))
    assert raised.value is error
    assert calls["count"] == 1
    assert harness.clock.slept == []


def test_after_an_interruption_the_same_key_finds_the_operation_again(harness: Harness) -> None:
    script = harness.script(
        ex("POST", f"/sandboxes/{SBX}/executions", _ACCEPTED, headers={"idempotency-key": "key-1"}),
        ex("POST", f"/sandboxes/{SBX}/executions", _RAN, headers={"idempotency-key": "key-1"}),
    )
    fabric = harness.client(script)
    interruption = _interrupt(harness)

    def interrupted(_: float) -> NoReturn:
        raise interruption

    async def cancelled(_: float) -> NoReturn:
        raise interruption

    if isinstance(fabric, AsyncFabric):
        fabric._driver.sleep = cancelled
    else:
        fabric._driver.sleep = interrupted
    handle = fabric.sandboxes.handle(SBX)
    with pytest.raises(interruption):
        harness.run(handle.exec(["true"], generation=1, idempotency_key="key-1"))

    harness.virtualize(fabric)  # the caller comes back later, patient again
    assert harness.run(handle.exec(["true"], generation=1, idempotency_key="key-1")).execution_id == EXE
    assert script.seen[0].body == script.seen[1].body


# ------------------------------------------------------------------ real cancellation of a real task
def _async_client(script: Script) -> tuple[AsyncFabric, httpx2.AsyncClient]:
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(script.handler))
    return AsyncFabric(CANARY_KEY, base_url=BASE_URL, project=PROJECT, http_client=http), http


def test_cancelling_the_task_that_awaits_a_call_sends_no_cancel() -> None:
    script = Script([ex("POST", f"/sandboxes/{SBX}/executions", _ACCEPTED)])

    async def scenario() -> None:
        fabric, http = _async_client(script)
        waiting = asyncio.Event()
        never = asyncio.Event()

        async def wait_for_ever(_: float) -> None:
            waiting.set()
            await never.wait()

        fabric._driver.sleep = wait_for_ever
        call = asyncio.ensure_future(fabric.sandboxes.handle(SBX).exec(["sleep", "600"], generation=1))
        await waiting.wait()
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        await http.aclose()

    with asyncio.Runner() as runner:
        runner.run(scenario())
    script.finish()
    assert [seen.method for seen in script.seen] == ["POST"]


def test_a_timeout_around_a_call_sends_no_cancel() -> None:
    script = Script([ex("POST", f"/sandboxes/{SBX}/executions", _ACCEPTED)])

    async def scenario() -> None:
        fabric, http = _async_client(script)
        never = asyncio.Event()

        async def wait_for_ever(_: float) -> None:
            await never.wait()

        fabric._driver.sleep = wait_for_ever
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0):
                await fabric.sandboxes.handle(SBX).exec(["sleep", "600"], generation=1)
        await http.aclose()

    with asyncio.Runner() as runner:
        runner.run(scenario())
    script.finish()
    assert [seen.method for seen in script.seen] == ["POST"]


def test_a_call_that_was_cancelled_leaves_its_client_usable() -> None:
    script = Script(
        [ex("POST", f"/sandboxes/{SBX}/executions", _ACCEPTED), ex("POST", f"/sandboxes/{SBX}/executions", _RAN)]
    )
    results: list[Any] = []

    async def scenario() -> None:
        fabric, http = _async_client(script)
        waiting = asyncio.Event()

        async def wait_for_ever(_: float) -> None:
            waiting.set()
            await asyncio.Event().wait()

        fabric._driver.sleep = wait_for_ever
        handle = fabric.sandboxes.handle(SBX)
        call = asyncio.ensure_future(handle.exec(["true"], generation=1, idempotency_key="key-1"))
        await waiting.wait()
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        results.append(await handle.exec(["true"], generation=1, idempotency_key="key-1"))
        await http.aclose()

    with asyncio.Runner() as runner:
        runner.run(scenario())
    script.finish()
    assert results[0].execution_id == EXE
