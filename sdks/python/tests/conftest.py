"""Fixtures of the whole suite.

Two of them are guards, not helpers, and apply to every test: no test may open a network connection,
and no test may wait in real time. A test that would do either fails at once and says so.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Iterator
from typing import NoReturn

import pytest

from support import Harness


def _refuse_connection(*_: object, **__: object) -> NoReturn:
    raise AssertionError("a test tried to reach the network: every test talks to a scripted transport")


def _refuse_sleep(*_: object, **__: object) -> NoReturn:
    raise AssertionError("a test tried to wait in real time: every test runs on a virtual clock")


@pytest.fixture(autouse=True)
def _no_network_no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _refuse_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse_connection)
    monkeypatch.setattr(socket, "getaddrinfo", _refuse_connection)
    monkeypatch.setattr(socket, "create_connection", _refuse_connection)
    monkeypatch.setattr(time, "sleep", _refuse_sleep)
    monkeypatch.setattr(asyncio, "sleep", _refuse_sleep)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The configuration of the machine that runs the tests is not part of any test."""
    for name in ("ACF_API_KEY", "ACF_BASE_URL", "ACF_PROJECT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(params=["sync", "async"])
def harness(request: pytest.FixtureRequest) -> Iterator[Harness]:
    """One harness per client flavor: a test that takes it runs against ``Fabric`` and against ``AsyncFabric``."""
    harness = Harness(request.param)
    yield harness
    harness.close()
    harness.finish()
