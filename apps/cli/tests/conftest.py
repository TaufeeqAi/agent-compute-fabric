"""Fixtures of the whole suite.

Two of them are guards and apply to every test: no test may open a network connection, and the
configuration of the machine that runs the tests is not part of any test.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest

from support import Cli


def _refuse_connection(*_: object, **__: object) -> NoReturn:
    raise AssertionError("a test tried to reach the network: every test talks to a scripted transport")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _refuse_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse_connection)
    monkeypatch.setattr(socket, "getaddrinfo", _refuse_connection)
    monkeypatch.setattr(socket, "create_connection", _refuse_connection)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No variable of this tool, and no home directory but an empty one, reaches a test from outside."""
    for name in (
        "ACF_API_KEY",
        "ACF_BASE_URL",
        "ACF_PROJECT",
        "ACF_PROFILE",
        "ACF_MCP_URL",
        "ACF_CA_FILE",
        "NO_COLOR",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Cli]:
    """The command line on a scripted platform. Every exchange a test scripts has to have happened."""
    runner = Cli(monkeypatch, tmp_path)
    yield runner
    runner.finish()
