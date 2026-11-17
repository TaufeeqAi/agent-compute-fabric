"""Shared fixtures."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acf_cli.client import ClientConfig, HostClient
from support import Behavior, FakeClock, ScriptedHost

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "schemas"


def _schema(name: str) -> dict[str, Any]:
    path = SCHEMA_DIR / name
    if not path.is_file():  # fail loudly: a silently skipped contract test is no test at all
        pytest.fail(f"{path} is missing; generate it with `make schemas` (acf-host schema --out schemas)")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="session")
def request_schema() -> dict[str, Any]:
    return _schema("request.schema.json")


@pytest.fixture(scope="session")
def response_schema() -> dict[str, Any]:
    return _schema("response.schema.json")


@pytest.fixture(scope="session")
def host_config_schema() -> dict[str, Any]:
    return _schema("host-config.schema.json")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def socket_path(tmp_path: Path) -> Path:
    return tmp_path / "acf.sock"


@pytest.fixture
def host_factory(socket_path: Path) -> Iterator[Callable[..., ScriptedHost]]:
    """``host_factory(*behaviours, default=None)`` starts a scripted host and returns it."""
    started: list[ScriptedHost] = []

    def make(*script: Behavior, default: Behavior | None = None) -> ScriptedHost:
        host = ScriptedHost(socket_path, script, default=default)
        host.start()
        started.append(host)
        return host

    yield make
    for host in started:
        host.stop()
    for host in started:
        host.assert_clean()


@pytest.fixture
def config(socket_path: Path) -> ClientConfig:
    return ClientConfig(socket_path=socket_path, connect_timeout_s=2.0, io_timeout_s=2.0)


@pytest.fixture
def client(config: ClientConfig, clock: FakeClock) -> HostClient:
    return HostClient(config, sleep=clock.sleep, monotonic=clock.monotonic)


def require_e2e() -> bool:
    """CI sets ACF_REQUIRE_E2E=1 so a missing host binary is a failure, not a quiet skip."""
    return os.environ.get("ACF_REQUIRE_E2E") == "1"
