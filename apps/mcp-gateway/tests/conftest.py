"""Fixtures: the adapter over a scripted core, served in process."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx2
import pytest
from hypothesis import settings

from acf_mcp.gateway import Gateway, create_app
from tests.support import BASE_URL, FakeCore, edge_config, serving

# The property test is part of the gate, so a run must be repeatable: its examples follow from the test
# itself (no random seed), nothing is carried over from an earlier run (no example database), and no
# example fails for being slow on a busy machine (no deadline; pytest's own timeout bounds a test).
# Hypothesis keeps its files outside the repository.
os.environ.setdefault("HYPOTHESIS_STORAGE_DIRECTORY", str(Path(tempfile.gettempdir()) / "acf-mcp-gateway-hypothesis"))
settings.register_profile("acf", derandomize=True, database=None, deadline=None, print_blob=False)
settings.load_profile("acf")


@pytest.fixture
def core() -> FakeCore:
    return FakeCore()


@pytest.fixture
async def app(core: FakeCore) -> AsyncIterator[Gateway]:
    """The adapter with a default edge configuration, its lifespan running."""
    gateway = create_app(core, edge_config())
    async with serving(gateway):
        yield gateway


@pytest.fixture
async def client(app: Gateway) -> AsyncIterator[httpx2.AsyncClient]:
    """An HTTP client whose requests go straight into the application."""
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE_URL) as http:
        yield http


@pytest.fixture
def short_window(monkeypatch: pytest.MonkeyPatch) -> float:
    """Shorten the time the SDK waits before it answers with an event stream, and between keep-alives.

    The SDK holds the choice between a JSON object and an event stream open for this long. Production
    keeps its value; a test of a long call cannot wait for it.
    """
    window = 0.05
    monkeypatch.setattr("mcp.server._streamable_http_modern._SSE_PING_INTERVAL", window)
    return window
