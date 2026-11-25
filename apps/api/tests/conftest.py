"""Fixtures shared by the tests of the API package."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

from tests.support.deploy import HOST_BINARY_ENV, REQUIRE_HOST_ENV, host_binary, host_required
from tests.support.harness import Identity, Rig, build_rig

# Property tests are part of the gate, so a run must be repeatable: the examples follow from the test
# itself (no random seed), nothing is carried over from an earlier run (no example database), and no
# example fails for being slow on a busy machine (no deadline; pytest's own timeout bounds a test).
# Hypothesis keeps its files outside the repository.
os.environ.setdefault("HYPOTHESIS_STORAGE_DIRECTORY", str(Path(tempfile.gettempdir()) / "acf-api-hypothesis"))
settings.register_profile(
    "acf",
    derandomize=True,
    database=None,
    deadline=None,
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=False,
)
settings.load_profile("acf")


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    """A running core over the model host, ready for granting work."""
    built = await build_rig(tmp_path)
    try:
        yield built
    finally:
        await built.close()


@pytest.fixture
async def dev(rig: Rig) -> Identity:
    """A developer with the `developer` grant template in a project of its own."""
    return await rig.developer()


def pytest_runtest_setup(item: pytest.Item) -> None:
    """A test marked ``host`` needs the test host binary: skipped without it, failed when a host is required.

    A suite that needs a real host fails, and never skips, when a real host is required: a run that
    was asked to prove something against the host must not report success for having proven nothing.
    """
    if item.get_closest_marker("host") is None or host_binary() is not None:
        return
    reason = f"${HOST_BINARY_ENV} names no executable test host"
    if host_required():
        pytest.fail(f"{reason}, and {REQUIRE_HOST_ENV}=1 makes that a failure", pytrace=False)
    pytest.skip(reason)
