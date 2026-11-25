"""Isolation in time: every sandbox has an expiry, and nothing of it executes after that, core or no core.

* ``control_plane`` (evidence level L2/L3): the expiry is set at creation from the request or from the profile's
  default, and at its expiry the host itself issues the destroy and gives the lease back.
* T-HOST-01 needs a production host (L4): the bound must hold while the core is not running, which is exactly when
  nothing in the core can be what enforces it.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from acf_driver import AcfLocal, Sandbox, resources
from acf_integration import HostEnv, HostUnit, await_sandbox, require_root, vmm_of
from acf_proc import pids_with_argument, process_alive

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]


def _expiry(sandbox: Sandbox) -> datetime:
    return datetime.fromisoformat(sandbox.expires_at.replace("Z", "+00:00")).astimezone(UTC)


@pytest.mark.control_plane
def test_the_expiry_is_set_at_creation_from_the_request_or_from_the_profiles_default(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """LT-1: every sandbox has an expiry, set at ``sandbox.create`` from the request or the profile's default."""
    slack = timedelta(seconds=30)
    asked = datetime.now(UTC)
    default = acf.ok("sandbox", "create", "--image", acf.image).succeeded().sandbox_result()
    explicit = acf.ok("sandbox", "create", "--image", acf.image, "--lifetime", "10m").succeeded().sandbox_result()
    by_default = timedelta(seconds=host_env.profile.integer("defaults.lifetime_secs"))
    assert abs(_expiry(default) - asked - by_default) < slack, "with no lifetime asked, the profile's default applies"
    assert abs(_expiry(explicit) - asked - timedelta(minutes=10)) < slack

    wire = acf.wire
    with wire.nothing_recorded("a lifetime that is not a lifetime"):
        zero = wire.call("sandbox.create", {"image": acf.image, "resources": resources(), "lifetime_secs": 0}).refused()
    assert zero.failure_class == "INVALID_REQUEST"
    started = wire.start(default)
    assert started.expires_at == default.expires_at, "starting a sandbox must not move its expiry"


@pytest.mark.control_plane
def test_at_its_expiry_the_host_itself_destroys_a_sandbox_and_releases_its_lease(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """LT-3 and §16.2 part B: when a sandbox's expiry has passed, the host issues ``sandbox.destroy`` as an
    operation of its own. The host observes every generation at least every ``recovery.sweep_interval_ms``."""
    wire = acf.wire
    sweep = host_env.config.integer("recovery.sweep_interval_ms") / 1000
    lifetime = 3
    # The long-lived one first: a boot on a real VMM takes longer than the short one's whole lifetime.
    kept = wire.ready(acf.name("outlives"))
    box = acf.ok("sandbox", "create", "--image", acf.image, "--lifetime", f"{lifetime}s").succeeded().sandbox_result()
    assert wire.info().live_sandboxes == 2

    gone = await_sandbox(
        acf, box, lambda seen: seen.state == "DESTROYED", within=lifetime + sweep + 15, what="destroying at expiry"
    )
    assert datetime.now(UTC) >= _expiry(box), "the sandbox was destroyed BEFORE its expiry"
    assert gone.state == "DESTROYED"
    destroys = [
        op for op in wire.operations() if op.target == box.sandbox_id and op.operation_type == "sandbox.destroy"
    ]
    assert [op.issuer for op in destroys] == ["HOST"], "the destroy at expiry is an operation the host issued"
    assert wire.info().live_sandboxes == 1, "a lease must not outlive its sandbox's expiry"
    assert wire.refresh(kept).state == "READY", "a sandbox whose expiry has not passed was touched"


def test_t_host_01_with_the_core_killed_a_runtime_ends_at_its_expiry_within_the_tolerance(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    """T-HOST-01: "with the core killed, a sandbox's runtime ends at its expiry, within the tolerance".

    On the real host, as root: a sandbox with a lifetime of one minute is started, and the core is then sent
    SIGKILL and kept down, so nothing in the core can end the runtime. Pass: a few seconds before the expiry the
    VMM process is still running (the bound is an expiry, not "when the core dies"); by the expiry plus
    ``lifetime.expiry_tolerance_ms`` it is gone, and no process of the generation is left. When the core comes
    back, the sandbox ends ``DESTROYED`` and its lease is released.
    """
    require_root(host_env, "ending the core and seeing the VMM of another user")
    tolerance = timedelta(milliseconds=host_env.config.integer("lifetime.expiry_tolerance_ms"))
    box = acf.boot("mortal", lifetime="60s")
    identity = vmm_of(box)
    expiry = _expiry(box)
    assert expiry - datetime.now(UTC) > timedelta(seconds=20), "the sandbox took too long to start for this test"

    old = host_unit.kill_and_keep_down()
    try:
        while datetime.now(UTC) < expiry - timedelta(seconds=5):
            assert process_alive(*identity), "the runtime ended long before its expiry: the core's death ended it"
            time.sleep(0.5)
        deadline = expiry + tolerance
        while process_alive(*identity):
            late = datetime.now(UTC) - deadline
            assert late <= timedelta(seconds=1), (
                f"the runtime is still executing {late.total_seconds():.1f}s after its expiry plus the tolerance"
            )
            time.sleep(0.1)
        ended = datetime.now(UTC)
        assert ended >= expiry - timedelta(seconds=5)
        assert pids_with_argument(box.jail_id) == [], "a process of the expired generation is left"
    finally:
        host_unit.start_if_stopped()
        host_unit.wait_ready(not_pid=old)

    sweep = host_env.config.integer("recovery.sweep_interval_ms") / 1000
    final = await_sandbox(
        acf, box, lambda seen: seen.state == "DESTROYED", within=sweep + 60, what="destroying the expired sandbox"
    )
    assert final.state == "DESTROYED"
    assert acf.wire.info().live_sandboxes == 0
