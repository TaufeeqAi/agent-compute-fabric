"""The command line, end to end through Typer, against a scripted host on a real socket.

Three families of assertion, in this order of importance:

1. **What was sent.** Destructive operations carry ``(sandbox_id, expected_generation)`` read a
   moment earlier, never a name; a refused confirmation sends nothing; a bad argument is rejected
   before any connection is made.
2. **What the exit code says.** Scripts branch on it: workload failure, refusal, definite failure,
   *unknown outcome*, unreachable host.
3. **What goes where.** Guest output is relayed byte-exact on a pipe; the structured report goes to
   stderr (or, with ``--json``, one document on stdout).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

import factories as f
from acf_cli import __version__
from acf_cli.client import ClientConfig, HostClient
from acf_cli.main import app
from acf_cli.models import Body, ResponseEnvelope
from support import FakeClock, Lost, Reply, ScriptedHost, error_body, respond

HostFactory = Callable[..., ScriptedHost]
SBX = f.SANDBOX_ID


# ----------------------------------------------------------------------------- harness
@pytest.fixture(autouse=True)
def fast_clients(monkeypatch: pytest.MonkeyPatch, clock: FakeClock) -> None:
    """Every client the CLI builds polls on the fake clock, so UNKNOWN grace periods cost no real time."""

    def make(config: ClientConfig) -> HostClient:
        return HostClient(config, sleep=clock.sleep, monotonic=clock.monotonic)

    monkeypatch.setattr("acf_cli.common.HostClient", make)


def invoke(socket_path: Path, *args: str, env: dict[str, str] | None = None) -> Result:
    return CliRunner().invoke(app, ["--socket", str(socket_path), *args], env=env, catch_exceptions=False)


def ok(kind: str, data: Any, status: str = "SUCCEEDED") -> Reply:
    return Reply(lambda req: respond(req, status, result=f.body(kind, data)))


def refused(failure_class: str, message: str = "refused", status: str = "REJECTED") -> Reply:
    return Reply(lambda req: respond(req, status, error=error_body(failure_class, message)))


def unknown_answer() -> Reply:
    return Reply(
        lambda req: respond(
            req,
            "UNKNOWN",
            error=error_body("TIMEOUT_UNKNOWN", "the deadline passed", side_effect="possible", outcome_unknown=True),
        )
    )


def observing(status: str, **kw: Any) -> Reply:
    return Reply(lambda req: respond(req, status, operation_id=req["body"]["params"]["operation_id"], **kw))


def json_out(result: Result) -> Any:
    return json.loads(result.stdout)


def lifecycle(run_data: dict[str, Any] | None = None, *, destroy: bool = True) -> list[Reply]:
    """The four answers a successful ``run`` needs, in order."""
    script = [
        ok("sandbox", f.sandbox_view(generation=1, state="REQUESTED")),
        ok("sandbox", f.sandbox_view(generation=1, state="READY")),
        ok("run", run_data if run_data is not None else f.run_result()),
    ]
    if destroy:
        script.append(ok("sandbox", f.sandbox_view(generation=1, state="DESTROYED")))
    return script


# ----------------------------------------------------------------------------- the root command
def test_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"acf-local {__version__}"


def test_no_arguments_prints_usage_and_is_a_usage_error() -> None:
    result = CliRunner().invoke(app, [])
    assert "Usage:" in result.output
    assert result.exit_code == 2


def test_help_lists_every_command() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("run", "exec", "sandbox", "snapshot", "evidence", "operation", "host"):
        assert command in result.stdout


def test_the_socket_can_come_from_the_environment(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("host_info", f.host_info()))
    result = CliRunner().invoke(app, ["host", "info", "--json"], env={"ACF_SOCKET": str(socket_path)})
    assert result.exit_code == 0
    assert json_out(result)["protocol"] == "acf.host/1"


def test_an_unreachable_host_exits_6_with_a_hint(socket_path: Path) -> None:
    result = invoke(socket_path, "host", "info")
    assert result.exit_code == 6
    assert "no host agent socket" in result.stderr
    assert "hint:" in result.stderr
    assert result.stdout == ""


# ----------------------------------------------------------------------------- host
def test_host_info_human_and_json(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("host_info", f.host_info()), ok("host_info", f.host_info(live_sandboxes=3)))
    human = invoke(socket_path, "host", "info")
    assert human.exit_code == 0
    assert "acf.host/1" in human.stdout
    assert "firecracker 1.17.0" in human.stdout
    as_json = invoke(socket_path, "host", "info", "--json")
    assert json_out(as_json)["live_sandboxes"] == 3


def test_host_metrics_and_reload(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        ok("metrics", {"counters": {"ops": 4}, "gauges": {"live_sandboxes": 1}}),
        ok("host_info", f.host_info(policy={"name": "strict", "version": "2", "digest": "cd" * 32})),
    )
    metrics = invoke(socket_path, "host", "metrics")
    assert "counters.ops" in metrics.stdout
    reload = invoke(socket_path, "host", "reload-policy")
    assert reload.exit_code == 0
    assert "strict@2" in reload.stderr
    assert host.methods == ["metrics", "policy_reload"]
    assert "operation_id" not in host.requests[1], "a reload creates no operation"


def test_a_reload_by_a_non_administrator_is_a_refusal(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(refused("AUTHORIZATION", "policy reload is restricted to trusted administrators"))
    result = invoke(socket_path, "host", "reload-policy")
    assert result.exit_code == 3
    assert "restricted to trusted administrators" in result.stderr


# ----------------------------------------------------------------------------- sandbox
def test_listing_sandboxes(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        ok("sandboxes", []),
        ok("sandboxes", [f.sandbox_view(name="alpha"), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="beta")]),
        ok("sandboxes", [f.sandbox_view(name="alpha")]),
    )
    assert "no sandboxes" in invoke(socket_path, "sandbox", "list").stdout
    table = invoke(socket_path, "sandbox", "list").stdout
    assert "alpha" in table
    assert "beta" in table
    listed = json_out(invoke(socket_path, "sandbox", "list", "--json"))
    assert [s["name"] for s in listed] == ["alpha"]


def test_create_converts_units_and_pins_network_none(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(ok("sandbox", f.sandbox_view(state="REQUESTED")))
    result = invoke(
        socket_path,
        "sandbox",
        "create",
        "--image",
        "python",
        "--cpu",
        "2",
        "--memory",
        "4Gi",
        "--disk",
        "2Gi",
        "--name",
        "w",
    )
    assert result.exit_code == 0
    request = host.requests[0]
    assert request["body"]["params"] == {
        "name": "w",
        "image": "python",
        "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 2048, "network": "none"},
    }
    assert request["operation_id"].startswith("op-")


def test_create_with_start_boots_what_it_created_using_the_generation_it_got_back(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        ok("sandbox", f.sandbox_view(generation=4, state="REQUESTED")), ok("sandbox", f.sandbox_view(generation=4))
    )
    result = invoke(socket_path, "sandbox", "create", "--image", "python", "--start")
    assert result.exit_code == 0
    assert host.requests[1]["body"] == {
        "method": "sandbox_start",
        "params": {"sandbox_id": SBX, "expected_generation": 4},
    }


def test_only_the_none_network_exists_in_phase_1(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory()
    result = invoke(socket_path, "sandbox", "create", "--image", "python", "--network", "host")
    assert result.exit_code == 2
    assert host.requests == []


def test_destroy_resolves_the_name_with_a_read_then_destroys_by_id_and_generation(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        ok("sandbox", f.sandbox_view(name="work", generation=7)),
        ok("sandbox", f.sandbox_view(name="work", generation=7, state="DESTROYED")),
    )
    result = invoke(socket_path, "sandbox", "destroy", "work", "--yes")
    assert result.exit_code == 0
    assert host.methods == ["sandbox_inspect", "sandbox_destroy"]
    assert host.requests[0]["body"]["params"] == {"sandbox": "work"}
    assert host.requests[1]["body"]["params"] == {"sandbox_id": SBX, "expected_generation": 7}
    assert "operation_id" in host.requests[1]
    assert "operation_id" not in host.requests[0]


def test_destroy_without_confirmation_in_a_non_interactive_shell_sends_nothing_destructive(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(ok("sandbox", f.sandbox_view(name="work", generation=7)))
    result = invoke(socket_path, "sandbox", "destroy", "work")
    assert result.exit_code == 2
    assert "refusing to destroy" in result.stderr
    assert "--yes" in result.stderr
    assert host.methods == ["sandbox_inspect"]


def test_a_stale_generation_is_a_conflict_not_an_accident(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        ok("sandbox", f.sandbox_view(generation=7)),
        refused("STATE_CONFLICT", "sandbox is at generation 8, not 7 (stale reference)", status="CONFLICT"),
    )
    result = invoke(socket_path, "sandbox", "destroy", SBX, "--yes")
    assert result.exit_code == 3
    assert "stale reference" in result.stderr


def test_unknown_sandbox_name_is_a_refusal_with_a_hint(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(refused("NOT_FOUND", "no sandbox `ghost`"))
    result = invoke(socket_path, "sandbox", "inspect", "ghost")
    assert result.exit_code == 3
    assert "no sandbox `ghost`" in result.stderr
    assert "list" in result.stderr


def test_start_and_stop_use_the_resolved_generation(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        ok("sandbox", f.sandbox_view(generation=2, state="REQUESTED")),
        ok("sandbox", f.sandbox_view(generation=2)),
        ok("sandbox", f.sandbox_view(generation=2)),
        ok("sandbox", f.sandbox_view(generation=2, state="STOPPED")),
    )
    assert invoke(socket_path, "sandbox", "start", "x").exit_code == 0
    assert invoke(socket_path, "sandbox", "stop", "x").exit_code == 0
    assert host.requests[1]["body"]["params"]["expected_generation"] == 2
    assert host.requests[3]["body"]["method"] == "sandbox_stop"


# ----------------------------------------------------------------------------- snapshot
def snap(**over: Any) -> dict[str, Any]:
    return f.snapshot_view(**over)


def test_snapshot_create_defaults_to_the_only_running_sandbox(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        ok("sandboxes", [f.sandbox_view(generation=3)]),
        ok("snapshot", snap()),
    )
    result = invoke(socket_path, "snapshot", "create", "baseline")
    assert result.exit_code == 0
    assert host.requests[1]["body"] == {
        "method": "snapshot_create",
        "params": {"sandbox_id": SBX, "expected_generation": 3, "name": "baseline"},
    }


def test_snapshot_create_refuses_to_guess_between_several_sandboxes(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        ok("sandboxes", [f.sandbox_view(name="a"), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="b")])
    )
    result = invoke(socket_path, "snapshot", "create")
    assert result.exit_code == 3
    assert "2 sandboxes are up" in result.stderr
    assert "--sandbox" in result.stderr
    assert host.methods == ["sandbox_list"]


def test_snapshot_create_with_no_running_sandbox_says_so(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("sandboxes", [f.sandbox_view(state="STOPPED")]))
    result = invoke(socket_path, "snapshot", "create")
    assert result.exit_code == 3
    assert "no running sandbox" in result.stderr


def test_restore_rolls_the_source_sandbox_back_by_id_and_generation(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        ok("snapshots", [snap()]),
        ok("sandbox", f.sandbox_view(generation=2)),
        ok("sandbox", f.sandbox_view(generation=3)),
    )
    result = invoke(socket_path, "snapshot", "restore", "baseline")
    assert result.exit_code == 0
    assert host.requests[1]["body"] == {"method": "sandbox_inspect", "params": {"sandbox": SBX}}
    assert host.requests[2]["body"]["params"] == {
        "snapshot": {"snapshot_id": f.SNAPSHOT_ID, "snapshot_generation": 1},
        "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 2},
    }


def test_restore_into_a_new_sandbox(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(ok("snapshots", [snap()]), ok("sandbox", f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID)))
    result = invoke(socket_path, "snapshot", "restore", "baseline", "--new", "--name", "clone")
    assert result.exit_code == 0
    assert host.requests[1]["body"]["params"]["target"] == {"kind": "new", "name": "clone"}


def test_restore_whose_source_sandbox_is_gone_suggests_new(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("snapshots", [snap()]), refused("NOT_FOUND", "no sandbox"))
    result = invoke(socket_path, "snapshot", "restore", "baseline")
    assert result.exit_code == 3
    assert "no longer exists" in result.stderr
    assert "--new" in result.stderr


@pytest.mark.parametrize(
    "args",
    [["--new", "--sandbox", "x"], ["--name", "n"]],
    ids=["new-and-sandbox", "name-without-new"],
)
def test_restore_rejects_contradictory_options_before_sending_anything(
    host_factory: HostFactory, socket_path: Path, args: list[str]
) -> None:
    host = host_factory()
    result = invoke(socket_path, "snapshot", "restore", "baseline", *args)
    assert result.exit_code == 2
    assert host.requests == []


def test_snapshot_names_must_resolve_to_exactly_one(host_factory: HostFactory, socket_path: Path) -> None:
    twin = f.snapshot_view(snapshot={"snapshot_id": "snp-" + "dd" * 16, "snapshot_generation": 1}, name="baseline")
    host_factory(ok("snapshots", [snap(), twin]), ok("snapshots", [snap()]))
    ambiguous = invoke(socket_path, "snapshot", "inspect", "baseline")
    assert ambiguous.exit_code == 3
    assert "ambiguous" in ambiguous.stderr
    missing = invoke(socket_path, "snapshot", "inspect", "nope")
    assert missing.exit_code == 3
    assert "existing snapshots: baseline" in missing.stderr


def test_snapshot_delete_needs_confirmation_and_then_sends_the_exact_reference(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(ok("snapshots", [snap()]), ok("snapshots", [snap()]), ok("snapshot", snap(state="DELETED")))
    refused_run = invoke(socket_path, "snapshot", "delete", "baseline")
    assert refused_run.exit_code == 2
    assert host.methods == ["snapshot_list"]
    confirmed = invoke(socket_path, "snapshot", "delete", "baseline", "--yes")
    assert confirmed.exit_code == 0
    assert host.requests[2]["body"] == {
        "method": "snapshot_delete",
        "params": {"snapshot_id": f.SNAPSHOT_ID, "snapshot_generation": 1},
    }


def test_snapshot_list(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("snapshots", [snap()]))
    result = invoke(socket_path, "snapshot", "list")
    assert "baseline" in result.stdout
    assert "8.0 MiB" in result.stdout


# ----------------------------------------------------------------------------- run: argument validation
@pytest.mark.parametrize(
    ("args", "needle"),
    [
        (["--image", "python"], "nothing to run"),
        (["--image", "python", "--command", "x", "--", "y"], "either --command or arguments"),
        (["--image", "python", "--shell", "--", "a", "b"], "--shell applies to --command"),
        (["--image", "python", "--command", 'echo "unterminated'], "cannot parse --command"),
        (["--image", "python", "--command", "x", "--memory", "banana"], "invalid memory size"),
        (["--image", "python", "--command", "x", "--timeout", "0"], "greater than zero"),
        (["--image", "python", "--command", "x", "--max-stdout", "lots"], "invalid size"),
        (["--image", "python", "--command", "x", "--env", "NOEQUALS"], "invalid --env"),
        (["--image", "python", "--command", "x", "--env", "A=1", "--env", "A=2"], "more than once"),
        (["--image", "python", "--command", "x", "--network", "host"], "host"),
        (["--image", "python", "--command", "x", "--cpu", "0"], "0"),
    ],
)
def test_bad_run_arguments_are_rejected_before_any_connection(
    host_factory: HostFactory, socket_path: Path, args: list[str], needle: str
) -> None:
    host = host_factory()  # empty script: a single connection would fail the test
    result = invoke(socket_path, "run", *args)
    assert result.exit_code == 2
    assert needle in result.output
    assert host.requests == []


# ----------------------------------------------------------------------------- run: the milestone
def test_run_relays_stdout_exactly_and_reports_on_stderr(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(*lifecycle(f.run_result(stdout=f.capture(b"hello\n"), stderr=f.capture(b"warn\n"))))
    result = invoke(
        socket_path,
        "run",
        "--image",
        "python",
        "--cpu",
        "2",
        "--memory",
        "4096",
        "--network",
        "none",
        "--command",
        "python experiment.py",
    )
    assert result.exit_code == 0
    assert result.stdout == "hello\n", "stdout carries the guest's stdout and nothing else"
    assert "warn\n" in result.stderr
    for needle in (f.RUN_ID, "SUCCEEDED (exit 0)", "742 ms", "destroyed", "stdout", "evidence"):
        assert needle in result.stderr, needle
    assert host.methods == ["sandbox_create", "sandbox_start", "exec", "sandbox_destroy"]
    assert host.requests[2]["body"]["params"]["command"]["argv"] == ["python", "experiment.py"]
    ops = [r["operation_id"] for r in host.requests]
    assert len(set(ops)) == 4
    assert all(o.startswith("op-") for o in ops)


def test_run_relays_non_utf8_guest_bytes_untouched_on_a_pipe(host_factory: HostFactory, socket_path: Path) -> None:
    payload = b"\x1b[31mred\x1b[0m\xff\xfe\x00\r\nend"
    host_factory(*lifecycle(f.run_result(stdout=f.capture(payload))))
    result = invoke(socket_path, "run", "--image", "python", "--command", "x")
    assert result.stdout_bytes == payload


def test_run_json_is_one_document_and_the_guest_output_stays_inside_it(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host_factory(*lifecycle(f.run_result(stdout=f.capture(b"hello\n"))))
    result = invoke(socket_path, "run", "--image", "python", "--command", "x", "--json")
    assert result.exit_code == 0
    doc = json_out(result)
    assert set(doc) >= {
        "run",
        "sandbox",
        "cleanup",
        "operations",
        "interrupted",
        "unresolved",
        "cleanup_failed",
        "error",
    }
    assert doc["run"]["run_id"] == f.RUN_ID
    assert base64.b64decode(doc["run"]["stdout"]["data_b64"]) == b"hello\n"
    assert doc["cleanup"].startswith("destroyed")
    assert list(doc["operations"]) == ["create", "start", "exec", "destroy"]
    assert doc["error"] is None


def test_run_with_a_shell_wraps_the_command_explicitly(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(*lifecycle())
    result = invoke(socket_path, "run", "--image", "python", "--shell", "--command", "a | b && c")
    assert result.exit_code == 0
    assert host.requests[2]["body"]["params"]["command"]["argv"] == ["/bin/sh", "-c", "a | b && c"]


def test_run_passes_limits_env_and_cwd_through_untouched_and_unclamped(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(*lifecycle())
    result = invoke(
        socket_path,
        "run",
        "--image",
        "python",
        "--timeout",
        "2m",
        "--max-pids",
        "64",
        "--max-stdout",
        "64KiB",
        "--max-stderr",
        "1MiB",
        "--env",
        "LANG=C",
        "--cwd",
        "/work",
        "--",
        "python",
        "-c",
        "print(1)",
    )
    assert result.exit_code == 0
    assert host.requests[2]["body"]["params"]["command"] == {
        "argv": ["python", "-c", "print(1)"],
        "env": {"LANG": "C"},
        "cwd": "/work",
        "limits": {"timeout_ms": 120_000, "max_pids": 64, "max_stdout_bytes": 65_536, "max_stderr_bytes": 1_048_576},
    }


def test_run_keep_does_not_destroy(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(*lifecycle(destroy=False))
    result = invoke(socket_path, "run", "--image", "python", "--command", "x", "--keep", "--name", "dev")
    assert result.exit_code == 0
    assert host.methods == ["sandbox_create", "sandbox_start", "exec"]
    assert host.requests[0]["body"]["params"]["name"] == "dev"
    assert "kept" in result.stderr


# ----------------------------------------------------------------------------- run: exit codes
@pytest.mark.parametrize(
    ("run_data", "plain", "propagated"),
    [
        (f.run_result(outcome="FAILED", exit_code=3), 1, 3),
        (f.run_result(outcome="FAILED", exit_code=None, signal=9), 1, 137),
        (f.run_result(outcome="TIMED_OUT", exit_code=None, signal=None), 1, 1),
        (f.run_result(outcome="CANCELLED", exit_code=None, signal=15), 1, 143),
        (f.run_result(outcome="SUCCEEDED", exit_code=0), 0, 0),
    ],
    ids=["exit-3", "signal-9", "timed-out", "cancelled", "success"],
)
def test_run_exit_codes_for_the_workloads_own_outcome(
    host_factory: HostFactory, socket_path: Path, run_data: dict[str, Any], plain: int, propagated: int
) -> None:
    host_factory(*lifecycle(run_data), *lifecycle(run_data))
    assert invoke(socket_path, "run", "--image", "python", "--command", "x").exit_code == plain
    result = invoke(socket_path, "run", "--image", "python", "--command", "x", "--propagate-exit-code")
    assert result.exit_code == propagated


def test_a_failed_workload_still_has_its_output_relayed_and_its_sandbox_destroyed(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        *lifecycle(
            f.run_result(
                outcome="FAILED", exit_code=2, stdout=f.capture(b"partial\n"), stderr=f.capture(b"Traceback\n")
            )
        )
    )
    result = invoke(socket_path, "run", "--image", "python", "--command", "x")
    assert result.exit_code == 1
    assert result.stdout == "partial\n"
    assert "Traceback" in result.stderr
    assert host.methods[-1] == "sandbox_destroy"


def test_a_policy_refusal_is_exit_3_with_the_reason_and_a_hint(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(refused("ADMISSION_REJECTED", "memory 99999 MiB exceeds the policy ceiling of 2048 MiB"))
    result = invoke(socket_path, "run", "--image", "python", "--command", "x", "--memory", "99999")
    assert result.exit_code == 3
    assert "exceeds the policy ceiling" in result.stderr
    assert "hint:" in result.stderr
    assert host.methods == ["sandbox_create"]


def test_a_definite_failure_is_exit_4(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        ok("sandbox", f.sandbox_view(state="REQUESTED")),
        Reply(lambda req: respond(req, "FAILED", error=error_body("BACKEND_CRASH", "the VMM exited during boot"))),
        ok("sandbox", f.sandbox_view(state="DESTROYED")),
    )
    result = invoke(socket_path, "run", "--image", "python", "--command", "x")
    assert result.exit_code == 4
    assert "the VMM exited during boot" in result.stderr
    assert "destroyed" in result.stderr


def test_an_unknown_exec_is_exit_5_and_leaves_the_sandbox_in_place(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(
        ok("sandbox", f.sandbox_view(state="REQUESTED")),
        ok("sandbox", f.sandbox_view()),
        unknown_answer(),
        default=observing("UNKNOWN"),
    )
    result = invoke(socket_path, "run", "--image", "python", "--command", "x")
    assert result.exit_code == 5
    assert "left in place" in result.stderr
    assert SBX in result.stderr
    assert "do NOT re-run" in result.stderr
    assert "sandbox_destroy" not in host.methods
    assert host.methods.count("exec") == 1, "an unknown outcome is observed, never re-run"


def test_a_successful_run_whose_cleanup_fails_is_a_failure_with_the_command_to_finish_it(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host_factory(*lifecycle(destroy=False), refused("STATE_CONFLICT", "sandbox is busy", status="CONFLICT"))
    result = invoke(socket_path, "run", "--image", "python", "--command", "x")
    assert result.exit_code == 4
    assert f"acf-local sandbox destroy {SBX}" in result.stderr
    assert "SUCCEEDED" in result.stderr, "the run's own evidence is still delivered"


def test_a_cleanup_failure_does_not_mask_a_workload_failure(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        *lifecycle(f.run_result(outcome="FAILED", exit_code=2), destroy=False),
        refused("STATE_CONFLICT", "sandbox is busy", status="CONFLICT"),
    )
    result = invoke(socket_path, "run", "--image", "python", "--command", "x", "--json")
    assert result.exit_code == 1
    assert json_out(result)["cleanup_failed"] is True


# ----------------------------------------------------------------------------- exec
def test_exec_resolves_the_name_then_runs_against_that_generation(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        ok("sandbox", f.sandbox_view(name="dev", generation=5, state="COMPLETED")),
        ok("run", f.run_result(stdout=f.capture(b"hi\n"))),
    )
    result = invoke(socket_path, "exec", "dev", "--timeout", "5s", "--", "echo", "hi")
    assert result.exit_code == 0
    assert result.stdout == "hi\n"
    assert host.requests[1]["body"]["params"] == {
        "sandbox_id": SBX,
        "expected_generation": 5,
        "command": {"argv": ["echo", "hi"], "env": {}, "limits": {"timeout_ms": 5000}},
    }


def test_exec_exit_codes_and_json(host_factory: HostFactory, socket_path: Path) -> None:
    failing = f.run_result(outcome="FAILED", exit_code=7)
    host_factory(
        ok("sandbox", f.sandbox_view()),
        ok("run", failing),
        ok("sandbox", f.sandbox_view()),
        ok("run", failing),
        ok("sandbox", f.sandbox_view()),
        ok("run", f.run_result()),
    )
    assert invoke(socket_path, "exec", "dev", "--", "false").exit_code == 1
    assert invoke(socket_path, "exec", "dev", "--propagate-exit-code", "--", "false").exit_code == 7
    as_json = invoke(socket_path, "exec", "dev", "--json", "--", "true")
    assert json_out(as_json)["run"]["outcome"] == "SUCCEEDED"


def test_exec_against_a_busy_sandbox_is_a_refusal(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        ok("sandbox", f.sandbox_view(state="RUNNING")),
        refused(
            "STATE_CONFLICT", "sandbox is RUNNING; exec requires an idle (READY/COMPLETED) sandbox", status="CONFLICT"
        ),
    )
    result = invoke(socket_path, "exec", "dev", "--", "echo")
    assert result.exit_code == 3
    assert "requires an idle" in result.stderr


# ----------------------------------------------------------------------------- Ctrl-C
def press_ctrl_c_on(monkeypatch: pytest.MonkeyPatch, clock: FakeClock, method: str) -> None:
    """The operator presses Ctrl-C at the moment the CLI is about to send ``method`` (nothing reaches the host)."""

    class CtrlC(HostClient):
        def roundtrip(
            self, body: Body, *, operation_id: str | None = None, io_timeout_s: float | None = None
        ) -> ResponseEnvelope:
            if body.method == method:
                raise KeyboardInterrupt
            return super().roundtrip(body, operation_id=operation_id, io_timeout_s=io_timeout_s)

    monkeypatch.setattr(
        "acf_cli.common.HostClient",
        lambda config: CtrlC(config, sleep=clock.sleep, monotonic=clock.monotonic),
    )


def test_ctrl_c_during_exec_cancels_it_then_reports_how_it_ended(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    cancelled = f.run_result(
        outcome="CANCELLED", exit_code=None, signal=15, stdout=f.capture(b"partial\n"), stderr=f.capture(b"")
    )
    host = host_factory(
        ok("sandbox", f.sandbox_view(name="dev", state="COMPLETED")),
        observing("IN_PROGRESS"),
        observing("SUCCEEDED", result=f.body("run", cancelled)),
    )
    press_ctrl_c_on(monkeypatch, clock, "exec")
    result = invoke(socket_path, "exec", "dev", "--", "sleep", "99")
    assert result.exit_code == 130
    assert result.stdout == "partial\n", "what the workload printed before it was stopped is still delivered"
    assert "CANCELLED" in result.stderr
    assert host.methods[1:] == ["operation_cancel", "operation_get"]


def test_ctrl_c_during_exec_when_the_host_cannot_say_how_it_ended_never_suggests_a_rerun(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    host_factory(ok("sandbox", f.sandbox_view(name="dev", state="COMPLETED")), Lost())
    press_ctrl_c_on(monkeypatch, clock, "exec")
    result = invoke(socket_path, "exec", "dev", "--", "sleep", "99")
    assert result.exit_code == 130
    assert "did not confirm how the run ended" in result.stderr
    assert "do NOT re-run it: acf-local operation get op-" in result.stderr


def test_ctrl_c_during_exec_json_says_so_in_the_document(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    cancelled = f.run_result(outcome="CANCELLED", exit_code=None, signal=15)
    host_factory(
        ok("sandbox", f.sandbox_view(name="dev", state="COMPLETED")),
        observing("IN_PROGRESS"),
        observing("SUCCEEDED", result=f.body("run", cancelled)),
    )
    press_ctrl_c_on(monkeypatch, clock, "exec")
    result = invoke(socket_path, "exec", "dev", "--json", "--", "sleep", "99")
    assert result.exit_code == 130
    doc = json_out(result)
    assert (doc["interrupted"], doc["resolved"]) == (True, True)
    assert doc["run"]["outcome"] == "CANCELLED"
    assert doc["operation_id"].startswith("op-")


def test_ctrl_c_during_run_cancels_the_exec_then_still_destroys_the_sandbox(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    cancelled = f.run_result(outcome="CANCELLED", exit_code=None, signal=15)
    host = host_factory(
        ok("sandbox", f.sandbox_view(generation=1, state="REQUESTED")),
        ok("sandbox", f.sandbox_view(generation=1, state="READY")),
        observing("IN_PROGRESS"),
        observing("SUCCEEDED", result=f.body("run", cancelled)),
        ok("sandbox", f.sandbox_view(generation=1, state="DESTROYED")),
    )
    press_ctrl_c_on(monkeypatch, clock, "exec")
    result = invoke(socket_path, "run", "--image", "python", "--", "sleep", "99")
    assert result.exit_code == 130
    assert "cleanup: destroyed" in result.stderr
    assert host.methods == ["sandbox_create", "sandbox_start", "operation_cancel", "operation_get", "sandbox_destroy"]


def test_ctrl_c_during_a_mutation_names_the_operation_to_observe_not_to_repeat(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    host_factory(ok("sandbox", f.sandbox_view(name="dev", state="PROVISIONING")))
    press_ctrl_c_on(monkeypatch, clock, "sandbox_start")
    result = invoke(socket_path, "sandbox", "start", "dev")
    assert result.exit_code == 130
    assert "interrupted" in result.stderr
    assert "may still complete" in result.stderr
    assert "acf-local operation get op-" in result.stderr


def test_ctrl_c_during_a_read_has_nothing_in_flight_to_mention(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    host_factory()
    press_ctrl_c_on(monkeypatch, clock, "sandbox_list")
    result = invoke(socket_path, "sandbox", "list")
    assert result.exit_code == 130
    assert "interrupted" in result.stderr
    assert "operation" not in result.stderr


# ----------------------------------------------------------------------------- evidence
def test_evidence_get_shows_the_record_and_can_relay_the_output(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        ok("run", f.run_result(stdout=f.capture(b"result\n"))),
        ok("run", f.run_result(stdout=f.capture(b"result\n"))),
    )
    plain = invoke(socket_path, "evidence", "get", f.RUN_ID)
    assert plain.exit_code == 0
    assert plain.stdout == ""
    assert f.RUN_ID in plain.stderr
    with_output = invoke(socket_path, "evidence", "get", f.RUN_ID, "--output")
    assert with_output.stdout == "result\n"
    assert host.requests[0]["body"] == {"method": "run_inspect", "params": {"run_id": f.RUN_ID}}


def test_evidence_get_exit_codes(host_factory: HostFactory, socket_path: Path) -> None:
    failed = f.run_result(outcome="FAILED", exit_code=2)
    host_factory(ok("run", failed), ok("run", failed))
    assert invoke(socket_path, "evidence", "get", f.RUN_ID).exit_code == 0, "retrieval succeeded"
    assert invoke(socket_path, "evidence", "get", f.RUN_ID, "--propagate-exit-code").exit_code == 2


def test_a_run_that_has_not_finished_has_no_evidence_yet_and_is_never_reported_as_success(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host_factory(
        ok("operation", f.operation_view()),
        ok("operation", f.operation_view()),
    )
    human = invoke(socket_path, "evidence", "get", f.RUN_ID)
    assert human.exit_code == 5
    assert "has not finished" in human.stderr
    as_json = invoke(socket_path, "evidence", "get", f.RUN_ID, "--json")
    assert as_json.exit_code == 5
    assert json_out(as_json)["finished"] is False


def test_evidence_json(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(ok("run", f.run_result()))
    doc = json_out(invoke(socket_path, "evidence", "get", f.RUN_ID, "--json"))
    assert doc["finished"] is True
    assert doc["run"]["run_id"] == f.RUN_ID


def test_evidence_rejects_a_malformed_run_id_locally(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory()
    result = invoke(socket_path, "evidence", "get", "run-123")
    assert result.exit_code == 2
    assert "is not a run id" in result.stderr
    assert host.requests == []


# ----------------------------------------------------------------------------- operation
def test_operation_get_exit_codes_follow_the_operations_status(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(
        observing("SUCCEEDED", result=f.body("sandbox", f.sandbox_view())),
        observing("UNKNOWN", error=error_body("TIMEOUT_UNKNOWN", "lost", side_effect="possible", outcome_unknown=True)),
        observing("FAILED", error=error_body("BACKEND_CRASH", "vmm died")),
        observing("REJECTED", error=error_body("NOT_FOUND", "operation does not exist")),
        observing("IN_PROGRESS"),
    )
    codes = {
        status: invoke(socket_path, "operation", "get", f.OP_ID).exit_code
        for status in ("SUCCEEDED", "UNKNOWN", "FAILED", "NOT_FOUND", "IN_PROGRESS")
    }
    assert codes == {"SUCCEEDED": 0, "UNKNOWN": 5, "FAILED": 4, "NOT_FOUND": 3, "IN_PROGRESS": 5}


def test_operation_get_explains_unknown_and_json_mirrors_the_wire(host_factory: HostFactory, socket_path: Path) -> None:
    unknown_error = error_body("TIMEOUT_UNKNOWN", "lost", side_effect="possible", outcome_unknown=True)
    host_factory(observing("UNKNOWN", error=unknown_error), observing("UNKNOWN", error=unknown_error))
    human = invoke(socket_path, "operation", "get", f.OP_ID)
    assert "Do NOT re-run it" in human.stdout
    assert "outcome unknown" in human.stdout
    doc = json_out(invoke(socket_path, "operation", "get", f.OP_ID, "--json"))
    assert doc["status"] == "UNKNOWN"
    assert doc["error"]["class"] == "TIMEOUT_UNKNOWN"
    assert doc["error"]["outcome_unknown"] is True


def test_operation_get_wait_polls_until_final(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(
        observing("IN_PROGRESS"), observing("IN_PROGRESS"), observing("SUCCEEDED", result=f.body("run", f.run_result()))
    )
    result = invoke(socket_path, "operation", "get", f.OP_ID, "--wait")
    assert result.exit_code == 0
    assert host.methods == ["operation_get"] * 3
    assert f"run {f.RUN_ID}" in result.stdout


def test_operation_ids_are_validated_locally(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory()
    result = invoke(socket_path, "operation", "get", "nope")
    assert result.exit_code == 2
    assert "is not an operation id" in result.stderr
    assert host.requests == []


def test_cancel_waits_for_the_run_to_end_and_exits_0(host_factory: HostFactory, socket_path: Path) -> None:
    cancelled_run = f.run_result(outcome="CANCELLED", exit_code=None, signal=15)
    host = host_factory(observing("IN_PROGRESS"), observing("SUCCEEDED", result=f.body("run", cancelled_run)))
    result = invoke(socket_path, "operation", "cancel", f.OP_ID)
    assert result.exit_code == 0
    assert "CANCELLED" in result.stdout
    assert host.methods == ["operation_cancel", "operation_get"]


def test_cancel_of_something_that_cannot_be_cancelled_is_a_refusal(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host_factory(
        refused("STATE_CONFLICT", "SandboxStart cannot be cancelled in Phase 1; only exec runs can", status="CONFLICT")
    )
    result = invoke(socket_path, "operation", "cancel", f.OP_ID)
    assert result.exit_code == 3
    assert "only exec runs can" in result.stdout + result.stderr


def test_cancel_of_an_already_finished_operation_just_reports_it(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(observing("SUCCEEDED", result=f.body("run", f.run_result())))
    result = invoke(socket_path, "operation", "cancel", f.OP_ID)
    assert result.exit_code == 0
    assert host.methods == ["operation_cancel"]


def test_cancel_that_never_takes_effect_is_unknown_not_success(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(observing("IN_PROGRESS"), default=observing("IN_PROGRESS"))
    result = invoke(socket_path, "operation", "cancel", f.OP_ID, "--wait-timeout", "3s")
    assert result.exit_code == 5
