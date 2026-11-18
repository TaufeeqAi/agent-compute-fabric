"""The reference client as a program: its exit codes and its two output streams.

A script that drives the client depends on three things only: the exit code, what is on stdout, and what is on
stderr. Each is checked here against the client's documented behaviour, ``control_plane`` only (evidence level
L2/L3). The exit codes that need a real guest or a real crash are in the suites of those subjects: ``1`` (the
command did not exit with status 0) and ``130`` (interrupted) with the execution and process suites, ``5`` (the
operation ended ``UNKNOWN``) with the recovery suite.
"""

from __future__ import annotations

import json
import socket
import struct
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_PROTOCOL,
    EXIT_REFUSED,
    EXIT_TRANSPORT,
    EXIT_USAGE,
    AcfLocal,
    Target,
    frame,
)
from acf_integration import HostEnv

pytestmark = [pytest.mark.integration, pytest.mark.control_plane, pytest.mark.usefixtures("clean_host")]


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A private directory with a SHORT path: the path of a socket is limited to about a hundred bytes, and the
    temporary directory of a test runner can be deeper than that."""
    with tempfile.TemporaryDirectory(prefix="acf-it-", dir="/tmp") as made:
        yield Path(made)


def test_success_is_exit_0_with_the_commands_output_on_stdout_and_the_record_on_stderr(acf: AcfLocal) -> None:
    box = acf.wire.ready(acf.name("streams"))
    structured = acf.execute(box.sandbox_id, ["echo", "hello"])
    assert structured.returncode == EXIT_OK, structured.completed.describe()
    assert structured.completed.stderr == "", "with --json nothing but the document is printed"
    expected = structured.run.stdout.inline()

    plain = acf.call("sandbox", "exec", box.sandbox_id, "--", "echo", "hello")
    assert plain.returncode == EXIT_OK, plain.describe()
    assert plain.stdout_bytes == expected, "stdout carries the command's own stdout and nothing else"
    assert structured.run.run_id not in plain.stdout
    assert "EXITED" in plain.stderr, "the record of the execution goes to stderr, where it cannot corrupt a pipe"

    raw = acf.call("sandbox", "exec", box.sandbox_id, "--raw", "--", "echo", "hello")
    assert (raw.returncode, raw.stdout_bytes) == (EXIT_OK, expected)


def test_json_output_is_exactly_one_document_whatever_the_outcome(acf: AcfLocal) -> None:
    box = acf.wire.ready(acf.name("json"))
    outcomes = {
        "a read": acf.json("sandbox", "inspect", box.sandbox_id),
        "an operation": acf.json("sandbox", "stop", box.sandbox_id),
        "a refusal": acf.json("sandbox", "start", box.sandbox_id),
        "a usage error": acf.json("sandbox", "destroy", box.sandbox_id),  # no --yes
        "a listing": acf.json("sandbox", "list"),
    }
    codes = {what: done.returncode for what, done in outcomes.items()}
    assert codes == {
        "a read": EXIT_OK,
        "an operation": EXIT_OK,
        "a refusal": EXIT_REFUSED,
        "a usage error": EXIT_USAGE,
        "a listing": EXIT_OK,
    }
    for what, done in outcomes.items():
        document = json.loads(done.stdout)  # exactly one document: anything after it would fail here
        assert isinstance(document, dict), what
        assert "request_id" not in document, "the answer is printed in wire form, without the request id"
    assert outcomes["a refusal"].answer().refused().failure_class == "STATE_CONFLICT"
    error = outcomes["a usage error"].client_error()
    assert (error["kind"], error["exit_code"], error["operation_id"]) == ("InvalidArgument", EXIT_USAGE, None)


def test_a_refusal_is_exit_3_with_the_class_and_the_retry_advice_and_nothing_on_stdout(acf: AcfLocal) -> None:
    wire = acf.wire
    with wire.nothing_recorded("a refused command"):
        plain = acf.call("sandbox", "inspect", "sbx-" + "0" * 32)
        structured = acf.json("sandbox", "inspect", "sbx-" + "0" * 32)
    assert (plain.returncode, structured.returncode) == (EXIT_REFUSED, EXIT_REFUSED), "the code is the same either way"
    assert plain.stdout == "", "a refusal prints nothing a pipe would take for output"
    assert "NOT_FOUND" in plain.stderr
    assert "NEVER" in plain.stderr, "the host's retry advice is part of a refusal"
    refusal = structured.refusal()
    assert (refusal.failure_class, refusal.retry) == ("NOT_FOUND", "NEVER")


def test_a_usage_error_is_exit_2_and_sends_nothing(acf: AcfLocal, short_dir: Path) -> None:
    nowhere = acf.as_peer(Target(socket=short_dir / "no-host-here.sock"))
    mistakes = [
        ("frobnicate",),
        ("sandbox", "create", "--image"),
        ("sandbox", "create", "--image", acf.image, "--memory", "lots"),
        ("sandbox", "create", "--image", acf.image, "--network", "wide-open"),
        ("sandbox", "exec", "some-sandbox"),
        ("sandbox", "exec", "some-sandbox", "--command", "true", "--", "true"),
        ("snapshot", "restore", "some-snapshot"),
        ("host", "set-mode", "containment"),
    ]
    for args in mistakes:
        done = nowhere.call(*args)
        assert done.returncode == EXIT_USAGE, (
            f"{args}: a usage error must be found before anything is sent (exit 6 would mean the client tried to "
            f"connect):\n{done.describe()}"
        )
        assert done.stdout == ""
        assert done.stderr.strip(), "a usage error says what is wrong"

    wire = acf.wire
    box = wire.ready(acf.name("unconfirmed"))
    with wire.nothing_recorded("a destructive command without confirmation"):
        unconfirmed = acf.call("sandbox", "destroy", box.sandbox_id)
    assert unconfirmed.returncode == EXIT_USAGE
    assert "--yes" in unconfirmed.stderr
    assert wire.refresh(box).state == "READY"


def test_an_unreachable_host_is_exit_6(acf: AcfLocal, short_dir: Path) -> None:
    nowhere = acf.as_peer(Target(socket=short_dir / "no-host-here.sock"))
    for args in (("host", "info"), ("sandbox", "list"), ("sandbox", "create", "--image", acf.image)):
        done = nowhere.json(*args)
        assert done.returncode == EXIT_TRANSPORT, done.describe()
        error = done.client_error()
        assert (error["kind"], error["exit_code"]) == ("HostUnreachable", EXIT_TRANSPORT)
    plain = nowhere.call("host", "info")
    assert (plain.returncode, plain.stdout) == (EXIT_TRANSPORT, "")
    assert str(short_dir / "no-host-here.sock") in plain.stderr, "the message names the endpoint that was tried"


def test_a_peer_that_does_not_answer_in_the_protocol_is_exit_7(acf: AcfLocal, short_dir: Path) -> None:
    """Exit code 7: "the peer did not answer in ``acf.host/2``". The peer here is a listener of this test that
    reads one frame and answers with one that is not a response."""
    path = short_dir / "impostor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(4)
    answers = [
        frame(b"this is not a response"),
        frame(json.dumps({"protocol": "acf.host/9", "answer": "RESULT"}).encode()),
    ]

    def serve() -> None:
        for answer in answers:
            connection, _ = listener.accept()
            with connection:
                header = connection.recv(4)
                if len(header) == 4:
                    connection.recv(struct.unpack(">I", header)[0])
                connection.sendall(answer)

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        impostor = acf.as_peer(Target(socket=path))
        for _ in answers:
            done = impostor.json("host", "info")
            assert done.returncode == EXIT_PROTOCOL, done.describe()
            assert done.client_error()["exit_code"] == EXIT_PROTOCOL
    finally:
        server.join(timeout=30)
        listener.close()


def test_an_operation_that_ends_failed_is_exit_4(acf: AcfLocal, host_env: HostEnv) -> None:
    host_env.test_host()  # the failure is made by changing a file of the test host
    wire = acf.wire
    box = wire.ready(acf.name("failing"), memory_mib=128, disk_mib=256)
    # Two snapshots, each with an artifact that no longer matches its manifest: a restore of either is accepted
    # and then fails. One snapshot would not do for two attempts: the first failure makes it INVALID.
    damaged = []
    for name in ("damaged", "damaged-too"):
        snapshot = wire.snapshot(box, acf.name(name))
        artifact = host_env.snapshot_dir(snapshot) / "mem"
        artifact.write_bytes(artifact.read_bytes() + b"\x00")
        damaged.append(snapshot)

    structured = acf.json("snapshot", "restore", damaged[0].snapshot_id, "--new")
    assert structured.returncode == EXIT_FAILED, structured.describe()
    operation = structured.operation()
    assert (operation.state, operation.failure_class) == ("FAILED", "INTEGRITY_FAILURE")
    plain = acf.call("snapshot", "restore", damaged[1].snapshot_id, "--new")
    assert plain.returncode == EXIT_FAILED
    assert plain.stdout == ""
    assert "FAILED" in plain.stderr
    assert operation.operation_id not in plain.stderr, "the second attempt is a new operation with its own identity"
    assert [s.sandbox_id for s in wire.sandboxes()] == [box.sandbox_id]

    # A snapshot that a restore found damaged is INVALID from then on: a further restore of it is refused
    # (exit 3, nothing recorded), not attempted again.
    again = acf.json("snapshot", "restore", damaged[0].snapshot_id, "--new")
    assert again.refusal().failure_class == "STATE_CONFLICT", again.describe()


def test_the_client_says_which_version_it_is(acf: AcfLocal) -> None:
    done = acf.call("--version")
    assert done.returncode == EXIT_OK
    name, _, version = done.stdout.strip().partition(" ")
    assert name == "acf-local"
    assert version, "a version follows the name"
    assert done.stderr == ""
