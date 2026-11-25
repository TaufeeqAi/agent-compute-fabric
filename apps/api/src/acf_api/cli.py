"""``acf-api``: the processes of the interface plane, and the operator's tool.

    acf-api core --config <core.yaml>      the one core process of a deployment
    acf-api edge --config <edge.yaml>      an edge process: the REST adapter
    acf-api init --config <core.yaml>      create the store, the journal and the fingerprint key of a new deployment
    acf-api admin --config <core.yaml> <operation> [--arg value ...]
                                           an operator command, carried out by the running core
    acf-api check --config <core.yaml> [--host-enrolment <table> [--other-certificate <file> ...]]
                                           validate a configuration without starting anything, and
                                           lint the host's enrolment table against the platform's certificate
    acf-api deployment-id                  print a new deployment id for a new configuration
    acf-api artifacts --out <dir> [--check]
    acf-api compat --baseline <dir> [--candidate <dir>] [--accept <file>]
                                           compare the contract artifacts with a released version

Exit status: 0 done; 1 failed; 2 the command line or the configuration cannot be used; 78 a process
refuses to start because a precondition does not hold. A service manager must not restart on 2 or 78:
nothing changes until an operator changes it.

Developer keys are issued here, by an operator on the platform host, and nowhere else: no public
interface can issue or revoke one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from acf_api import __version__

_EXIT_USAGE = 2
_EXIT_FAILED = 1
#: ``EX_CONFIG`` of sysexits.h: the process cannot start as it is configured.
_EXIT_CONFIG = 78


def _print(value: object) -> None:
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=False, default=str) + "\n")


def _fail(message: str, code: int = _EXIT_FAILED) -> int:
    sys.stderr.write(f"acf-api: {message}\n")
    return code


def _core(args: argparse.Namespace) -> int:
    from acf_api.core import app  # noqa: PLC0415 - an edge process never imports the core

    try:
        return asyncio.run(app.run(args.config))
    except app.StartupError as e:
        return _fail(f"the core refuses to start: {e}", _EXIT_CONFIG)


def _edge(args: argparse.Namespace) -> int:
    from acf_api.edge import server  # noqa: PLC0415

    return server.run(args.config)


def _init(args: argparse.Namespace) -> int:
    """Create a deployment: the store, its journal outside the store, and the fingerprint key."""
    from acf_api.core import config as cfg  # noqa: PLC0415
    from acf_api.core.store import engine, journal  # noqa: PLC0415

    try:
        config = cfg.load_config(args.config)
    except cfg.ConfigError as e:
        return _fail(str(e), _EXIT_USAGE)
    paths = config.paths
    if paths.journal.resolve().is_relative_to(paths.store_dir.resolve()):
        return _fail(
            "the security journal must live outside the store directory, "
            "so that a restore of the store never overwrites it",
            _EXIT_USAGE,
        )
    if paths.journal.exists() or (paths.store_dir / engine.STATE_FILE).exists():
        return _fail("a store or a journal already exists at the configured paths; nothing was changed")
    try:
        if not paths.fingerprint_key.exists():
            paths.fingerprint_key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(paths.fingerprint_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(secrets.token_hex(32) + "\n")
        journal.create_journal(paths.journal, config.deployment_id)
        engine.create_store(paths.store_dir, config.deployment_id)
    except (OSError, engine.StoreError, journal.JournalError) as e:
        return _fail(f"the deployment could not be created: {e}")
    _print({"deployment_id": config.deployment_id, "store": str(paths.store_dir), "journal": str(paths.journal)})
    return 0


def _check(args: argparse.Namespace) -> int:
    from acf_api.core import config as cfg  # noqa: PLC0415

    try:
        config = cfg.load_config(args.config)
        cfg.check_startup_files(config)
        allowed = config.security.allow_shared_identity
        separation = cfg.check_separation(config)
        refusing = cfg.check_separation(config, shared_identity_allowed=allowed) if allowed else separation
    except cfg.ConfigError as e:
        return _fail(str(e), _EXIT_USAGE)
    except cfg.UntrustedInput as e:
        return _fail(f"not a trusted input: {e}")
    report: dict[str, Any] = {"deployment_id": config.deployment_id, "separation": separation or "holds"}
    enrolment_problems: list[str] = []
    if args.host_enrolment is not None:
        try:
            enrolment_problems = _lint_enrolment(config.host.certificate, args.host_enrolment, args.other_certificate)
        except _Unusable as e:
            return _fail(str(e), _EXIT_USAGE)
        report["host_enrolment"] = enrolment_problems or "one entry, role caller"
    _print(report)
    return 0 if not refusing and not enrolment_problems else 1


class _Unusable(Exception):
    """A file named on the command line cannot be used. The message names it."""


def _lint_enrolment(certificate: Path, table: Path, other_certificates: list[Path]) -> list[str]:
    """What is wrong with the platform's entry in a copy of the host's enrolment table."""
    import yaml  # noqa: PLC0415

    from acf_api.core.host import enrolment  # noqa: PLC0415

    def identity(path: Path) -> enrolment.Identity:
        try:
            return enrolment.identity_of(path.read_bytes())
        except OSError as e:
            raise _Unusable(f"cannot read {path}: {e}") from e
        except enrolment.NotACertificate as e:
            raise _Unusable(f"{path} is not a PEM certificate") from e

    try:
        document = yaml.safe_load(table.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise _Unusable(f"cannot read {table}: {e}") from e
    others = {f"the certificate {path}": identity(path) for path in other_certificates}
    return enrolment.lint(document, identity(certificate), others)


def _admin(args: argparse.Namespace) -> int:
    from acf_api.core import config as cfg  # noqa: PLC0415
    from acf_api.core.admin import server as admin_server  # noqa: PLC0415
    from acf_api.core.admin.commands import AdminError  # noqa: PLC0415

    try:
        config = cfg.load_config(args.config)
    except cfg.ConfigError as e:
        return _fail(str(e), _EXIT_USAGE)
    arguments: dict[str, Any] = {}
    pending = list(args.arguments)
    while pending:
        flag = pending.pop(0)
        if not flag.startswith("--") or not pending:
            return _fail("admin arguments are given as `--name value`", _EXIT_USAGE)
        name, raw = flag[2:].replace("-", "_"), pending.pop(0)
        if raw.startswith("@"):
            # A value read from a file, for a grant document.
            try:
                import yaml  # noqa: PLC0415

                arguments[name] = yaml.safe_load(Path(raw[1:]).read_text(encoding="utf-8"))
            except (OSError, ValueError, yaml.YAMLError) as e:
                return _fail(f"cannot read {raw[1:]}: {e}", _EXIT_USAGE)
            continue
        try:
            arguments[name] = json.loads(raw)
        except ValueError:
            arguments[name] = raw
    try:
        _print(asyncio.run(admin_server.call(config.paths.admin_socket, args.operation, arguments)))
    except AdminError as e:
        return _fail(str(e))
    return 0


def _deployment_id(_args: argparse.Namespace) -> int:
    from acf_api.core.identity.keys import new_id  # noqa: PLC0415

    sys.stdout.write(new_id("dep") + "\n")
    return 0


def _artifacts(args: argparse.Namespace) -> int:
    from acf_api.contract import generate  # noqa: PLC0415

    argv = ["--out", str(args.out)] + (["--check"] if args.check else [])
    return generate.main(argv)


def _compat(args: argparse.Namespace) -> int:
    from acf_api.contract import compat  # noqa: PLC0415

    return compat.run(args.baseline, args.candidate, args.accept)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acf-api", description="The interface plane of Agent Compute Fabric.")
    parser.add_argument("--version", action="version", version=f"acf-api {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler, text in (
        ("core", _core, "run the one core process of a deployment"),
        ("edge", _edge, "run an edge process: the REST adapter"),
        ("init", _init, "create the store, the journal and the fingerprint key of a new deployment"),
        ("check", _check, "validate a core configuration and its files"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("--config", type=Path, required=True)
        p.set_defaults(handler=handler)
        if name == "check":
            p.add_argument(
                "--host-enrolment",
                type=Path,
                metavar="TABLE",
                help="a copy of the host's enrolment table: the platform must be in it once, as a caller",
            )
            p.add_argument(
                "--other-certificate",
                type=Path,
                action="append",
                default=[],
                metavar="FILE",
                help="a certificate of another platform component, such as an edge: the host must not know it",
            )
    admin = sub.add_parser("admin", help="an operator command, carried out by the running core")
    admin.add_argument("--config", type=Path, required=True)
    admin.add_argument("operation", help="for example: health, project.create, principal.create, role.set, key.issue")
    admin.add_argument(
        "arguments", nargs=argparse.REMAINDER, help="`--name value` pairs; `@file` reads a YAML or JSON file"
    )
    admin.set_defaults(handler=_admin)
    sub.add_parser("deployment-id", help="print a new deployment id for a new configuration").set_defaults(
        handler=_deployment_id
    )
    artifacts = sub.add_parser("artifacts", help="generate or check the contract artifacts")
    artifacts.add_argument("--out", type=Path, required=True)
    artifacts.add_argument("--check", action="store_true")
    artifacts.set_defaults(handler=_artifacts)
    compat = sub.add_parser("compat", help="compare the contract artifacts with a released version")
    compat.add_argument("--baseline", type=Path, required=True, help="the `protocols` directory of a released version")
    compat.add_argument("--candidate", type=Path, help="a `protocols` directory; by default, what this code generates")
    compat.add_argument("--accept", type=Path, help="a file of reviewed findings, one exact finding a line")
    compat.set_defaults(handler=_compat)
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
