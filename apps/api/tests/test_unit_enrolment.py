"""The lint of the host's enrolment table: one peer for the platform, a caller, and nothing else of it.

Proves T3-RED-45 at the static level and the check that AR-312 leaves to the deployment procedure: the
host does not report the role it gave a peer, so the role is read where it is written.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acf_api import cli
from acf_api.core.host import enrolment
from tests.support.deploy import private_dir
from tests.support.harness import config_dict

pytestmark = pytest.mark.proves("T3-RED-45", level="L0")

REPO = Path(__file__).resolve().parents[3]


def certificate(name: str, key: ec.EllipticCurvePrivateKey | None = None) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """A self-signed certificate and its key. ``key``: issue another certificate for the same key."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    built = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return built.public_bytes(serialization.Encoding.PEM), key


@pytest.fixture(scope="module")
def platform() -> enrolment.Identity:
    return enrolment.identity_of(certificate("developer-platform")[0])


def table(*peers: dict[str, Any]) -> dict[str, Any]:
    root = {"peer_id": "local-root", "role": "operator", "match": {"local_uid": 0}}
    return {"schema_version": 1, "peers": [root, *peers]}


def peer(role: str, peer_id: str = "developer-platform", **match: Any) -> dict[str, Any]:
    return {"peer_id": peer_id, "role": role, "match": match}


# ----------------------------------------------------------------------------------------- the digests
def test_the_digests_are_the_ones_the_hosts_manual_tells_an_operator_to_compute() -> None:
    """`openssl x509 -outform DER | sha256sum` and `openssl x509 -pubkey | openssl pkey -pubin -outform DER | sha256sum`."""
    pem, key = certificate("anyone")
    identity = enrolment.identity_of(pem)
    loaded = x509.load_pem_x509_certificate(pem)
    der = loaded.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert identity.certificate_sha256 == hashlib.sha256(der).hexdigest()
    assert identity.spki_sha256 == hashlib.sha256(spki).hexdigest()
    assert identity.certificate_sha256 != identity.spki_sha256
    assert all(
        len(digest) == 64 and digest == digest.lower() for digest in (identity.certificate_sha256, identity.spki_sha256)
    )


def test_a_new_certificate_for_the_same_key_keeps_the_public_key_digest_and_changes_the_other() -> None:
    first, key = certificate("developer-platform")
    second, _ = certificate("developer-platform", key)
    one, two = enrolment.identity_of(first), enrolment.identity_of(second)
    assert one.spki_sha256 == two.spki_sha256
    assert one.certificate_sha256 != two.certificate_sha256


@pytest.mark.parametrize(
    "not_one", [b"", b"not a certificate", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"]
)
def test_what_is_not_a_certificate_is_said_to_be_none(not_one: bytes) -> None:
    with pytest.raises(enrolment.NotACertificate):
        enrolment.identity_of(not_one)


# --------------------------------------------------------------------------------------------- the lint
@pytest.mark.parametrize("by", [enrolment.BY_PUBLIC_KEY, enrolment.BY_CERTIFICATE])
def test_one_entry_with_the_role_caller_is_as_it_must_be(platform: enrolment.Identity, by: str) -> None:
    assert enrolment.lint(table(peer("caller", **{by: getattr(platform, by)})), platform) == []


def test_a_platform_that_is_not_enrolled_is_said_to_be_refused_by_the_host(platform: enrolment.Identity) -> None:
    (problem,) = enrolment.lint(table(), platform)
    assert "no entry matches" in problem


@pytest.mark.parametrize("role", ["operator", "observer", "", "Caller"])
def test_any_role_but_caller_is_wrong_and_the_reason_is_given(platform: enrolment.Identity, role: str) -> None:
    (problem,) = enrolment.lint(table(peer(role, spki_sha256=platform.spki_sha256)), platform)
    assert f"the role `{role}`" in problem
    assert "must be `caller`" in problem


def test_two_entries_for_the_one_certificate_are_wrong_even_if_both_are_callers(platform: enrolment.Identity) -> None:
    twice = table(
        peer("caller", "by-key", spki_sha256=platform.spki_sha256),
        peer("caller", "by-certificate", certificate_sha256=platform.certificate_sha256),
    )
    (problem,) = enrolment.lint(twice, platform)
    assert "2 entries match" in problem
    assert "`by-key`" in problem
    assert "`by-certificate`" in problem


def test_an_operator_entry_beside_a_caller_entry_is_reported_for_both_reasons(platform: enrolment.Identity) -> None:
    both = table(
        peer("caller", "as-caller", spki_sha256=platform.spki_sha256),
        peer("operator", "as-operator", certificate_sha256=platform.certificate_sha256),
    )
    problems = enrolment.lint(both, platform)
    assert len(problems) == 2
    assert any("2 entries match" in problem for problem in problems)
    assert any("`as-operator`" in problem and "must be `caller`" in problem for problem in problems)


def test_a_digest_in_upper_case_is_a_dead_entry_and_the_lint_says_why(platform: enrolment.Identity) -> None:
    problems = enrolment.lint(table(peer("caller", spki_sha256=platform.spki_sha256.upper())), platform)
    assert len(problems) == 2
    assert "upper-case" in problems[0]
    assert "no entry matches" in problems[1]


def test_no_other_component_of_the_platform_may_be_known_to_the_host(platform: enrolment.Identity) -> None:
    """An edge reads the bytes callers send. A certificate of an edge that the host accepts is a way round the core."""
    rest = enrolment.identity_of(certificate("rest-edge")[0])
    mcp = enrolment.identity_of(certificate("mcp-edge")[0])
    others = {"the REST edge's certificate": rest, "the agent-protocol edge's certificate": mcp}
    good = peer("caller", spki_sha256=platform.spki_sha256)
    assert enrolment.lint(table(good), platform, others) == []
    (problem,) = enrolment.lint(
        table(good, peer("observer", "edge", certificate_sha256=rest.certificate_sha256)), platform, others
    )
    assert "`edge` enrols the REST edge's certificate" in problem


def test_entries_of_other_peers_are_none_of_the_lints_business(platform: enrolment.Identity) -> None:
    stranger = enrolment.identity_of(certificate("somebody-else")[0])
    others_peers = table(
        peer("caller", spki_sha256=platform.spki_sha256),
        peer("operator", "break-glass", certificate_sha256=stranger.certificate_sha256),
        peer("observer", "metrics", local_gid=992),
    )
    assert enrolment.lint(others_peers, platform) == []


@pytest.mark.parametrize(
    "broken",
    [None, [], "peers", {"peers": "none"}, {"schema_version": 1}],
)
def test_a_table_that_is_not_a_table_is_a_problem_and_never_a_crash(platform: enrolment.Identity, broken: Any) -> None:
    problems = enrolment.lint(broken, platform)
    assert problems[0] == "the table is not a mapping with a list of `peers`"


def test_an_entry_that_is_not_an_entry_is_named_by_its_position(platform: enrolment.Identity) -> None:
    odd = {
        "peers": ["text", {"peer_id": "no-match", "role": "caller"}, peer("caller", spki_sha256=platform.spki_sha256)]
    }
    assert enrolment.lint(odd, platform) == [
        "entry 1 is not a peer with a `match`",
        "entry 2 is not a peer with a `match`",
    ]


def test_the_shipped_example_enrols_nobody_for_the_platform() -> None:
    """The example's entry for a control plane is a comment: an operator writes the real digest in."""
    shipped = yaml.safe_load((REPO / "config" / "enrolment.example.yaml").read_text(encoding="utf-8"))
    assert [p["role"] for p in shipped["peers"]] == ["operator"], "only the local operator is live in the example"
    (problem,) = enrolment.lint(shipped, enrolment.identity_of(certificate("developer-platform")[0]))
    assert "no entry matches" in problem


# ------------------------------------------------------------------------------------- the operator's command
@pytest.fixture
def deployment() -> Iterator[tuple[Path, enrolment.Identity]]:
    """A configuration whose files pass the trusted-input rule, and the digests of its host certificate."""
    with private_dir("n") as root:
        data = config_dict(root)
        pem, key = certificate("developer-platform")
        secrets = Path(data["host"]["certificate"]).parent
        secrets.mkdir(mode=0o700)
        Path(data["host"]["certificate"]).write_bytes(pem)
        Path(data["host"]["trust_anchors"]).write_bytes(pem)
        private_key = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        for secret, content in (
            (data["host"]["private_key"], private_key),
            (data["paths"]["fingerprint_key"], b"ab" * 32 + b"\n"),
        ):
            Path(secret).write_bytes(content)
            Path(secret).chmod(0o600)
        for public in (data["host"]["certificate"], data["host"]["trust_anchors"]):
            Path(public).chmod(0o644)
        config = root / "core.yaml"
        config.write_text(yaml.safe_dump(data), encoding="utf-8")
        yield config, enrolment.identity_of(pem)


def _table_file(config: Path, name: str, *peers: dict[str, Any]) -> str:
    path = config.parent / name
    path.write_text(yaml.safe_dump(table(*peers)), encoding="utf-8")
    return str(path)


def test_the_check_command_lints_the_table_an_operator_points_it_at(
    deployment: tuple[Path, enrolment.Identity], capsys: pytest.CaptureFixture[str]
) -> None:
    config, identity = deployment
    good = _table_file(config, "enrolment.yaml", peer("caller", spki_sha256=identity.spki_sha256))
    assert cli.main(["check", "--config", str(config), "--host-enrolment", good]) == 0
    assert '"host_enrolment": "one entry, role caller"' in capsys.readouterr().out

    as_operator = _table_file(config, "operator.yaml", peer("operator", spki_sha256=identity.spki_sha256))
    assert cli.main(["check", "--config", str(config), "--host-enrolment", as_operator]) == 1
    assert "must be `caller`" in capsys.readouterr().out


def test_the_check_command_is_told_which_other_certificates_the_host_must_not_know(
    deployment: tuple[Path, enrolment.Identity], capsys: pytest.CaptureFixture[str]
) -> None:
    config, identity = deployment
    edge_pem, _ = certificate("rest-edge")
    edge = config.parent / "rest-tls.crt"
    edge.write_bytes(edge_pem)
    both = _table_file(
        config,
        "both.yaml",
        peer("caller", spki_sha256=identity.spki_sha256),
        peer("caller", "rest-edge", certificate_sha256=enrolment.identity_of(edge_pem).certificate_sha256),
    )
    assert cli.main(["check", "--config", str(config), "--host-enrolment", both]) == 0, (
        "nobody said the second one is ours"
    )
    capsys.readouterr()
    assert cli.main(["check", "--config", str(config), "--host-enrolment", both, "--other-certificate", str(edge)]) == 1
    assert f"`rest-edge` enrols the certificate {edge}" in capsys.readouterr().out


def test_the_check_command_says_which_file_it_cannot_use(
    deployment: tuple[Path, enrolment.Identity], capsys: pytest.CaptureFixture[str]
) -> None:
    config, identity = deployment
    assert cli.main(["check", "--config", str(config), "--host-enrolment", str(config.parent / "missing.yaml")]) == 2
    assert "cannot read" in capsys.readouterr().err

    not_yaml = config.parent / "broken.yaml"
    not_yaml.write_text("peers: [", encoding="utf-8")
    assert cli.main(["check", "--config", str(config), "--host-enrolment", str(not_yaml)]) == 2
    assert f"cannot read {not_yaml}" in capsys.readouterr().err

    good = _table_file(config, "enrolment.yaml", peer("caller", spki_sha256=identity.spki_sha256))
    assert (
        cli.main(["check", "--config", str(config), "--host-enrolment", good, "--other-certificate", str(not_yaml)])
        == 2
    )
    assert f"{not_yaml} is not a PEM certificate" in capsys.readouterr().err


def test_without_a_table_the_check_command_says_nothing_about_enrolment(
    deployment: tuple[Path, enrolment.Identity], capsys: pytest.CaptureFixture[str]
) -> None:
    config, _ = deployment
    assert cli.main(["check", "--config", str(config)]) == 0
    assert "host_enrolment" not in capsys.readouterr().out
