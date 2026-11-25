"""A lint of the host's enrolment table: is the platform enrolled once, as a caller, and is nothing else of it?

On the host the platform is one peer, and its role decides what it can reach: a ``caller`` acts on the
records that carry its own tags, an ``operator`` on every record and on the host itself. No operator
method is reachable through the platform, and it is the role on the host that makes that true from the
host's side. The host does not report which role it gave a peer, so the role cannot be confirmed over
the wire today. It is checked where it is written: in the host's own table.

The lint answers three questions about a table and the certificate the platform presents:

* does **exactly one** entry match that certificate, by the certificate or by its public key;
* is that entry's role ``caller``;
* does **no** entry match a certificate of another component of the platform, such as the TLS
  certificate of an edge. An edge reads bytes from callers and must be nobody to the host.

It reads a table and decides nothing for the host: an entry it calls wrong is still in force until an
operator changes it. Run it when the platform is deployed and whenever its certificate changes
(``acf-api check --host-enrolment``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROLE_CALLER: Final = "caller"
#: The two ways an entry of the host's table names a certificate.
BY_CERTIFICATE: Final = "certificate_sha256"
BY_PUBLIC_KEY: Final = "spki_sha256"


class NotACertificate(Exception):
    """The file given as a certificate is not one PEM certificate."""


@dataclass(frozen=True, slots=True)
class Identity:
    """What an enrolment entry can name a certificate by: two digests, in lower-case hex."""

    certificate_sha256: str
    spki_sha256: str

    def matched_by(self, match: Mapping[str, Any]) -> bool:
        return match.get(BY_CERTIFICATE) == self.certificate_sha256 or match.get(BY_PUBLIC_KEY) == self.spki_sha256

    def would_be_matched_in_other_letters(self, match: Mapping[str, Any]) -> bool:
        """The digest is there, but not spelled in lower case: the host does not match it, and the entry is dead."""
        for name, digest in ((BY_CERTIFICATE, self.certificate_sha256), (BY_PUBLIC_KEY, self.spki_sha256)):
            written = match.get(name)
            if isinstance(written, str) and written != digest and written.lower() == digest:
                return True
        return False


def identity_of(pem: bytes) -> Identity:
    """The digests of one PEM certificate, as the host computes them."""
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError as e:
        raise NotACertificate("not a PEM certificate") from e
    public_key = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return Identity(
        certificate_sha256=hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest(),
        spki_sha256=hashlib.sha256(public_key).hexdigest(),
    )


def _entries(table: object) -> tuple[list[tuple[str, str, Mapping[str, Any]]], list[str]]:
    """The entries of a table as (peer id, role, match), and what is wrong with its shape."""
    problems: list[str] = []
    if not isinstance(table, Mapping) or not isinstance(table.get("peers"), list):
        return [], ["the table is not a mapping with a list of `peers`"]
    entries: list[tuple[str, str, Mapping[str, Any]]] = []
    for position, peer in enumerate(table["peers"]):
        if not isinstance(peer, Mapping) or not isinstance(peer.get("match"), Mapping):
            problems.append(f"entry {position + 1} is not a peer with a `match`")
            continue
        peer_id = str(peer.get("peer_id", f"entry {position + 1}"))[:128]
        entries.append((peer_id, str(peer.get("role", "")), peer["match"]))
    return entries, problems


def lint(table: object, platform: Identity, others: Mapping[str, Identity] | None = None) -> list[str]:
    """Everything that is wrong with the platform's enrolment in ``table``. Empty: it is as it must be.

    ``others``: certificates of other components of the platform, by a name for the message. None of them
    may be enrolled at all.
    """
    entries, problems = _entries(table)
    mine = [(peer_id, role) for peer_id, role, match in entries if platform.matched_by(match)]
    if not mine:
        dead = [peer_id for peer_id, _, match in entries if platform.would_be_matched_in_other_letters(match)]
        if dead:
            problems.append(
                f"the entry `{dead[0]}` names the platform's certificate in upper-case letters: "
                "the host matches lower-case hex only"
            )
        problems.append("no entry matches the certificate the platform presents: the host will refuse the platform")
    elif len(mine) > 1:
        names = ", ".join(f"`{peer_id}`" for peer_id, _ in mine)
        problems.append(
            f"{len(mine)} entries match the platform's certificate ({names}): one credential must name one peer"
        )
    for peer_id, role in mine:
        if role != ROLE_CALLER:
            problems.append(
                f"the entry `{peer_id}` gives the platform the role `{role}`; it must be `{ROLE_CALLER}`, "
                "so that no operator capability of the host is reachable through the platform"
            )
    for name, identity in sorted((others or {}).items()):
        enrolled = [peer_id for peer_id, _, match in entries if identity.matched_by(match)]
        if enrolled:
            problems.append(
                f"the entry `{enrolled[0]}` enrols {name}: only the core's certificate may be known to the host"
            )
    return problems
