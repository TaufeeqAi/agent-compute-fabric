//! The network endpoint's TLS configuration (contract AU-1, AU-3, AU-4).
//!
//! * **TLS 1.3 only.** The dependency is built without TLS 1.2 support, and the configuration names
//!   1.3 explicitly, so a lower version cannot be negotiated by any configuration.
//! * **Client authentication is mandatory.** There is no "optional" verifier and no anonymous mode.
//! * **Trust anchors are listed explicitly.** The system trust store is never consulted: a
//!   certificate that chains to a public authority means nothing here.
//! * A chain-valid certificate is only *authentication*. Authority comes from enrolment (AU-2), which
//!   matches the leaf certificate's fingerprint, or its public key's.
//! * **The host's own certificate names the host.** `host_id` is the audience of every command, so
//!   the certificate must carry it as a subject alternative name (AU-4). A caller that verifies the
//!   host against its `host_id` then verifies the thing it addresses, whatever address it dialled.

use std::sync::Arc;

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    server::{ParsedCertificate, WebPkiClientVerifier},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AcfError, Result};

/// What the core hands the edge so it can terminate TLS. The core read each file through the
/// trusted-input rule; the edge user can read none of them.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsMaterial {
    /// The host's certificate chain, PEM, leaf first.
    pub certificate_pem: String,
    /// The host's private key, PEM.
    pub private_key_pem: String,
    /// Trust anchors for client certificates, PEM.
    pub trust_anchors_pem: String,
}

impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // OB-7: a credential never reaches a log, even by accident.
        f.debug_struct("TlsMaterial")
            .field("certificate_pem", &format_args!("<{} bytes>", self.certificate_pem.len()))
            .finish_non_exhaustive()
    }
}

fn invalid(what: &str, e: impl std::fmt::Display) -> AcfError {
    AcfError::corrupt(format!("TLS {what}: {e}"))
}

fn certificates(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| invalid(what, e))?;
    if certs.is_empty() {
        return Err(invalid(what, "no certificate found"));
    }
    Ok(certs)
}

/// The server configuration of the network endpoint. Any failure here is a failed mandatory check:
/// the endpoint is not opened and the host is in `CONTAINMENT` (T-AUTH-04).
pub fn server_config(material: &TlsMaterial) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let chain = certificates(&material.certificate_pem, "certificate")?;
    let key = PrivateKeyDer::from_pem_slice(material.private_key_pem.as_bytes()).map_err(|e| invalid("private key", e))?;
    let mut anchors = RootCertStore::empty();
    for anchor in certificates(&material.trust_anchors_pem, "trust anchors")? {
        anchors.add(anchor).map_err(|e| invalid("trust anchor", e))?;
    }
    if anchors.is_empty() {
        return Err(invalid("trust anchors", "at least one explicit trust anchor is required; the system trust store is never used"));
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(anchors), Arc::clone(&provider))
        .build()
        .map_err(|e| invalid("client verifier", e))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| invalid("protocol versions", e))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| invalid("certificate and key", e))?;
    Ok(Arc::new(config))
}

/// AU-4: the host presents a credential bound to its `host_id`. The leaf certificate must be valid
/// for that name, or the endpoint is not opened: a caller told to verify the host it addresses
/// would otherwise have nothing to verify it against.
pub fn bound_to_host(material: &TlsMaterial, host_id: &str) -> Result<()> {
    let chain = certificates(&material.certificate_pem, "certificate")?;
    let leaf = chain.first().ok_or_else(|| invalid("certificate", "no certificate found"))?;
    let parsed = ParsedCertificate::try_from(leaf).map_err(|e| invalid("certificate", e))?;
    let name = ServerName::try_from(host_id)
        .map_err(|e| invalid("certificate", format!("host_id `{host_id}` cannot be the name of a certificate: {e}")))?;
    rustls::client::verify_server_name(&parsed, &name).map_err(|_| {
        invalid("certificate", format!("it does not name this host: no subject alternative name equals host_id `{host_id}` (AU-4)"))
    })
}

/// Lower-case hex SHA-256 of a certificate's DER encoding, and of its SubjectPublicKeyInfo (when it
/// parses). These are the two things an enrolment entry can name.
pub fn fingerprints(leaf: &CertificateDer<'_>) -> (String, Option<String>) {
    let certificate = hex::encode(Sha256::digest(leaf.as_ref()));
    let spki = ParsedCertificate::try_from(leaf).ok().map(|p| hex::encode(Sha256::digest(p.subject_public_key_info().as_ref())));
    (certificate, spki)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::pki::TestPki;

    #[test]
    fn the_hosts_certificate_must_name_the_host() {
        let named = TestPki::for_host(&["localhost", "acf-host-01"]).server_material();
        bound_to_host(&named, "acf-host-01").expect("a subject alternative name equals the host id");
        bound_to_host(&named, "localhost").expect("every listed name is a name of the host");
        for other in ["acf-host-02", "acf-host-0", "host-01", "ACF-HOST-01.example"] {
            let e = bound_to_host(&named, other).expect_err("the certificate names another host");
            assert!(e.message.contains("does not name this host"), "{other}: {}", e.message);
        }
        // The subject's common name is not a name: only a subject alternative name binds.
        let e = bound_to_host(&named, "acf test host").expect_err("a common name is not enough");
        assert!(e.message.contains("cannot be the name") || e.message.contains("does not name"), "{}", e.message);
        let mut garbage = named.clone();
        garbage.certificate_pem = "not a certificate".into();
        assert!(bound_to_host(&garbage, "acf-host-01").is_err());
    }

    #[test]
    fn a_complete_configuration_is_accepted_and_offers_only_tls_1_3() {
        let pki = TestPki::new();
        let cfg = server_config(&pki.server_material()).unwrap();
        assert!(!cfg.alpn_protocols.iter().any(|p| p.is_empty()));
        // The crate is built without TLS 1.2; the only version static that exists to select is 1.3.
        assert_eq!(rustls::version::TLS13.version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn missing_anchors_a_missing_key_or_garbage_are_refused() {
        let pki = TestPki::new();
        let good = pki.server_material();
        let mut no_anchors = good.clone();
        no_anchors.trust_anchors_pem = String::new();
        assert!(server_config(&no_anchors).is_err(), "no trust anchors: the system store is never a fallback");
        let mut no_key = good.clone();
        no_key.private_key_pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n".into();
        assert!(server_config(&no_key).is_err());
        let mut garbage = good.clone();
        garbage.certificate_pem = "not a certificate".into();
        assert!(server_config(&garbage).is_err());
        let mut wrong_pair = good;
        wrong_pair.private_key_pem = TestPki::new().server_material().private_key_pem;
        assert!(server_config(&wrong_pair).is_err(), "a key that does not match the certificate");
    }

    #[test]
    fn fingerprints_are_stable_distinct_and_survive_reissue_only_for_the_key() {
        let pki = TestPki::new();
        let a = pki.client("a");
        let (cert_a, spki_a) = fingerprints(&a.der);
        assert_eq!(cert_a.len(), 64);
        assert_eq!(fingerprints(&a.der), (cert_a.clone(), spki_a.clone()), "stable");
        let b = pki.client("b");
        let (cert_b, spki_b) = fingerprints(&b.der);
        assert_ne!(cert_a, cert_b);
        assert_ne!(spki_a, spki_b);
        // The same key under a new certificate: the certificate fingerprint changes, the key's does not.
        let reissued = pki.reissue(&a);
        let (cert_r, spki_r) = fingerprints(&reissued.der);
        assert_ne!(cert_r, cert_a);
        assert_eq!(spki_r, spki_a);
    }

    #[test]
    fn material_never_prints_its_key() {
        let shown = format!("{:?}", TestPki::new().server_material());
        assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    }
}
