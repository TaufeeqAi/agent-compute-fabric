//! A throwaway certificate authority for the mutual-TLS tests and the in-memory test host.
//!
//! Every key is generated in memory when a test asks for it. Nothing here is compiled into a release
//! build, so no code path can mint a credential on a production host.

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber};
use rustls::pki_types::CertificateDer;

use crate::edge::TlsMaterial;

/// A client certificate with its key.
pub struct ClientIdentity {
    pub name: String,
    pub der: CertificateDer<'static>,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity").field("name", &self.name).finish_non_exhaustive()
    }
}

/// One authority, one host certificate, and as many client certificates as a test needs.
pub struct TestPki {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
    server_certificate_pem: String,
    server_key_pem: String,
    serial: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for TestPki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestPki").finish_non_exhaustive()
    }
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPki {
    /// The `host_id` of the test configurations. A host's certificate must name its host (AU-4).
    pub const TEST_HOST_ID: &'static str = "test-host";

    /// An authority and a host certificate valid for `localhost`, `127.0.0.1` and the test host id.
    pub fn new() -> Self {
        Self::for_host(&["localhost", "127.0.0.1", Self::TEST_HOST_ID])
    }

    pub fn for_host(names: &[&str]) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.distinguished_name.push(DnType::CommonName, "acf test authority");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
        let issuer = Issuer::new(ca, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server = CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
        server.distinguished_name.push(DnType::CommonName, "acf test host");
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server.serial_number = Some(SerialNumber::from(1u64));
        let server_certificate_pem = server.signed_by(&server_key, &issuer).unwrap().pem();
        Self {
            ca_pem,
            issuer,
            server_certificate_pem,
            server_key_pem: server_key.serialize_pem(),
            serial: std::sync::atomic::AtomicU64::new(2),
        }
    }

    /// The authority's certificate: what a client trusts, and what the host lists as its anchor.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// What the core hands the edge for the network endpoint.
    pub fn server_material(&self) -> TlsMaterial {
        TlsMaterial {
            certificate_pem: self.server_certificate_pem.clone(),
            private_key_pem: self.server_key_pem.clone(),
            trust_anchors_pem: self.ca_pem.clone(),
        }
    }

    fn issue(&self, name: &str, key: &KeyPair) -> ClientIdentity {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(SerialNumber::from(self.serial.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        let cert = params.signed_by(key, &self.issuer).unwrap();
        ClientIdentity { name: name.to_owned(), der: cert.der().clone(), certificate_pem: cert.pem(), private_key_pem: key.serialize_pem() }
    }

    /// A new key and a certificate for it, signed by this authority.
    pub fn client(&self, name: &str) -> ClientIdentity {
        self.issue(name, &KeyPair::generate().unwrap())
    }

    /// A new certificate for the **same key**: what a rotation of the certificate looks like.
    pub fn reissue(&self, client: &ClientIdentity) -> ClientIdentity {
        self.issue(&client.name, &KeyPair::from_pem(&client.private_key_pem).unwrap())
    }
}
