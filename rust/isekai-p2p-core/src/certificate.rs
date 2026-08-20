//! The key in a peer certificate: asking for one, and reading one back.
//!
//! The name side of the same question is [`crate::hostname`]; this is the key
//! side, and both are things a peer certificate is asked in the handshake.
//!
//! The CSR side moved down with it (plan §4.4, phase 1c-iii): the endpoint
//! certificate module in `isekai-p2p` builds requests, and `isekai-p2p` and
//! `isekai-link-utils` are siblings — neither may reach across.
//!
//! It lives here rather than in `isekai-link-utils` because everything that
//! consumes it is below that crate: [`crate::attestation::verify`] takes this
//! digest as a parameter, and the peer layer compares it against what an
//! Endpoint signed for. `isekai-link-utils::cert` re-exports it for the
//! managed-domain certificate route, which is the other consumer.

use anyhow::Context as _;
use rcgen::{CertificateParams, KeyPair};

/// The SPKI digest of a certificate, base64url without padding.
///
/// The same value [`spki_sha256`] computes for a key,
/// arrived at from the other side: a certificate presented in a handshake.
/// Comparing the two is what makes a statement about a key into a statement
/// about *this connection*.
///
/// `None` for anything that will not parse — a certificate that cannot be read
/// is not one that matched.
pub fn spki_sha256_of_certificate(der: &[u8]) -> Option<String> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use x509_parser::prelude::*;

    let (_, certificate) = X509Certificate::from_der(der).ok()?;
    let digest = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// A PKCS#10 certificate request for `hostname`, signed by `key`.
///
/// One `dNSName` SAN and **no other extension request at all** — rcgen omits the
/// attribute entirely when neither `keyUsage` nor `extendedKeyUsage` is set, so
/// what goes on the wire is the SAN and nothing more. That satisfies §8.6.2
/// rule 7 (and §7.4.2, which adopts it) by having nothing to permit rather than
/// by asking for the permitted things.
pub fn certificate_request(key: &KeyPair, hostname: &str) -> anyhow::Result<String> {
    let mut params = CertificateParams::new(vec![hostname.to_owned()])
        .context("failed to build the certificate request parameters")?;
    // **The CN has to be the hostname, even though nothing reads it as a name.**
    // The proxy does not check the subject — the CA takes the name from the SAN
    // — but ACME order validation checks that whatever CN is present is also in
    // the SAN, and rcgen's default is `CN=rcgen self signed cert`. Left alone,
    // every request is refused with
    //
    //   common name `rcgen self signed cert` is missing from the CSR's
    //   subjectAltName extension
    //
    // which names the CN and so reads like a subject problem, when what it is
    // asking for is agreement with the SAN.
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostname);
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(key)
        .context("failed to sign the certificate request")?;
    csr.pem()
        .context("failed to encode the certificate request")
}

/// SHA-256 of `key`'s SubjectPublicKeyInfo, base64url without padding.
///
/// The proxy reports the same value for what it has issued and cached, so
/// comparing them answers "is the certificate it holds still one this device
/// can use" — which nothing else can answer, since only this device has the key.
pub fn spki_sha256(key: &KeyPair) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(key.public_key_der());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}
