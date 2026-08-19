//! Reading a key out of a peer certificate.
//!
//! The name side of the same question is [`crate::hostname`]; this is the key
//! side, and both are things a peer certificate is asked in the handshake.
//!
//! It lives here rather than in `isekai-link-utils` because everything that
//! consumes it is below that crate: [`crate::attestation::verify`] takes this
//! digest as a parameter, and the peer layer compares it against what an
//! Endpoint signed for. `isekai-link-utils::cert` re-exports it for the
//! managed-domain certificate route, which is the other consumer.

/// The SPKI digest of a certificate, base64url without padding.
///
/// The same value `isekai_link_utils::cert::spki_sha256` computes for a key,
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
