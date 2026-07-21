//! A self-signed development certificate for the video QUIC listener.
//!
//! In P2P mode the server presents this to the video (`sample` ALPN)
//! connection; the client dials with certificate validation disabled (dev
//! only), so any self-signed cert works. This is not used for the proxy or
//! Identity API TLS, which are real.

use anyhow::Context as _;

/// A PEM certificate and its private key.
pub struct DevCert {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed certificate for `subject_alt_names`
/// (e.g. `["localhost", "127.0.0.1"]`).
pub fn dev_cert(subject_alt_names: Vec<String>) -> anyhow::Result<DevCert> {
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("failed to generate a self-signed development certificate")?;
    Ok(DevCert {
        cert_pem: certified.cert.pem(),
        key_pem: certified.key_pair.serialize_pem(),
    })
}
