//! A self-signed development certificate for the video QUIC listener.
//!
//! In P2P mode the server presents this to the video (`sample` ALPN)
//! connection; the client dials with certificate validation disabled (dev
//! only), so any self-signed cert works. This is not used for the proxy or
//! Identity API TLS, which are real.
//!
//! # Why there is a PKCS#12 bundle, and why only on Windows
//!
//! [`isekai_link_utils::make_msquic_async_listener`] loads credentials two
//! different ways. On Unix it points msquic at the PEM files. On Windows it
//! either imports a **PKCS#12** blob (`PFXImportCertStore`) or, without one,
//! falls back to building a certificate context by hand — and that fallback
//! imports the private key through an **RSA** provider
//! (`ProviderType::rsa_full()`). `rcgen` generates ECDSA P-256, so the fallback
//! fails with `ASN1 bad tag value met` and the dev certificate is unusable on
//! Windows. Handing it the PKCS#12 path instead takes the branch that copes
//! with modern keys.
//!
//! The bundle is built with OpenSSL, which is a dependency worth having only
//! where it earns its keep. On Linux and macOS that would mean linking against
//! whatever OpenSSL the system ships, and the PEM path already works there — so
//! [`DevCert::pkcs12`] is `None` off Windows and nothing links OpenSSL.

use anyhow::Context as _;

/// A PEM certificate and its private key, plus — on Windows — the same pair
/// packaged as PKCS#12.
pub struct DevCert {
    pub cert_pem: String,
    pub key_pem: String,
    /// Base64 (standard alphabet) PKCS#12 with an empty password, in the shape
    /// [`isekai_link_utils::make_msquic_async_listener`] expects, or `None`
    /// where this build does not produce one (everywhere but Windows — see the
    /// module docs).
    pub pkcs12: Option<String>,
}

/// Generate a self-signed certificate for `subject_alt_names`
/// (e.g. `["localhost", "127.0.0.1"]`).
pub fn dev_cert(subject_alt_names: Vec<String>) -> anyhow::Result<DevCert> {
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("failed to generate a self-signed development certificate")?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let pkcs12 = pkcs12_bundle(&cert_pem, &key_pem)?;
    Ok(DevCert {
        cert_pem,
        key_pem,
        pkcs12,
    })
}

/// The friendly name carried inside the bundle. Only ever seen in a certificate
/// store listing, so it just has to say where it came from.
#[cfg(windows)]
const PKCS12_FRIENDLY_NAME: &str = "ISEKAI-link dev certificate";

/// Package the PEM pair as base64 PKCS#12.
///
/// Empty password, matching the `PCWSTR::null()` that
/// `make_msquic_async_listener` passes to `PFXImportCertStore`.
#[cfg(windows)]
fn pkcs12_bundle(cert_pem: &str, key_pem: &str) -> anyhow::Result<Option<String>> {
    use base64::Engine as _;

    let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes())
        .context("failed to parse the generated development certificate")?;
    let key = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes())
        .context("failed to parse the generated development private key")?;
    let bundle = openssl::pkcs12::Pkcs12::builder()
        .name(PKCS12_FRIENDLY_NAME)
        .pkey(&key)
        .cert(&cert)
        .build2("")
        .context("failed to build a PKCS#12 bundle for the development certificate")?;
    let der = bundle
        .to_der()
        .context("failed to serialise the PKCS#12 bundle")?;
    Ok(Some(base64::engine::general_purpose::STANDARD.encode(der)))
}

/// No bundle off Windows: the PEM path is what gets used there, and building
/// one would drag in a system OpenSSL for nothing (see the module docs).
#[cfg(not(windows))]
fn pkcs12_bundle(_cert_pem: &str, _key_pem: &str) -> anyhow::Result<Option<String>> {
    Ok(None)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The bundle has to be present, decodable, and readable back as PKCS#12 —
    /// the shape `make_msquic_async_listener` hands to `PFXImportCertStore`.
    #[test]
    fn windows_dev_cert_carries_a_parseable_pkcs12_bundle() {
        use base64::Engine as _;

        let dev = dev_cert(vec!["localhost".to_owned()]).expect("generate");
        let encoded = dev.pkcs12.expect("Windows builds package a PKCS#12 bundle");
        let der = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("bundle is standard base64");
        let parsed = openssl::pkcs12::Pkcs12::from_der(&der).expect("bundle is PKCS#12");
        // Empty password, as `PFXImportCertStore` is called with a null one.
        let parsed = parsed
            .parse2("")
            .expect("bundle opens with an empty password");
        assert!(parsed.cert.is_some(), "bundle carries the certificate");
        assert!(parsed.pkey.is_some(), "bundle carries the private key");
    }
}
