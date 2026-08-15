//! The video QUIC listener's TLS material: the key this device holds, the
//! certificate request that gets it signed, and a self-signed fallback.
//!
//! # The key is generated here and never leaves
//!
//! The relay carries the video connection's ciphertext. While the proxy
//! generated the key that opens it, the encryption on that leg protected the
//! peers from everyone *except* the proxy sitting in the middle of it. So the
//! key is made on the device, kept at `0600`, and what goes to the proxy is a
//! certificate request — a public key and a name (spec §8.6.2).
//!
//! There is no path that accepts a key from the proxy. The old route that
//! handed one over is not called, not even as a fallback: the proxies that
//! needed it are gone and will not be deployed again, and a fallback nobody can
//! reach is a way for the key to leave the device that nobody can test either.
//!
//! Separate from the Endpoint key on purpose. That one is a signing-only
//! identity, ideally never out of secure storage and never handed to a QUIC
//! stack; reusing one key across two protocols is its own hazard.
//!
//! The same key is reused across issuances. A new one spends an issuance slot —
//! five per seven days — and would invalidate any pinning built on it later.
//!
//! # A self-signed development certificate
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

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use isekai_p2p::agent::{
    attest, Attestation, CertificateParameters, EndpointKey, IssuedCertificate, MasqueH3Transport,
    ProxyClient, ProxyError,
};
use isekai_p2p::secret::write_secret;
use rcgen::{CertificateParams, KeyPair};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// What the video listener needs to present a certificate: the chain the proxy
/// issued, and the key this device kept.
///
/// The same three fields [`DevCert`] carries, because the listener cannot tell
/// the difference and should not have to.
pub struct VideoCert {
    /// The FQDN the certificate is for.
    pub hostname: String,
    /// The issued chain, leaf first.
    pub cert_pem: String,
    /// The device's key. **Never sent anywhere** — it is here because the
    /// listener has to be given it.
    pub key_pem: String,
    /// The pair as PKCS#12, on the platform that needs it. See the module docs.
    pub pkcs12: Option<String>,
}

/// Obtain the video listener's certificate, with the key never leaving here.
///
/// Three outcomes, and the caller treats the last two the same way:
///
/// | | |
/// | --- | --- |
/// | issued | a chain for a key this device generated (spec §8.6.2) |
/// | `None` | the proxy issues no certificates, or is older than the CSR route |
/// | error | the proxy refused in a way worth reporting |
///
/// `None` is not a failure. A proxy without `--p2p-cert-domain` never issued
/// anything, and one older than the CSR route still answers the old
/// `GET /v1/peer/certificate` — but that route hands over a key the proxy
/// generated, which is the thing being removed, so this does not fall back to
/// it. The caller uses a dev certificate and the peer skips validation, exactly
/// as it did before any of this existed.
pub async fn issue_video_cert(
    proxy: &ProxyClient<MasqueH3Transport>,
    endpoint_key: &EndpointKey,
    key: &KeyPair,
) -> anyhow::Result<Option<VideoCert>> {
    let Some(params) = proxy.certificate_parameters().await? else {
        // The proxy issues no certificates — no `--p2p-cert-domain` — so there
        // is nothing to ask for. The listener presents a development
        // certificate and the peer skips validation, as it did before any of
        // this existed.
        tracing::warn!("proxy issues no relay certificate; using a development one");
        return Ok(None);
    };
    // Said before asking, because the answer costs an issuance slot and the
    // reason is not otherwise visible: the proxy cannot know this device lost
    // its key, and this device cannot know what the proxy is holding.
    let local = spki_sha256(key);
    match &params.certificate {
        Some(cached) if cached.spki_sha256 != local => tracing::warn!(
            held = %cached.spki_sha256,
            local = %local,
            "the certificate the proxy holds is for another key — this device's is new or was \
             lost, and reissuing spends one of the Endpoint's issuances",
        ),
        _ => {}
    }

    // Said when it is nearly gone, because the way this is found out otherwise
    // is a `429` that lasts a week. Deleting the key file to test reissuance —
    // a reasonable thing to do — spends one each time.
    if let Some(quota) = &params.issue_quota {
        if quota.remaining <= 1 {
            tracing::warn!(
                remaining = quota.remaining,
                limit = quota.limit,
                reset_at = ?quota.reset_at,
                "few certificate issuances left for this Endpoint; a new key would need one",
            );
        } else {
            tracing::debug!(
                remaining = quota.remaining,
                limit = quota.limit,
                "issuance quota"
            );
        }
    }

    let csr = certificate_request(key, &params.hostname)?;

    // Say, in this Endpoint's own hand, which key the certificate is for.
    //
    // **This is what the proxy cannot forge.** It can obtain a second valid
    // certificate for the same name — it owns the name and the ACME account —
    // but it cannot sign as this Endpoint, so an initiator that checks this
    // statement and then pins the key it names is talking to this device or to
    // nobody (spec §8.6.5).
    //
    // Published on the issuance request, so a certificate and the statement
    // about it are settled together and a cached re-issue carries a fresh one.
    // Optional, and ignored by a proxy that does not know the field, so sending
    // it costs nothing where it is not yet understood.
    //
    // The expiry is this side's to choose — it is one of the signed lines, so
    // nothing downstream can shorten it without breaking the signature, and the
    // proxy checks only that it is in the future. Deliberately *not* the
    // `not_after` of whatever certificate the proxy happens to be holding: that
    // is the expiry of the certificate being replaced, so on every renewal the
    // statement would expire with the old one, and on a camera that has been
    // off past it the statement would arrive already expired and be refused
    // before the CA was even asked.
    let expires_at = (OffsetDateTime::now_utc() + ATTESTATION_LIFETIME)
        .format(&Rfc3339)
        .context("failed to format the attestation's expiry")?;
    let attestation = attest(endpoint_key, &params.hostname, &local, &expires_at);

    let Some(issued) = issue_with_retries(proxy, &csr, Some(&attestation)).await? else {
        // `parameters` answered and this did not. They arrived in the same
        // change, so this is not a version this proxy can be — something is
        // answering for the route that should be issuing.
        anyhow::bail!("the proxy has the certificate parameters route but not the issuing one");
    };

    // Checked rather than trusted. A certificate for a different key is one
    // this listener cannot present, and finding that out at the TLS handshake
    // would say nothing about why.
    // Signed over `params.hostname`, presented as `issued.hostname`. They are
    // the same name in every case the proxy produces, and if they ever were not
    // the statement would fail to verify at every initiator — which reads as an
    // attack rather than as the disagreement it is.
    anyhow::ensure!(
        issued.hostname == params.hostname,
        "the proxy issued a certificate for {}, but the statement is about {}",
        issued.hostname,
        params.hostname,
    );
    anyhow::ensure!(
        issued.spki_sha256 == local,
        "the proxy issued a certificate for another key (issued {}, local {})",
        issued.spki_sha256,
        local,
    );
    tracing::info!(
        hostname = %issued.hostname,
        not_after = ?issued.not_after,
        "issued a relay certificate for a key that stayed on this device",
    );
    video_cert(&issued.hostname, &issued.cert_pem, key).map(Some)
}

/// How long a statement stands.
///
/// It bounds the *statement*, not the certificate. What is vouched for is a
/// key, and the key is reused across issuances, so a statement outliving any
/// one certificate is not a statement about something that stopped being true.
/// A fresh one goes out with every issuance, so this only has to outlast the
/// gap between them.
const ATTESTATION_LIFETIME: time::Duration = time::Duration::days(90);

/// How long to wait between attempts when the proxy says to come back.
///
/// The proxy advertises `Retry-After: 30`, and this does not read it: the
/// control-plane transport hands back a status and a body, not headers. These
/// are chosen to cover an ACME order that is merely slow without turning a
/// broken proxy into a minute of silence at startup. Reading the header is the
/// better answer if this ever needs to be more than approximately right.
const ISSUANCE_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
];

/// Issue, retrying the answers that say retrying is the point.
///
/// **`certificate-unavailable` means an order is in flight or the CA was
/// slow** — a condition that clears on its own, and the first issuance for an
/// Endpoint is exactly when it happens. Failing on it would mean a camera that
/// cannot start the first time it is asked to.
///
/// Nothing else is retried. `certificate-rate-limited` clears in days, not
/// seconds, and `csr-invalid` is a fault on this side that will read the same
/// however many times it is sent.
async fn issue_with_retries(
    proxy: &ProxyClient<MasqueH3Transport>,
    csr: &str,
    attestation: Option<&Attestation>,
) -> Result<Option<IssuedCertificate>, ProxyError> {
    let mut delays = ISSUANCE_RETRY_DELAYS.iter();
    loop {
        let error = match proxy.issue_certificate(csr, attestation).await {
            Ok(issued) => return Ok(issued),
            Err(e) => e,
        };
        let retryable = matches!(
            &error,
            ProxyError::Problem { problem, .. }
                if problem.as_ref().map(|p| p.kind()) == Some("certificate-unavailable")
        );
        let Some(delay) = delays.next().filter(|_| retryable) else {
            return Err(error);
        };
        tracing::info!(?delay, "the proxy is not ready to issue yet: {error}");
        tokio::time::sleep(*delay).await;
    }
}

/// Load the video TLS key, generating and persisting one on first use.
///
/// Reused across issuances: see the module docs for why a fresh key is not
/// free. Written `0600` and never sent — a caller that logs, backs up or syncs
/// this file has undone the point of it.
pub fn load_or_generate_video_key(path: &Path) -> anyhow::Result<KeyPair> {
    if let Some(key) = read_key(path)? {
        return Ok(key);
    }
    // P-256: on the proxy's accepted list, the same curve as the Endpoint key,
    // and the smallest handshake of the options.
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate a video TLS key")?;
    // Written through a temporary and renamed into place, so a crash between
    // the two leaves either the old file or none — never a half-written one.
    // A truncated key here is not a lost file: `read_key` would find it, fail
    // to parse it, and go on failing at every start, because a key is only
    // generated when there is nothing there at all.
    write_secret(path, key.serialize_pem().as_bytes())
        .with_context(|| format!("failed to store the video TLS key at {}", path.display()))?;

    // Read back rather than returning what was just generated. Two processes
    // starting together both generate, and the rename means one file wins; the
    // one that reads its own key would hold a key its own file does not have,
    // and would find out at the next start when the certificate it had issued
    // no longer matched. Whatever is on disk is the key.
    read_key(path)?.with_context(|| {
        format!(
            "the video TLS key vanished after writing {}",
            path.display()
        )
    })
}

/// The key at `path`, or `None` if there is no file there.
///
/// A file that is present and unreadable is an error rather than a reason to
/// generate: overwriting it would throw away the identity a certificate was
/// issued against, and spend one of the Endpoint's issuances doing it.
fn read_key(path: &Path) -> anyhow::Result<Option<KeyPair>> {
    let pem = match std::fs::read_to_string(path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read the video TLS key at {}", path.display()))
        }
    };
    KeyPair::from_pem(&pem)
        .with_context(|| format!("failed to parse the video TLS key at {}", path.display()))
        .map(Some)
}

/// A PKCS#10 certificate request for `hostname`, signed by `key`.
///
/// One `dNSName` SAN and **no other extension request at all** — rcgen omits the
/// attribute entirely when neither `keyUsage` nor `extendedKeyUsage` is set, so
/// what goes on the wire is the SAN and nothing more. That satisfies §8.6.2
/// rule 7 by having nothing to permit, rather than by asking for the permitted
/// things.
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

/// Assemble what the listener needs from an issued chain and the local key.
///
/// The PKCS#12 is built here because this is the only side that can: the
/// issuance response deliberately carries no key.
pub fn video_cert(hostname: &str, cert_pem: &str, key: &KeyPair) -> anyhow::Result<VideoCert> {
    let key_pem = key.serialize_pem();
    let pkcs12 = pkcs12_bundle(cert_pem, &key_pem)?;
    Ok(VideoCert {
        hostname: hostname.to_owned(),
        cert_pem: cert_pem.to_owned(),
        key_pem,
        pkcs12,
    })
}

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

#[cfg(test)]
mod key_tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("isekai-tls-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("video-tls.pem")
    }

    /// The same key comes back, because a new one costs an issuance — five per
    /// seven days — and would invalidate anything pinned to the old one.
    #[test]
    fn the_key_is_generated_once_and_then_reused() {
        let path = temp_path("reuse");
        let _ = std::fs::remove_file(&path);

        let first = load_or_generate_video_key(&path).expect("generate");
        let again = load_or_generate_video_key(&path).expect("load");

        assert_eq!(
            spki_sha256(&first),
            spki_sha256(&again),
            "a restart must not order a new certificate",
        );
        let _ = std::fs::remove_file(&path);
    }

    /// It is a private key on disk. Anything that widens this has undone the
    /// reason the key is generated here at all.
    #[cfg(unix)]
    #[test]
    fn the_key_file_is_owner_only_from_the_start() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("mode");
        let _ = std::fs::remove_file(&path);
        load_or_generate_video_key(&path).expect("generate");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the video TLS key must be 0600");
        let _ = std::fs::remove_file(&path);
    }

    /// A key file that is there but unreadable is not a reason to make a new
    /// one. Overwriting it throws away the identity a certificate was issued
    /// against and spends one of five issuances a week doing it — so a
    /// truncated file has to be a loud failure, not a quiet fresh start.
    #[test]
    fn an_unreadable_key_is_an_error_and_not_a_new_one() {
        let path = temp_path("truncated");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "-----BEGIN PRIVATE KEY-----\ntruncated").expect("write");

        let err = load_or_generate_video_key(&path).expect_err("must not silently replace it");
        assert!(
            format!("{err:#}").contains("failed to parse"),
            "the error should name what it could not read: {err:#}",
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The proxy checks the SAN against the name it derived (spec §8.6.2 rule
    /// 6) and rejects anything else, so the request has to carry exactly the
    /// hostname it was given — not one this side worked out.
    #[test]
    fn the_request_asks_for_the_name_it_was_given() {
        let path = temp_path("csr");
        let _ = std::fs::remove_file(&path);
        let key = load_or_generate_video_key(&path).expect("generate");

        let csr = certificate_request(&key, "e4f9c3.p2p.isekai.tools").expect("csr");

        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(csr.len() < 8 * 1024, "the proxy caps the CSR at 8 KiB");
        let der = pem_body(&csr);
        assert!(
            contains(&der, b"e4f9c3.p2p.isekai.tools"),
            "the SAN has to be the hostname the proxy gave",
        );
        assert!(
            !contains(&der, b"rcgen self signed cert"),
            "rcgen's default CN is not in the SAN, and ACME order validation \
             refuses a CN that is not",
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The digest is over the public key, so it is the same whoever computes
    /// it — which is what makes comparing it to the proxy's answer meaningful.
    #[test]
    fn two_keys_do_not_share_a_digest() {
        let a = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a");
        let b = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("b");
        assert_ne!(spki_sha256(&a), spki_sha256(&b));
        assert_eq!(spki_sha256(&a), spki_sha256(&a));
    }

    fn pem_body(pem: &str) -> Vec<u8> {
        use base64::Engine as _;
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("base64")
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
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
