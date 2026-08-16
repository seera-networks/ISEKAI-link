//! Managed-domain certificates (spec §7.4), and the CSR pieces §7.4 shares
//! with §8.6.
//!
//! # What the CSR route is for
//!
//! `GET /certificate` (§7.4.3) has the proxy generate the key and send it. That
//! works, and it means the proxy holds the private key for the name a browser
//! connects to — so its disk, its backups and whoever can read them hold it
//! too. `POST /certificate` (§7.4.2) sends a certificate signing request
//! instead: a public key and a name. **Nothing here ever sends a key.**
//!
//! It does not make the proxy unable to intercept — it owns the name, the DNS
//! and the ACME account, and §7.4.4 says so plainly. Unlike §8.6 there is no
//! pinning available, because the other end is a browser. What this closes is
//! the exposure that does not need an attacker.
//!
//! # Why the name comes from the proxy
//!
//! A CSR needs the FQDN in its SAN, and it is `p{port}.{domain}`: the port
//! comes from the allocated public address and the domain is the proxy's
//! `--managed-domain`. Neither the value nor the rule for combining them is
//! knowable here, which is what [`certificate_parameters`] is for — the same
//! reason §8.6.1 exists on the Endpoint side. **Use `hostname` verbatim rather
//! than deriving it**; the proxy derives the name it will issue for from the
//! allocated port, and a locally-built name that disagrees is refused.
//!
//! # Shared with §8.6
//!
//! §7.4.2 states its CSR rules as identical to §8.6.2 rules 1–8, differing only
//! in how the FQDN is derived. So the request builder and the SPKI digest live
//! here and `camera-core`'s Endpoint-certificate path uses them, rather than the
//! two drifting apart the first time either is edited.

use std::path::Path;

use anyhow::Context as _;
use bytes::Bytes;
use h3_util::msquic_async::H3MsQuicAsyncConnector;
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use rcgen::{CertificateParams, KeyPair};
use serde::Deserialize;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::auth::AddAuthorizationLayer;

/// What `GET /certificate/parameters` answers (spec §7.4.1).
#[derive(Debug, Clone, Deserialize)]
pub struct CertificateParameters {
    /// The FQDN to put in the CSR's SAN, **verbatim**.
    pub hostname: String,
    /// The proxy's managed domain, for reporting.
    #[serde(default)]
    pub domain: String,
    /// The allocated public address's port, which `hostname` is derived from.
    #[serde(default)]
    pub port: u16,
    /// Key types the proxy will accept in a CSR.
    #[serde(default)]
    pub key_types: Vec<String>,
    /// Whether the deprecated `GET /certificate` route is still open.
    #[serde(default)]
    pub server_key_issuance: bool,
    /// How many issuances remain in the current window.
    #[serde(default)]
    pub issue_quota: Option<IssueQuota>,
    /// The certificate the proxy is holding, if it has one.
    #[serde(default)]
    pub certificate: Option<HeldCertificate>,
}

/// The issuance allowance, which is spent by orders to the CA.
///
/// A CSR carrying a key the proxy already has a certificate for is answered
/// from its cache and does not touch this.
#[derive(Debug, Clone, Deserialize)]
pub struct IssueQuota {
    pub limit: u32,
    pub window_secs: u64,
    pub remaining: u32,
    #[serde(default)]
    pub reset_at: String,
}

/// The certificate the proxy currently holds for this user.
#[derive(Debug, Clone, Deserialize)]
pub struct HeldCertificate {
    /// SHA-256 of its SubjectPublicKeyInfo, base64url unpadded.
    ///
    /// **Compare it with [`spki_sha256`] of the local key.** A mismatch means
    /// the proxy is holding a certificate for a key nobody has any more, so it
    /// is of no use to anyone — see [`CertificateParameters::usable_with`].
    pub spki_sha256: String,
    #[serde(default)]
    pub not_after: String,
}

impl CertificateParameters {
    /// Whether the certificate the proxy holds is one `key` can actually serve.
    ///
    /// `false` when it holds none, and when it holds one for a different key —
    /// which is the ordinary state right after moving off the server-key route,
    /// since the key that certificate was issued for was the proxy's.
    pub fn usable_with(&self, key: &KeyPair) -> bool {
        self.certificate
            .as_ref()
            .is_some_and(|held| held.spki_sha256 == spki_sha256(key))
    }

    /// Whether the proxy accepts the key type this module generates.
    ///
    /// An empty list is not a refusal: an older proxy does not send the field,
    /// and refusing on that would be reading silence as a `no`.
    pub fn accepts_p256(&self) -> bool {
        self.key_types.is_empty() || self.key_types.iter().any(|k| k == KEY_TYPE)
    }
}

/// The key type this module generates, as §7.4.1 names it.
const KEY_TYPE: &str = "ecdsa-p256";

/// What `POST /certificate` answers (spec §7.4.2).
///
/// **No `key_pem` and no `pkcs12`, and their absence is the point of the
/// route.** A caller that needs a PKCS#12 assembles one from this and the key
/// it already holds.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedCertificate {
    pub hostname: String,
    pub cert_pem: String,
    /// The digest of the key it was issued for — check it against the local one.
    #[serde(default)]
    pub spki_sha256: String,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub not_after: String,
}

/// A managed-domain certificate and the key it belongs to.
pub struct ManagedCertificate {
    /// The name the certificate is for, and the one to present as SNI.
    pub hostname: String,
    pub cert_pem: String,
    /// Serialized from the local key. It has not been anywhere.
    pub key_pem: String,
}

// ── key and CSR primitives ───────────────────────────────────────────────────

/// Load the TLS key at `path`, generating and persisting one on first use.
///
/// **Reused across issuances rather than regenerated.** A new key spends one of
/// the five weekly issuances (§7.4.2), where the same key is answered from the
/// proxy's cache without troubling the CA at all; and on the §8.6 side it would
/// invalidate anything pinned to the old one.
///
/// Written `0600` through a temporary and renamed into place, so a crash
/// between the two leaves either the old file or none — never a half-written
/// one that every later start fails to parse. Read back afterwards because two
/// processes starting together both generate and the rename picks one: the one
/// that returned its own key would hold a key its own file does not have.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<KeyPair> {
    if let Some(key) = read_key(path)? {
        return Ok(key);
    }
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate a TLS key")?;
    write_key(path, &key.serialize_pem())
        .with_context(|| format!("failed to store the TLS key at {}", path.display()))?;
    read_key(path)?
        .with_context(|| format!("the TLS key vanished after writing {}", path.display()))
}

/// The key at `path`, or `None` if there is no file there.
///
/// A file that is present and unreadable is an error rather than a reason to
/// generate: overwriting it would throw away the identity a certificate was
/// issued against, and spend an issuance doing it.
fn read_key(path: &Path) -> anyhow::Result<Option<KeyPair>> {
    let pem = match std::fs::read_to_string(path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read the TLS key at {}", path.display()))
        }
    };
    KeyPair::from_pem(&pem)
        .with_context(|| format!("failed to parse the TLS key at {}", path.display()))
        .map(Some)
}

fn write_key(path: &Path, pem: &str) -> anyhow::Result<()> {
    use std::io::Write as _;

    // **Beside the key, never in the system temp directory.** `persist` is a
    // rename, which does not cross filesystems, and a bare relative path — the
    // default for `masque-h3-server` — has an empty parent. Left to fall back
    // on `NamedTempFile::new()`, the temporary lands on `/tmp`, the rename
    // fails `EXDEV`, and the key is never written: the same failure on every
    // start.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .context("failed to create a temporary file beside the key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Before the bytes, so the key is never briefly world-readable.
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("failed to restrict the temporary key file")?;
    }
    temp.write_all(pem.as_bytes())
        .context("failed to write the key")?;
    // The rename is only atomic with respect to a crash if the bytes are on
    // disk before it.
    temp.as_file()
        .sync_all()
        .context("failed to flush the key")?;
    temp.persist(path)
        .map_err(|e| anyhow::anyhow!("failed to move the key into place: {e}"))?;
    Ok(())
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

/// The SPKI digest of a certificate, arrived at from the other side.
///
/// The same value [`spki_sha256`] computes for a key, taken from a certificate
/// instead — a chain that was issued, or one presented in a handshake.
///
/// `None` for anything that will not parse: a certificate that cannot be read
/// is not one that matched.
pub fn spki_sha256_of_certificate(der: &[u8]) -> Option<String> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use x509_parser::prelude::*;

    let (_, certificate) = X509Certificate::from_der(der).ok()?;
    let digest = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

// ── the §7.4 routes ──────────────────────────────────────────────────────────

/// `GET /certificate/parameters` (spec §7.4.1).
///
/// Touches no ACME and spends no issuance, so it can be read before every
/// request — and it has to be, because the name depends on the allocated port
/// and reading it is what allocates one.
pub async fn certificate_parameters(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<CertificateParameters> {
    let body = get(uri, jwt, channel, "/certificate/parameters", None).await?;
    serde_json::from_slice(&body).context("failed to parse the certificate parameters")
}

/// `POST /certificate` (spec §7.4.2) — issue against a CSR.
///
/// The proxy derives the name from the allocated port; `csr_pem` has to name
/// the same one, which is why it should be built from
/// [`CertificateParameters::hostname`] rather than assembled here.
pub async fn issue_certificate(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
    csr_pem: &str,
) -> anyhow::Result<IssuedCertificate> {
    let request = serde_json::to_vec(&serde_json::json!({ "csr_pem": csr_pem }))
        .context("failed to encode the certificate request body")?;
    let body = get(
        uri,
        jwt,
        channel,
        "/certificate",
        Some(("POST", Bytes::from(request))),
    )
    .await?;
    serde_json::from_slice(&body).context("failed to parse the issued certificate")
}

/// A managed-domain certificate for this client, obtaining one if needed.
///
/// Reads the parameters, uses the key at `key_path` (generating one on first
/// use), and asks for a certificate. **The key never leaves the machine**; what
/// comes back is a chain.
///
/// Issuance is asked for every time rather than only when something looks
/// stale: the proxy answers a CSR carrying a key it already has a certificate
/// for from its cache, without an order, so the ordinary case costs one request
/// and no quota.
pub async fn obtain_managed_certificate(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
    key_path: &Path,
) -> anyhow::Result<ManagedCertificate> {
    let params = certificate_parameters(uri.clone(), jwt, channel.clone()).await?;
    let key = load_or_generate_key(key_path)?;
    anyhow::ensure!(
        params.accepts_p256(),
        "the proxy accepts {:?} but this client only generates {KEY_TYPE}",
        params.key_types,
    );
    if let Some(quota) = &params.issue_quota {
        // Said before asking, because the way it is otherwise discovered is a
        // 429 that lasts the rest of the window.
        if quota.remaining <= 1 {
            tracing::warn!(
                "certificate issuances nearly spent: {} of {} left until {}",
                quota.remaining,
                quota.limit,
                quota.reset_at,
            );
        }
    }
    if !params.usable_with(&key) {
        // Not a failure — it is what the first request after moving off the
        // server-key route looks like — but it does mean this one orders.
        tracing::info!(
            "the proxy holds no certificate for this key; asking it to issue one for {}",
            params.hostname,
        );
    }
    let csr = certificate_request(&key, &params.hostname)?;
    let issued = issue_certificate(uri, jwt, channel, &csr).await?;

    // **Against the certificate, not against the digest beside it.** The field
    // is the proxy's word for what it issued; the chain is what will be served,
    // and a mismatch between the two would otherwise surface as a handshake
    // that fails for no stated reason. An omitted field is then not a way past
    // the check, which is what comparing the two strings made it.
    let local = spki_sha256(&key);
    let leaf = leaf_der(&issued.cert_pem).context("the issued chain has no certificate in it")?;
    let issued_for =
        spki_sha256_of_certificate(&leaf).context("the issued certificate could not be parsed")?;
    anyhow::ensure!(
        issued_for == local,
        "the proxy issued a certificate for another key ({issued_for} rather than \
         {local}); it would not be usable here",
    );
    anyhow::ensure!(
        issued.hostname == params.hostname,
        "the proxy issued for {} but named {} in its parameters",
        issued.hostname,
        params.hostname,
    );
    Ok(ManagedCertificate {
        hostname: issued.hostname,
        cert_pem: issued.cert_pem,
        key_pem: key.serialize_pem(),
    })
}

/// The first certificate in a PEM chain, as DER.
///
/// A chain is leaf-first, and the leaf is the one the key has to match.
fn leaf_der(chain_pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;

    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let start = chain_pem.find(BEGIN)? + BEGIN.len();
    let end = chain_pem[start..].find(END)? + start;
    let body: String = chain_pem[start..end]
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// One request, with the status checked and the body carried either way.
///
/// **§7.4 is a plain-text route (§5.6), so a failure is a status and a
/// sentence.** Parsing the body as the success type first turns
/// `csr subject common name must be…` into a JSON error, which is how an
/// earlier version of the Endpoint route left the only useful sentence on the
/// proxy's console.
async fn get(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
    path: &str,
    post: Option<(&str, Bytes)>,
) -> anyhow::Result<Bytes> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().context("URI scheme is required")?)
        .authority(
            uri.authority()
                .cloned()
                .context("URI authority is required")?,
        )
        .path_and_query(path)
        .build()?;
    let (method, body) = match post {
        Some((method, body)) => (method, body),
        None => ("GET", Bytes::new()),
    };
    let mut request = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        request = request.header(http::header::CONTENT_TYPE, "application/json");
    }
    let request = request.body(Full::new(body))?;

    let response = channel
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("channel ready error: {e}"))?
        .call(request)
        .await
        .map_err(|e| anyhow::anyhow!("channel call error: {e}"))?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("response body collect error: {e}"))?
        .to_bytes();
    if status.is_success() {
        return Ok(data);
    }
    let detail = String::from_utf8_lossy(&data);
    let detail = detail.trim();
    let retry = match (status, retry_after) {
        (StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE, Some(after)) => {
            // Seconds or an HTTP-date (RFC 9110), so it is repeated rather
            // than given a unit.
            format!("; retry-after {after}")
        }
        _ => String::new(),
    };
    anyhow::bail!(
        "{path} answered {status}{}{retry}",
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyPair {
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate a key")
    }

    /// The whole route rests on the digest of a key matching the digest of a
    /// certificate issued for it. If these disagreed, every check built on them
    /// would refuse honest certificates.
    #[test]
    fn a_certificate_digests_to_the_same_value_as_its_key() {
        let key = key();
        let params = CertificateParams::new(vec!["p1.example.com".to_owned()]).expect("params");
        let cert = params.self_signed(&key).expect("self-sign");
        assert_eq!(
            spki_sha256_of_certificate(cert.der()),
            Some(spki_sha256(&key)),
        );
    }

    /// A certificate for somebody else's key does not.
    #[test]
    fn a_certificate_for_another_key_does_not() {
        let params = CertificateParams::new(vec!["p1.example.com".to_owned()]).expect("params");
        let cert = params.self_signed(&key()).expect("self-sign");
        assert_ne!(
            spki_sha256_of_certificate(cert.der()),
            Some(spki_sha256(&key()))
        );
    }

    /// rcgen leaves `CN=rcgen self signed cert` alone, and ACME order
    /// validation refuses any CN that is not also in the SAN — which is how
    /// every request on the Endpoint route was refused once already. The test
    /// is on the absence of the default rather than the presence of the
    /// hostname, because the hostname was in the SAN even when this was broken.
    #[test]
    fn the_request_does_not_carry_rcgens_default_subject() {
        let csr = certificate_request(&key(), "p10042.example.com").expect("build a request");
        assert!(
            csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
            "{csr}"
        );
        let der = pem_body(&csr);
        let text = String::from_utf8_lossy(&der);
        assert!(!text.contains("rcgen self signed cert"), "{text}");
    }

    /// The proxy holding a certificate for a key nobody has is the ordinary
    /// state on the first CSR request, and it must not read as "up to date".
    #[test]
    fn a_certificate_for_a_key_we_do_not_have_is_not_usable() {
        let mine = key();
        let params = CertificateParameters {
            hostname: "p1.example.com".to_owned(),
            domain: "example.com".to_owned(),
            port: 1,
            key_types: vec![KEY_TYPE.to_owned()],
            server_key_issuance: true,
            issue_quota: None,
            certificate: Some(HeldCertificate {
                spki_sha256: spki_sha256(&key()),
                not_after: String::new(),
            }),
        };
        assert!(!params.usable_with(&mine));
        assert!(params.accepts_p256());
    }

    /// An older proxy sends no `key_types`, and reading that silence as a
    /// refusal would stop a client that would otherwise work.
    #[test]
    fn an_unstated_key_type_list_is_not_a_refusal() {
        let params = CertificateParameters {
            hostname: String::new(),
            domain: String::new(),
            port: 0,
            key_types: Vec::new(),
            server_key_issuance: false,
            issue_quota: None,
            certificate: None,
        };
        assert!(params.accepts_p256());
    }

    /// A generated key is used again rather than replaced: a new one spends an
    /// issuance, and the same one is answered from the proxy's cache.
    #[test]
    fn a_key_is_generated_once_and_then_reused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("managed-tls.pem");
        let first = load_or_generate_key(&path).expect("generate");
        let second = load_or_generate_key(&path).expect("load");
        assert_eq!(spki_sha256(&first), spki_sha256(&second));
    }

    /// A key that is there but unreadable is a loud failure, not a reason to
    /// make a new one — replacing it would throw away what a certificate was
    /// issued against.
    #[test]
    fn an_unreadable_key_is_an_error_rather_than_a_fresh_start() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("managed-tls.pem");
        std::fs::write(&path, b"not a key").expect("write");
        assert!(load_or_generate_key(&path).is_err());
    }

    /// The key is `0600` from the moment it exists, not after a second step.
    #[cfg(unix)]
    #[test]
    fn a_generated_key_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("managed-tls.pem");
        load_or_generate_key(&path).expect("generate");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /// A key path with no directory component is the default for
    /// `masque-h3-server`. A temporary in the system temp directory cannot be
    /// renamed onto a different filesystem, so this is not a cosmetic detail:
    /// it is the difference between working and failing identically forever.
    #[test]
    fn a_key_path_with_no_directory_is_written_beside_the_cwd() {
        let dir = tempfile::tempdir().expect("temp dir");
        let previous = std::env::current_dir().expect("cwd");
        // Serialised against the other cwd-sensitive test by the lock below.
        let _guard = CWD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_current_dir(dir.path()).expect("chdir");
        let written = load_or_generate_key(Path::new("bare-key.pem"));
        std::env::set_current_dir(previous).expect("chdir back");
        written.expect("a bare path is written beside the cwd");
        assert!(dir.path().join("bare-key.pem").is_file());
    }

    /// A directory that is not there yet is made, rather than being an error
    /// that leaves the caller with no key.
    #[test]
    fn a_missing_directory_is_created() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("not").join("there").join("tls.pem");
        load_or_generate_key(&path).expect("generate");
        assert!(path.is_file());
    }

    /// The digest is taken from the certificate, so a chain for somebody else's
    /// key is refused whatever the response says beside it.
    #[test]
    fn the_leaf_of_a_chain_is_what_is_digested() {
        let key = key();
        let params = CertificateParams::new(vec!["p1.example.com".to_owned()]).expect("params");
        let cert = params.self_signed(&key).expect("self-sign");
        let leaf = leaf_der(&cert.pem()).expect("the leaf parses");
        assert_eq!(spki_sha256_of_certificate(&leaf), Some(spki_sha256(&key)));
    }

    /// Anything that is not a chain is a missing leaf rather than a panic.
    #[test]
    fn a_chain_with_no_certificate_has_no_leaf() {
        assert_eq!(leaf_der(""), None);
        assert_eq!(leaf_der("-----BEGIN CERTIFICATE-----\nnot base64!\n"), None);
    }

    static CWD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn pem_body(pem: &str) -> Vec<u8> {
        use base64::Engine as _;

        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("the request body is base64")
    }
}
