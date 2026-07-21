//! Shared configuration and Endpoint Token acquisition.
//!
//! A [`P2pConfig`] says how to reach the Identity API and the proxy, which Auth0
//! token authenticates to the Identity API, and which Endpoint key to prove
//! possession of. [`issue_endpoint_token`] turns that into an Endpoint Token,
//! which the session facades then use for the proxy control plane and relay
//! data path.

use std::path::Path;

use anyhow::Context as _;
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{EndpointToken, IdentityClient};
use isekai_p2p_core::proxy::ControlPlaneTransport;
use isekai_p2p_core::transport::MasqueH3Transport;

/// Everything a P2P session needs to reach the services and identify itself.
pub struct P2pConfig {
    /// Identity API base URL (HTTPS), e.g. `https://identity.isekai.link:8443`.
    pub identity_url: String,
    /// Reach the Identity API over HTTP/3 (QUIC) instead of HTTP/1.1 + HTTP/2.
    pub identity_http3: bool,
    /// Proxy base URL, e.g. `https://proxy.isekai.link:8443`.
    pub proxy_url: String,
    /// Auth0 access token — used **only** to obtain the Endpoint Token from the
    /// Identity API. It is never sent to the proxy.
    pub auth0_token: String,
    /// P2P protocol string, e.g. `isekai-validator-v1`.
    pub protocol: String,
    /// Register the Endpoint before issuing a token (needed on first use of a
    /// freshly generated key).
    pub register: bool,
    /// Device display name recorded at registration.
    pub device_name: Option<String>,
    /// Requested Endpoint Token TTL, in seconds (`None` = server default).
    pub token_ttl: Option<i64>,
    /// The Endpoint keypair, proven on every proxy request via PoP.
    pub key: EndpointKey,
}

impl P2pConfig {
    /// This Endpoint's ID (`ep:...`), derived from [`P2pConfig::key`].
    pub fn endpoint_id(&self) -> String {
        self.key.endpoint_id()
    }
}

/// Load a PKCS#8 PEM Endpoint key from `path`, generating and persisting one on
/// first use.
///
/// A generated key is written with owner-only (`0600`) permissions on Unix — it
/// is long-lived material that must never leave the Endpoint.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<EndpointKey> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read Endpoint key at {}", path.display()))?;
        return EndpointKey::from_pkcs8_pem(&pem).map_err(anyhow::Error::from);
    }
    let key = EndpointKey::generate();
    let pem = key.to_pkcs8_pem()?;
    write_private(path, &pem)?;
    Ok(key)
}

/// Register (when [`P2pConfig::register`] is set) and issue an Endpoint Token,
/// over whichever Identity API transport the config selects.
pub async fn issue_endpoint_token(cfg: &P2pConfig) -> anyhow::Result<EndpointToken> {
    // The Identity API serves h1/h2 on TCP+TLS and h3 on QUIC at the same port;
    // pick one. The two branches build different concrete transports, so the
    // register/issue work is shared via the generic `issue`.
    if cfg.identity_http3 {
        let client = IdentityClient::new(MasqueH3Transport::connect(&cfg.identity_url)?);
        issue(&client, cfg).await
    } else {
        let client = IdentityClient::new(HttpsTransport::connect(&cfg.identity_url)?);
        issue(&client, cfg).await
    }
}

async fn issue<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
) -> anyhow::Result<EndpointToken> {
    let token = if cfg.register {
        client
            .register_and_issue(
                &cfg.auth0_token,
                &cfg.key,
                cfg.device_name.as_deref(),
                cfg.token_ttl,
            )
            .await?
    } else {
        client
            .issue_token(&cfg.auth0_token, &cfg.key, None, None, cfg.token_ttl)
            .await?
    };
    Ok(token)
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write key at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_generate_key_persists_then_reloads_the_same_key() {
        let path = std::env::temp_dir().join(format!("isekai-p2p-key-{}.pem", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // First call generates and persists.
        let generated = load_or_generate_key(&path).expect("generate");
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
        }

        // Second call reloads the identical key (same Endpoint ID).
        let reloaded = load_or_generate_key(&path).expect("reload");
        assert_eq!(generated.endpoint_id(), reloaded.endpoint_id());

        std::fs::remove_file(&path).unwrap();
    }
}
