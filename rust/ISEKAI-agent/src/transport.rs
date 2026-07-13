//! msquic-based HTTP/3 transport for the proxy control plane (feature `msquic`).
//!
//! The proxy's P2P control-plane routes are HTTP/3-only, so this implements
//! [`ControlPlaneTransport`] over `channel-masque`'s [`H3Channel`] on msquic —
//! the same H3 stack the WebRTC `agent` uses, guaranteeing interop with the
//! msquic-served proxy. Header injection (Endpoint Token + PoP) is done by the
//! caller ([`crate::proxy::ProxyClient`]); this just performs the exchange.

use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use channel_masque::H3Channel;
use h3_util::msquic_async::H3MsQuicAsyncConnector;
use h3_util::msquic_async::h3_msquic_async::msquic;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use tower::{Service, ServiceExt};

use crate::proxy::{ControlPlaneTransport, HttpResponse};

/// An HTTP/3 control-plane transport to the MASQUE proxy.
#[derive(Clone)]
pub struct MasqueH3Transport {
    channel: H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
    uri: Uri,
}

impl MasqueH3Transport {
    /// Connect to the proxy at `target` (e.g. `https://proxy.isekai.link:8443`).
    pub fn connect(target: &str) -> anyhow::Result<Self> {
        let uri: Uri = target.parse().context("invalid proxy target URI")?;
        let (registration, config) = make_client_config(None, false)?;
        let (registration, config_qmux) = make_client_config(Some(registration), true)?;
        let connector =
            H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), registration);
        let channel = H3Channel::<_, Full<Bytes>>::new(connector, uri.clone(), None);
        Ok(Self { channel, uri })
    }
}

impl ControlPlaneTransport for MasqueH3Transport {
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> anyhow::Result<HttpResponse> {
        let uri = Uri::builder()
            .scheme(
                self.uri
                    .scheme()
                    .cloned()
                    .context("proxy URI has no scheme")?,
            )
            .authority(
                self.uri
                    .authority()
                    .cloned()
                    .context("proxy URI has no authority")?,
            )
            .path_and_query(path)
            .build()
            .context("failed to build request URI")?;

        let mut builder = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).context("invalid HTTP method")?)
            .uri(uri);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(body)))
            .context("failed to build request")?;

        // H3Channel is a cloneable, multiplexing tower Service.
        let mut channel = self.channel.clone();
        let response = channel
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("H3 channel not ready: {e}"))?
            .call(request)
            .await
            .map_err(|e| anyhow::anyhow!("H3 request failed: {e}"))?;

        let status = response.status().as_u16();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read response body: {e:?}"))?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

/// Build an msquic client registration + configuration (ALPN `h3` or `h3qx-01`
/// for qmux), mirroring the `agent` crate's client setup.
pub(crate) fn make_client_config(
    registration: Option<Arc<msquic::Registration>>,
    is_qmux: bool,
) -> anyhow::Result<(Arc<msquic::Registration>, Arc<msquic::Configuration>)> {
    let registration = match registration {
        Some(registration) => registration,
        None => Arc::new(msquic::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?),
    };
    let alpn = if is_qmux {
        [msquic::BufferRef::from("h3qx-01")]
    } else {
        [msquic::BufferRef::from("h3")]
    };
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;
    let mut credential = msquic::CredentialConfig::new_client();
    // Dev/testing only: accept a self-signed proxy certificate when the operator
    // explicitly opts in via `ISEKAI_INSECURE_SKIP_VERIFY`. Never set in prod.
    if std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_some() {
        tracing::warn!(
            "ISEKAI_INSECURE_SKIP_VERIFY set: skipping proxy TLS certificate validation"
        );
        credential = credential.set_credential_flags(
            msquic::CredentialFlags::CLIENT | msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION,
        );
    }
    configuration.load_credential(&credential)?;
    Ok((registration, Arc::new(configuration)))
}
