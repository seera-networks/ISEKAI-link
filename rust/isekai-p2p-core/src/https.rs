//! HTTPS transport over TCP — HTTP/1.1 and HTTP/2, negotiated by ALPN.
//!
//! The Identity API serves h1/h2 on TCP+TLS and h3 on QUIC at the same port,
//! advertising the latter with `Alt-Svc`. This is the TCP half; the QUIC half is
//! [`crate::transport::MasqueH3Transport`], which needs the `msquic` feature.
//! Both implement [`ControlPlaneTransport`], so the Identity client works over
//! either.

use anyhow::Context as _;

use crate::proxy::{ControlPlaneTransport, HttpResponse};

/// An HTTP/1.1 + HTTP/2 transport to an HTTPS service at a fixed base URL.
#[derive(Debug, Clone)]
pub struct HttpsTransport {
    base_url: String,
    http: reqwest::Client,
}

impl HttpsTransport {
    /// Build a transport for the service at `base_url`
    /// (e.g. `https://identity.isekai.tools:9443`).
    ///
    /// Honors `ISEKAI_INSECURE_SKIP_VERIFY` the same way the msquic transport
    /// does, so a development server with a self-signed certificate (`DEV_CERT`)
    /// can be reached with one opt-in for both transports.
    pub fn connect(base_url: &str) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder();
        if std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_some() {
            tracing::warn!(
                "ISEKAI_INSECURE_SKIP_VERIFY set: skipping Identity API TLS certificate validation"
            );
            builder = builder.danger_accept_invalid_certs(true);
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http: builder
                .build()
                .context("failed to build the HTTPS client")?,
        })
    }
}

impl ControlPlaneTransport for HttpsTransport {
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> anyhow::Result<HttpResponse> {
        let method: reqwest::Method = method.parse().context("invalid HTTP method")?;
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .body(body);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let resp = req.send().await.context("HTTPS request failed")?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .context("failed to read the response body")?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}
