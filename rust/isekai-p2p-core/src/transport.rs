//! msquic-based HTTP/3 transport for the proxy control plane (feature `msquic`).
//!
//! The proxy's P2P control-plane routes are HTTP/3-only, so this implements
//! [`ControlPlaneTransport`] over `channel-masque`'s [`H3Channel`] on msquic —
//! the same H3 stack the WebRTC `agent` uses, guaranteeing interop with the
//! msquic-served proxy. Header injection (Endpoint Token + PoP) is done by the
//! caller ([`crate::proxy::ProxyClient`]); this just performs the exchange.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use channel_masque::H3Channel;
use h3_util::msquic_async::H3MsQuicAsyncConnector;
use h3_util::msquic_async::h3_msquic_async::{msquic, msquic_async};
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
            H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), false, registration);
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

/// The process-wide msquic registration.
///
/// One registration per process, so [`shutdown_msquic`] has a single thing to
/// drain: every connection the CLI opens (control plane, bind session, relay
/// leg) hangs off it, and `wait_idle()` only means "safe to close" if nothing
/// else is still running on a registration we forgot about.
///
/// The `Option` exists so `shutdown_msquic` can `take()` the last strong
/// reference and let `RegistrationClose` run at a point where we know it will
/// not block.
static REGISTRATION: Mutex<Option<Arc<msquic_async::Registration>>> = Mutex::new(None);

/// The shared registration, opening it on first use.
fn shared_registration() -> anyhow::Result<Arc<msquic_async::Registration>> {
    let mut slot = REGISTRATION.lock().expect("registration mutex poisoned");
    if let Some(registration) = slot.as_ref() {
        return Ok(registration.clone());
    }
    let registration = Arc::new(msquic_async::Registration::new(
        &msquic::RegistrationConfig::default(),
    )?);
    *slot = Some(registration.clone());
    Ok(registration)
}

/// Shut the msquic registration down and wait until every connection and stream
/// derived from it has been closed. Returns `false` if `timeout` elapsed first.
///
/// Call this once, after everything holding an msquic handle has been dropped
/// and before leaving `main`. `shutdown()` asks the connections to go away,
/// which ends the background h3 drivers holding them; `wait_idle()` then
/// resolves once the last handle is closed, which is exactly the condition
/// under which `RegistrationClose` returns promptly instead of blocking in
/// `CxPlatRundownReleaseAndWait`.
///
/// On timeout the registration is deliberately **leaked** rather than dropped:
/// something still holds a handle, so `RegistrationClose` would block forever,
/// and the caller is expected to fall back to a hard exit.
/// Drain the registration without closing it, for a caller that is about to
/// leave the process without running destructors.
///
/// [`shutdown_msquic`] drops the registration once it drains, which runs
/// `RegistrationClose`. That is still a *blocking* call, and `wait_idle()` does
/// not cover application-owned client `Configuration`s — one outstanding
/// anywhere and the close waits on its rundown reference, uninterruptibly and
/// after the timeout has already been satisfied. On an exit path there is
/// nothing to gain from closing, so this never does.
///
/// Returns whether every connection and listener closed within `timeout`.
pub async fn drain_msquic(timeout: Duration) -> bool {
    let registration = REGISTRATION
        .lock()
        .expect("registration mutex poisoned")
        .take();
    let Some(registration) = registration else {
        // No msquic work happened this run.
        return true;
    };
    registration.shutdown();
    let drained = tokio::time::timeout(timeout, registration.wait_idle())
        .await
        .is_ok();
    if !drained {
        tracing::warn!(?timeout, "msquic registration still has live handles");
    }
    std::mem::forget(registration);
    drained
}

pub async fn shutdown_msquic(timeout: Duration) -> bool {
    let registration = REGISTRATION
        .lock()
        .expect("registration mutex poisoned")
        .take();
    let Some(registration) = registration else {
        // No msquic work happened this run (e.g. `keygen`).
        return true;
    };
    registration.shutdown();
    match tokio::time::timeout(timeout, registration.wait_idle()).await {
        Ok(()) => {
            // Last strong reference, so this runs RegistrationClose, which now
            // has nothing left to wait for.
            drop(registration);
            true
        }
        Err(_) => {
            tracing::warn!(
                ?timeout,
                "msquic registration still has live handles; skipping RegistrationClose"
            );
            std::mem::forget(registration);
            false
        }
    }
}

/// Build an msquic client registration + configuration (ALPN `h3` or `h3qx-01`
/// for qmux), mirroring the `agent` crate's client setup.
///
/// The returned [`msquic::Configuration`] is intentionally *not* tracked by
/// `wait_idle()` (a configuration's rundown reference outlives
/// `ConfigurationClose`), so callers must drop it before the registration —
/// which they do, since the connector owning it is dropped well before
/// [`shutdown_msquic`] runs.
pub(crate) fn make_client_config(
    registration: Option<Arc<msquic_async::Registration>>,
    is_qmux: bool,
) -> anyhow::Result<(Arc<msquic_async::Registration>, Arc<msquic::Configuration>)> {
    let registration = match registration {
        Some(registration) => registration,
        None => shared_registration()?,
    };
    let alpn = if is_qmux {
        [msquic::BufferRef::from("h3qx-01")]
    } else {
        [msquic::BufferRef::from("h3")]
    };
    let configuration = registration.open_configuration(
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                // Pin this connection's MTU to the standard ~1500-byte network
                // path so it can carry a *relayed* inner QUIC packet from the
                // very first datagram. A tunneled QUIC Initial is padded to 1200
                // bytes (RFC 9000 §14.1); at msquic's default MinimumMtu (1248)
                // the outer connection's max-datagram length (~1206) is just
                // under 1200 + CONNECT-UDP encapsulation, so the first relayed
                // packet is dropped `TooLarge` before DPLPMTUD probes upward.
                // (On loopback the MTU is effectively unbounded, so this only
                // bites off-loopback.) Raising the floor to 1400 clears the
                // encapsulated Initial immediately while keeping the outer IP
                // packet within a standard 1500-MTU path. Deliberate trade-off:
                // the relay data path therefore assumes a normal ~1500-MTU
                // network and does not support constrained sub-1400 paths
                // (e.g. a 1280-MTU tunnel), where a nested 1200-byte QUIC
                // handshake cannot fit a datagram anyway.
                .set_MinimumMtu(1400)
                .set_MaximumMtu(1500)
                .set_StreamMultiReceiveEnabled()
                // Ask the proxy to report the address it observes this
                // connection at. On a relay leg that report is how the Endpoint
                // learns its own NAT mapping, which the video connection then
                // names as a direct-path candidate
                // (docs/p2p_mode_migration_plan.md §2.2.3). Harmless on the
                // control-plane connections, which simply never look at it.
                .set_ReceiveObservedAddressReports(),
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
