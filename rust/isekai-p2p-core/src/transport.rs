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
    /// Build one request against the proxy, shared by the buffered and the
    /// streaming paths so they cannot address it differently.
    fn build_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> anyhow::Result<Request<Full<Bytes>>> {
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
        builder
            .body(Full::new(Bytes::from(body)))
            .context("failed to build request")
    }

    /// Connect to the proxy at `target` (e.g. `https://proxy.isekai.link:8443`).
    pub fn connect(target: &str) -> anyhow::Result<Self> {
        let uri: Uri = target.parse().context("invalid proxy target URI")?;
        let (registration, config) = make_client_config(None, false)?;
        let (registration, config_qmux) = make_client_config(Some(registration), true)?;
        let connector = H3MsQuicAsyncConnector::new(
            uri.clone(),
            config,
            Some(config_qmux),
            false,
            registration,
        );
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
        let request = self.build_request(method, path, headers, body)?;

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

impl crate::proxy::EventStreamTransport for MasqueH3Transport {
    async fn open_stream(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> anyhow::Result<(u16, tokio::sync::mpsc::Receiver<anyhow::Result<Vec<u8>>>)> {
        let request = self.build_request(method, path, headers, Vec::new())?;
        let mut channel = self.channel.clone();
        let response = channel
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("H3 channel not ready: {e}"))?
            .call(request)
            .await
            .map_err(|e| anyhow::anyhow!("H3 request failed: {e}"))?;
        let status = response.status().as_u16();

        // One chunk at a time. A depth of one is deliberate: the reader is a
        // listener reacting to each event, and buffering ahead of it would only
        // hide that it had stopped keeping up.
        let (chunks, receiver) = tokio::sync::mpsc::channel(1);
        let mut body = response.into_body();
        tokio::spawn(async move {
            loop {
                let frame = match body.frame().await {
                    Some(Ok(frame)) => frame,
                    Some(Err(e)) => {
                        let _ = chunks.send(Err(anyhow::anyhow!("{e:?}"))).await;
                        return;
                    }
                    // The response ended. Dropping the sender is how the reader
                    // finds out, and it means the same thing either way: the
                    // stream is over and it is time to reconnect.
                    None => return,
                };
                // Trailers carry nothing this stream uses.
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                if chunks.send(Ok(data.to_vec())).await.is_err() {
                    // Nobody is reading any more, so stop pulling the body —
                    // which also ends the request.
                    return;
                }
            }
        });
        Ok((status, receiver))
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
                // Keep the connection from going idle into that timeout.
                //
                // Without it, whether one of these survives depends on the
                // caller happening to send something every thirty seconds —
                // a control-plane client between requests, or a relay leg
                // whose peer has gone quiet, has no such guarantee. Ten
                // seconds leaves two attempts inside the timeout.
                //
                // This is the *connection* keepalive and not
                // `PathKeepAliveIntervalMs`: it is re-armed by any activity
                // anywhere on the connection, so it fires only when the whole
                // thing is quiet, which is exactly the case being covered.
                // Keeping an idle *path* warm is a different setting and a
                // different problem (see `camera-core`'s video connection).
                .set_KeepAliveIntervalMs(10_000)
                // `DestCidUpdateIdleTimeoutMs` is left at its default, and its
                // absence is a decision rather than an omission.
                //
                // Every configuration in this repository used to pin it to 0,
                // switching off the destination CID rotation to work around an
                // msquic defect. That defect is fixed, so none of them does now.
                //
                // **This does not get the rotation back, and is not meant to.**
                // The gate is 20 s since the last flush (`send.c`), and the
                // keepalive above flushes every 10, so on any connection
                // configured like this one it will not fire. What the removal
                // achieves is that a workaround whose reason is gone stops
                // being carried — and stops being copied into the next
                // configuration somebody writes. Wanting the rotation to
                // actually happen would mean settling the keepalive interval
                // against that 20 s, which is a different question.
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                // Floor this connection's MTU high enough to carry a *relayed*
                // inner QUIC packet in one datagram, from the very first one.
                //
                // The arithmetic, because the number matters and the failure is
                // silent. The inner video connection cannot go below 1248:
                // msquic clamps `MaximumMtu` up to QUIC_DPLPMTUD_MIN_MTU
                // (`core/settings.c`), so a full inner packet is 1248 bytes and
                // there is no way to ask for less. As a CONNECT-UDP payload
                // that is 1248 + 1 context-id byte, and the HTTP datagram
                // carrying it prefixes a quarter-stream-id varint — so about
                // 1250 goes on the wire. That varint is one byte because a
                // relay leg opens an H3 connection of its own and CONNECT-UDP
                // is its first request stream; a quarter stream id needs two
                // bytes only past 63, which is stream id 255. A caller that
                // kept opening requests on one connection would cross that,
                // and would owe this sum another byte. This connection's max-datagram length
                // runs about 42 bytes under its MTU. So the floor has to be at
                // least ~1292; anything lower and **every** full-size inner
                // packet fails to send and is dropped, while
                // ACKs and control packets still fit — which looks like a lossy
                // path rather than a misconfigured one.
                //
                // 1350 clears that with room for a longer connection ID, and is
                // as low as it can usefully go. It was 1400, which is more than
                // needed and excludes networks that carry 1360 but not 1400 —
                // one such network is what turned this up. Paths below ~1300
                // remain unsupported: the inner connection has a hard 1248-byte
                // floor, so there is nothing left to give.
                .set_MinimumMtu(1350)
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
    // **`USE_TLS_BUILTIN_CERTIFICATE_VALIDATION` is deliberately not set here.**
    // It was, briefly, and it is wrong on three of the four platforms:
    //
    // * Windows builds msquic with schannel (`CMakeLists.txt`), and
    //   `tls_schannel.c` answers `QUIC_STATUS_INVALID_PARAMETER` to any
    //   credential carrying this flag -- so `load_credential` fails and *every*
    //   client connection stops being possible, insecure escape hatch included.
    // * Linux and Android are `CX_PLATFORM_LINUX`, where `tls_quictls.c` ORs
    //   the flag in itself. Setting it changes nothing.
    // * Darwin is the one platform where it does something, and what it does is
    //   a regression: it replaces msquic's `CxPlatCertVerifyRawCertificate`
    //   (SecTrust, with the dialed name) with a bare `X509_verify_cert` against
    //   `SSL_CTX_set_default_verify_paths()` -- an empty store on iOS.
    //
    // What Android actually needed is below: a CA file, because it has no
    // system PEM for the default paths to find.
    let mut credential = msquic::CredentialConfig::new_client();
    // Android ships no system PEM file, so the default verify paths find
    // nothing; the app copies a bundle out of its assets and points
    // `SSL_CERT_FILE` at it. Setting `CaCertificateFile` drives
    // `SSL_CTX_load_verify_locations()` directly rather than depending on the
    // environment variable being honoured by this quictls build.
    //
    // An unset variable leaves the platform's own defaults alone, which is what
    // every other platform wants. An empty one is ignored rather than passed
    // on: `load_verify_locations` failing is fatal to the whole credential.
    if let Some(ca_file) = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| !p.is_empty())
    {
        credential = credential.set_ca_certificate_file(ca_file);
    }
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
