//! The peer QUIC connection the forwarding rides on.
//!
//! **This replaces `spike.rs`** (plan §4.4, phase 1c-iii-b). What was there was
//! a hand-rolled configuration and a dialer that validated nothing — scaffolding
//! written before the connection layer existed, and the first thing phase 1 said
//! it would delete. Both halves are `isekai_p2p::peer` now, so portal gets the
//! MTU cap sized to the relay tunnel, both keepalives, the fifteen-minute
//! handshake that rides across the peer's bind gap, the certificate check, and
//! the teardown rules — rather than a second, worse copy of each.
//!
//! What is still missing is the session that puts a proxy in front of this:
//! `ListenerSession` on one side, `InitiatorSession` on the other, and a Grant
//! saying the two Endpoints may talk. That is 1c-iii-c, and until it lands the
//! only thing that calls this is the loopback test.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use isekai_p2p::agent::ObservedAddress;
use isekai_p2p::endpoint_cert::{dev_cert, EndpointCert};
use isekai_p2p::peer::{dial, AttestedPeer, DialOptions, PeerSession};
use msquic_async::{Listener, Registration};
use tokio_util::sync::CancellationToken;

use crate::PORTAL_ALPN;

/// Bind a portal listener on `addr`.
///
/// With `cert` — this Endpoint's relay certificate — the listener presents it
/// and the initiator can validate the name it dialled. Without one it falls
/// back to a self-signed development certificate, and the initiator has to dial
/// with validation off.
///
/// The twin of `camera_core::video::bind_video_listener`, differing by the
/// ALPN. What the two share is already shared: the settings, the credential
/// loading and the Windows PKCS#12 branch are
/// [`isekai_link_utils::make_msquic_async_listener_with`], and the certificate
/// is [`isekai_p2p::endpoint_cert`]. Neither of those can hold this wrapper —
/// it needs both crates and they are siblings — so it stays with each caller
/// until something above them wants it too.
pub fn bind(
    reg: Option<Arc<Registration>>,
    addr: SocketAddr,
    cert: Option<&EndpointCert>,
) -> anyhow::Result<(Arc<Registration>, Listener, SocketAddr)> {
    let (cert_pem, key_pem, pkcs12) = match cert {
        Some(bundle) => (
            bundle.cert_pem.clone(),
            bundle.key_pem.clone(),
            bundle.pkcs12.clone(),
        ),
        None => {
            // On Windows the PKCS#12 bundle is what makes the development
            // certificate usable at all; elsewhere it is `None` and the PEM
            // path is taken. See `isekai_p2p::endpoint_cert`.
            //
            // **`spike.rs` had no bundle**, which is why portal's tests were
            // asked to run on Linux only.
            let dev = dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
            (dev.cert_pem, dev.key_pem, dev.pkcs12)
        }
    };
    let (reg, listener) = isekai_link_utils::make_msquic_async_listener_with(
        reg,
        PORTAL_ALPN,
        Some(addr),
        &cert_pem,
        &key_pem,
        pkcs12.as_deref(),
        isekai_link_utils::ListenerOptions {
            // Offered unconditionally, as the camera's listener does: a peer
            // that does not offer it back gets the connection it would have got
            // anyway.
            multipath: true,
        },
    )?;
    let local = listener
        .local_addr()
        .context("read the portal listener's local address")?;
    Ok((reg, listener, local))
}

/// What [`connect`] needs beyond the address.
///
/// The three things a session knows and a loopback test does not.
#[derive(Default)]
pub struct ConnectOptions {
    /// Validate the peer's certificate chain, and hold it against the host.
    ///
    /// Off is dev-only, and then there is nothing to check the certificate
    /// against. The loopback test uses it because the listener there presents
    /// the self-signed fallback; over a proxy it is on whenever the proxy names
    /// a host to dial.
    pub verify: bool,
    /// What the peer signed for about its own key, from the connect response.
    ///
    /// `None` is ordinary while this is being adopted and leaves the connection
    /// on name validation alone.
    pub pin: Option<AttestedPeer>,
    /// How the proxy sees this session's relay leg. `Some` offers it as a
    /// direct-path candidate and turns migration on.
    pub candidate: Option<ObservedAddress>,
}

/// Dial a portal listener.
///
/// `host` is a **name**, never an address to resolve — [`dial`] says why at
/// length, and the whole of it applies here: over a proxy this dials the local
/// relay bridge on loopback and the name is only ever what the certificate is
/// held against.
pub async fn connect(
    reg: Option<Arc<Registration>>,
    host: &str,
    port: u16,
    opts: ConnectOptions,
    shutdown: &CancellationToken,
) -> anyhow::Result<PeerSession> {
    let ConnectOptions {
        verify,
        pin,
        candidate,
    } = opts;
    dial(
        reg,
        DialOptions {
            alpn: PORTAL_ALPN,
            host,
            port,
            verify,
            pin,
            candidate,
            // **Both directions or neither.** This advertises that we will
            // receive datagrams, which is what lets the *server* answer a UDP
            // forward at all -- without it every reply is denied at zero bytes.
            datagrams: true,
        },
        shutdown,
    )
    .await
}
