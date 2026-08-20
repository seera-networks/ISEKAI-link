//! Opening the P2P session, both ways.
//!
//! **Phase 1c-iii-c-ii of `docs/portal_plan.md` §4.4**, and the last thing
//! phase 0 said it did not do. Everything under here is `isekai_p2p`: the
//! session types, the loop that drives the listener's, the certificate it
//! presents, and the dial. What is left in this file is the wiring — which is
//! all that should be left, since the camera does the same thing and the two
//! now differ only in what the connection carries.
//!
//! ```text
//!   portal-client                proxy                 portal-server
//!   InitiatorSession  ── peer connect ──▶  ListenerSession
//!        │                                       │
//!        └── QUIC over the relay leg ────────────┘
//!            (transport::connect)          (transport::bind + server::serve)
//! ```
//!
//! # The manual exchange
//!
//! The proxy will not let two Endpoints talk until a Grant says so, and nothing
//! here invents one. As with the camera (spec §13):
//!
//! 1. the client reveals its **Endpoint ID**;
//! 2. the server issues a **capability** for it and reveals its **listener id**;
//! 3. the client connects with both.
//!
//! Under [`AcceptPolicy::AutoNotify`] the last step is where it ends — the
//! listener binds whatever the proxy says is waiting, so nobody carries a
//! connection id across. That is the difference from the camera server, which
//! is `Manual` because an operator is watching a GUI.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context as _;
use isekai_p2p::agent::RelayOptions;
use isekai_p2p::endpoint_cert;
use isekai_p2p::listener::{run, ListenerCommand};
use isekai_p2p::peer::{AttestedPeer, PeerSession};
use isekai_p2p::{
    issue_endpoint_token, proxy_client, AcceptPolicy, InitiatorSession, ListenerSession, P2pConfig,
    SignalingEvent,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::server::Catalogue;
use crate::transport;

/// What the operator conveys to the client once the server is up.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    /// The private Peer Listener's id. Goes to the client.
    pub listener_id: String,
    /// This Endpoint's id, for the client's own records.
    pub endpoint_id: String,
    /// The loopback address the relay forwards to. Diagnostics only.
    pub portal_addr: SocketAddr,
}

/// A running portal server.
pub struct ServerHandle {
    /// What to tell the client.
    pub info: ServerInfo,
    commands: mpsc::Sender<ListenerCommand>,
    /// Bindings and departures, for anything that wants to report them.
    pub signaling: broadcast::Sender<SignalingEvent>,
}

impl ServerHandle {
    /// Mint a capability the named Endpoint can connect with.
    ///
    /// The one thing the client cannot get for itself: a Grant is what the
    /// proxy checks, and only this Endpoint can ask for one on its listener.
    pub async fn issue_capability(
        &self,
        allowed_endpoint: &str,
        ttl: Option<u64>,
    ) -> anyhow::Result<String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(ListenerCommand::IssueCapability {
                allowed_endpoint: allowed_endpoint.to_owned(),
                ttl,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("the listener session has stopped"))?;
        answer
            .await
            .map_err(|_| anyhow::anyhow!("the listener session dropped the request"))?
    }
}

/// Stand a portal server up: a listener the relay forwards to, and a session
/// that tells the proxy about it.
///
/// `cert_key_path` is where this device's certificate key lives. It is
/// generated on first use and reused after that — a new one spends an issuance
/// slot and invalidates any pinning built on the old one.
///
/// Runs until `shutdown`.
pub async fn serve(
    cfg: P2pConfig,
    cert_key_path: &Path,
    catalogue: Catalogue,
    policy: AcceptPolicy,
    shutdown: CancellationToken,
) -> anyhow::Result<ServerHandle> {
    // Issued once and reused for both the certificate and the session, so
    // standing up costs one Identity round trip rather than two.
    let endpoint_token = issue_endpoint_token(&cfg).await?.endpoint_token;

    // The key stays here and the request goes out; `None` means the proxy
    // issues nothing, and then the listener presents a development certificate
    // and the client dials without validating it.
    let cert_key = endpoint_cert::load_or_generate_cert_key(cert_key_path)?;
    let proxy = proxy_client(&cfg, &endpoint_token)?;
    let cert = endpoint_cert::issue(&proxy, &cfg.key, &cert_key).await?;
    if cert.is_none() {
        tracing::warn!("proxy issues no relay certificate; using a development one");
    }

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
    let (reg, listener, portal_addr) = transport::bind(None, bind_addr, cert.as_ref())?;

    // On the *same* registration as the listener, and on a shared unconnected
    // socket: msquic looks bindings up per registration, so a leg on another
    // one could never be shared with the accepted connections, and a direct
    // path is opened from this leg's binding
    // (`docs/p2p_mode_migration_plan.md` §2.2.3, §2.4).
    let session = ListenerSession::create_with_token_and_options(
        &cfg,
        &endpoint_token,
        portal_addr,
        None,
        RelayOptions {
            unconnected: true,
            registration: Some(reg.clone()),
        },
    )
    .await?;
    let info = ServerInfo {
        listener_id: session.listener_id.clone(),
        endpoint_id: session.endpoint_id.clone(),
        portal_addr,
    };

    let accepting = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accepting.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok(conn) => {
                        let catalogue = catalogue.clone();
                        // One task per peer: a forward that stalls must not
                        // stop the next peer being accepted.
                        tokio::spawn(async move {
                            if let Err(e) = crate::server::serve(conn, catalogue).await {
                                tracing::warn!("portal connection ended: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("portal accept failed: {e}");
                        break;
                    }
                },
            }
        }
    });

    let (commands, cmd_rx) = mpsc::channel(8);
    let (signaling, _) = broadcast::channel(32);
    tokio::spawn(run(session, cmd_rx, policy, signaling.clone(), shutdown));

    Ok(ServerHandle {
        info,
        commands,
        signaling,
    })
}

/// What a connected client holds.
///
/// The session outlives the connection deliberately: it is what holds the relay
/// leg open, and dropping it takes the QUIC down with it.
pub struct Connected {
    /// The relay session. Keep it; [`close`](Self::close) is how it ends.
    pub session: InitiatorSession,
    /// The peer connection the forwards run over.
    pub peer: PeerSession,
}

impl Connected {
    /// Report the connection closed and take the relay leg down.
    ///
    /// Worth doing rather than dropping: the listener finds who is waiting by
    /// listing connections in state `relay`, so one nobody reports occupies its
    /// leg until the proxy expires it.
    pub async fn close(self) {
        let Self { session, peer } = self;
        // The QUIC first: it rides the leg the session is about to remove.
        drop(peer);
        session.close().await;
    }
}

/// Connect to a portal server and open the peer QUIC to it.
///
/// `capability` and `listener_id` are what the server's operator hands over;
/// [`ServerHandle::issue_capability`] is where the first comes from.
pub async fn connect(
    cfg: &P2pConfig,
    capability: &str,
    listener_id: &str,
    shutdown: &CancellationToken,
) -> anyhow::Result<Connected> {
    let session = InitiatorSession::connect_with_options(
        cfg,
        capability,
        listener_id,
        &[],
        "127.0.0.1:0".parse().expect("valid loopback addr"),
        RelayOptions {
            unconnected: true,
            registration: None,
        },
    )
    .await
    .context("peer connect")?;

    // A *name*, never an address: it is the per-endpoint FQDN the peer's relay
    // certificate is issued for, and its only DNS record points back at
    // loopback. `None` means the proxy has relay certificates disabled, and
    // then there is nothing to validate against.
    let (host, verify) = match session.video_host() {
        Some(host) => (host.to_owned(), true),
        None => ("127.0.0.1".to_owned(), false),
    };

    // What the peer signed about its own key, if it has said anything. Absent
    // is ordinary and changes nothing; present means the handshake has to
    // produce that key (spec §8.6.5).
    let pin = match AttestedPeer::from_connection(&session.connection) {
        Ok(pin) => {
            tracing::info!(
                peer = %pin.peer_endpoint,
                "the peer signed for its portal key; the handshake has to present it",
            );
            Some(pin)
        }
        Err(why) => {
            tracing::info!("{why}");
            None
        }
    };

    // Resolved before the dial: a candidate has to be offered before `start`,
    // and the handshake can take a long time by design, so there is no useful
    // "add it later".
    let candidate = wait_for_observed(&session, shutdown).await;

    let peer = transport::connect(
        None,
        &host,
        session.local_addr.port(),
        transport::ConnectOptions {
            verify,
            pin,
            candidate,
        },
        shutdown,
    )
    .await?;

    Ok(Connected { session, peer })
}

/// Wait briefly for the relay leg's observed address.
///
/// `None` means carry on relay-only: a missing report costs a direct path, not
/// the forwarding, and blocking on it would be the wrong trade.
async fn wait_for_observed(
    session: &InitiatorSession,
    shutdown: &CancellationToken,
) -> Option<isekai_p2p::agent::ObservedAddress> {
    let mut watch = session.observed_address();
    if let Some(address) = *watch.borrow_and_update() {
        return Some(address);
    }
    let waited = tokio::time::timeout(OBSERVED_ADDRESS_WAIT, async {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return None,
                changed = watch.changed() => {
                    changed.ok()?;
                    if let Some(address) = *watch.borrow_and_update() {
                        return Some(address);
                    }
                }
            }
        }
    })
    .await;
    match waited {
        Ok(address) => address,
        Err(_) => {
            tracing::warn!(
                "no observed address from the relay leg within {OBSERVED_ADDRESS_WAIT:?}; \
                 forwarding over the relay without a direct-path candidate",
            );
            None
        }
    }
}

/// How long to wait for the relay leg's observed address before dialing without
/// it. The report normally lands within a round trip of the leg coming up; if it
/// does not, forwarding over the relay matters more than a direct path.
const OBSERVED_ADDRESS_WAIT: std::time::Duration = std::time::Duration::from_secs(3);
