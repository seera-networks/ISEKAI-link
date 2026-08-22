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
//! # Being allowed to connect
//!
//! The proxy will not let two Endpoints talk until this listener has authorised
//! them, and there are two ways it can have — see [`Reach`]. Pairing is the one
//! an installation runs on: a code is carried once, and the Grant it makes is
//! reusable and outlives the listener it was made against.
//!
//! Under [`AcceptPolicy::AutoNotify`] that is the end of it — the listener binds
//! whatever the proxy says is waiting, so nobody carries a connection id across.
//! That is the difference from the camera server, which is `Manual` because an
//! operator is watching a GUI.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use isekai_p2p::agent::RelayOptions;
use isekai_p2p::agent::{Grant, PairingCode, ReachableListener};
use isekai_p2p::direct_path::{self, RelayLegs};
use isekai_p2p::endpoint_cert;
use isekai_p2p::listener::{run, ListenerCommand};
use isekai_p2p::peer::{AttestedPeer, PeerSession};
use isekai_p2p::{
    issue_endpoint_token, proxy_client, AcceptPolicy, InitiatorSession, ListenerSession, P2pConfig,
    PeerDirectory, SignalingEvent,
};
use msquic_async::{msquic, Registration};
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
///
/// Holds what leaving needs: the task driving the session, so [`close`] can
/// wait for it to withdraw the Peer Listener, and the registration, so nothing
/// else drops the last reference to it while a `Listener` is still open.
///
/// [`close`]: Self::close
pub struct ServerHandle {
    /// What to tell the client.
    pub info: ServerInfo,
    commands: mpsc::Sender<ListenerCommand>,
    /// Bindings and departures, for anything that wants to report them.
    pub signaling: broadcast::Sender<SignalingEvent>,
    running: tokio::task::JoinHandle<()>,
    shutdown: CancellationToken,
    reg: Arc<Registration>,
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

    /// Mint a pairing code to show whoever should be let in.
    ///
    /// **This is the one to reach for**, and [`issue_capability`] is the
    /// exception. What a redeemed code makes is a Grant, which is reusable and
    /// whose key has no listener in it (spec §8.8) — so the peer reconnects
    /// without asking again, and keeps working when this server restarts onto a
    /// new listener id. A capability does neither.
    ///
    /// The code lasts 60..=300 seconds and replaces whatever this listener had:
    /// there is at most one live code per (Endpoint, protocol), so asking again
    /// is how you replace one nobody used rather than how you accumulate them.
    ///
    /// [`issue_capability`]: Self::issue_capability
    pub async fn show_pairing_code(&self, ttl: Option<u64>) -> anyhow::Result<PairingCode> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(ListenerCommand::ShowPairingCode { ttl, reply })
            .await
            .map_err(|_| anyhow::anyhow!("the listener session has stopped"))?;
        answer
            .await
            .map_err(|_| anyhow::anyhow!("the listener session dropped the request"))?
    }

    /// Who may reach this Endpoint, and since when.
    ///
    /// Grants outlive listeners, so this is the only place the answer exists:
    /// nothing about a running server says who paired with it three restarts
    /// ago.
    pub async fn grants(&self) -> anyhow::Result<Vec<Grant>> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(ListenerCommand::ListGrants { reply })
            .await
            .map_err(|_| anyhow::anyhow!("the listener session has stopped"))?;
        answer
            .await
            .map_err(|_| anyhow::anyhow!("the listener session dropped the request"))?
    }

    /// Take a grant away.
    ///
    /// **The counterpart [`show_pairing_code`] needs to exist.** A permission
    /// that stands until revoked, with no way to revoke it, is worse than one
    /// that expires — and a Grant surviving restarts means there is no
    /// accidental expiry to fall back on.
    ///
    /// [`show_pairing_code`]: Self::show_pairing_code
    pub async fn revoke_grant(&self, grant_id: &str) -> anyhow::Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(ListenerCommand::RevokeGrant {
                grant_id: grant_id.to_owned(),
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("the listener session has stopped"))?;
        answer
            .await
            .map_err(|_| anyhow::anyhow!("the listener session dropped the request"))?
    }

    /// Stop, withdraw the Peer Listener, and wait for msquic.
    ///
    /// **Cancelling is not leaving.** `listener::run` withdraws the listener on
    /// its way out, and a process that cancels and returns immediately drops
    /// the runtime first — so the listener is never withdrawn and lingers for
    /// its whole lease, with anyone who tries to reach it connecting to
    /// nothing. Waiting for the task is what makes the difference.
    ///
    /// Then the drain, for the reason [`Connected::close`] gives: a registration
    /// dropped while a `Listener` or an accepted connection is still open blocks
    /// in `RegistrationClose` and nothing says why.
    pub async fn close(self) {
        let Self {
            running,
            shutdown,
            reg,
            ..
        } = self;
        shutdown.cancel();
        if tokio::time::timeout(CLOSE_TIMEOUT, running).await.is_err() {
            tracing::warn!("the listener session did not finish within {CLOSE_TIMEOUT:?}");
        }
        if !isekai_p2p::peer::drain_registration(&reg, DRAIN_TIMEOUT).await {
            tracing::warn!("msquic still had live handles after {DRAIN_TIMEOUT:?}");
        }
    }
}

/// How long [`ServerHandle::close`] waits for the session to withdraw itself.
///
/// It is one proxy request; longer than this means the proxy is not answering,
/// and the listener expires on its own either way.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

    // **The half that was missing**, and without which nothing gets off the
    // relay. `transport::connect` has offered a direct-path candidate since
    // 1c-iii-c-ii, but a candidate only says where *we* may be reached; the peer
    // has no address to send to until this end advertises its leg's binding.
    // One half alone is a connection that stays relayed with nothing in either
    // log to say why — see [`isekai_p2p::direct_path`].
    //
    // Taken before the accept loop starts, because `run` below consumes the
    // session. `PerConnection` and not `Single`: a portal server can be serving
    // several peers, each on a leg of its own, and handing a connection another
    // peer's binding advertises a path it cannot reach.
    let legs = RelayLegs::PerConnection(session.legs());
    let accepting = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accepting.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok(conn) => {
                        let catalogue = catalogue.clone();
                        let serving = accepting.clone();
                        direct_path::advertise(conn.clone(), legs.clone(), serving.clone());
                        // One task per peer: a forward that stalls must not
                        // stop the next peer being accepted.
                        tokio::spawn(async move {
                            if let Err(e) = crate::server::serve(conn, catalogue, serving).await {
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
    let running = tokio::spawn(run(
        session,
        cmd_rx,
        policy,
        signaling.clone(),
        shutdown.clone(),
    ));

    Ok(ServerHandle {
        info,
        commands,
        signaling,
        running,
        shutdown,
        reg,
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
    /// Every UDP forward over this connection, and the one task allowed to
    /// receive its datagrams.
    ///
    /// **Owned here rather than by each forward**, because there is one datagram
    /// queue per connection and a second reader would take datagrams belonging
    /// to the first ([`crate::udp`]). Pass `Arc::clone` to each
    /// [`crate::udp::forward`]; do not keep one of your own past
    /// [`close`](Self::close), which drops this before it waits for msquic.
    pub sessions: Arc<crate::udp::Sessions>,
    /// Cancelled by [`close`](Self::close) before it waits, so the forwards let
    /// their handles go. Without it the drain has nothing to wait for but a
    /// stream nobody is going to drop.
    shutdown: CancellationToken,
}

impl Connected {
    /// Stop the forwards, wait for msquic, report the connection closed, and
    /// take the relay leg down.
    ///
    /// **The order is the whole of it.** `client::forward` spawns tasks holding
    /// `Connection` and `Stream` clones, and a registration dropped with any of
    /// those still live blocks in `RegistrationClose` uninterruptibly — so
    /// cancelling and then *waiting* is what makes Ctrl-C during a transfer end
    /// the process instead of wedging it.
    ///
    /// Reporting is worth doing rather than dropping for a different reason:
    /// the listener finds who is waiting by listing connections in state
    /// `relay`, so one nobody reports occupies its leg until the proxy expires
    /// it.
    pub async fn close(self) {
        let Self {
            session,
            peer,
            sessions,
            shutdown,
        } = self;
        shutdown.cancel();
        // **Dropped before the wait, not after it.** `Sessions` holds a
        // `Connection` clone of its own, and the drain below is a wait for
        // msquic to have no live handles left — one held by a value still in
        // scope is one that will never be released, and the wait would time out
        // pointing at msquic rather than at this line.
        drop(sessions);
        if !peer.drain(DRAIN_TIMEOUT).await {
            tracing::warn!("msquic still had live handles after {DRAIN_TIMEOUT:?}");
        }
        session.close().await;
    }
}

/// How long [`Connected::close`] waits for msquic to let its handles go.
///
/// Generous next to what it is waiting for — cancelled tasks dropping a
/// connection — and short enough that a client leaving does not look hung.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// What says this client may reach the server.
///
/// **Two mechanisms, deliberately not one** — the server spec's §13.3 keeps
/// both and says why: a Grant is a standing permission and a Capability is the
/// delegation of a single connect. Portal spent phases 1 to 5 using the second
/// for the first's job, which is what #166 turned out to be.
pub enum Reach<'a> {
    /// A standing grant, from pairing. **Reusable, and it survives the server
    /// restarting**: a Grant's key is `(owner_endpoint, allowed_endpoint,
    /// protocol)` with no listener in it (spec §8.8), so the listener id is
    /// discovered here rather than carried by hand.
    ///
    /// `peer` narrows the search to one server's Endpoint ID, which is what a
    /// client paired with more than one needs. `None` is right when there is
    /// only one, and says so if there is not.
    Grant { peer: Option<&'a str> },
    /// A capability the operator issued and handed over. **One-shot, and 30
    /// seconds by default** — right for letting a guest in once, wrong for
    /// anything that reconnects. It names its listener, so nothing is
    /// discovered.
    Capability {
        capability: &'a str,
        listener_id: &'a str,
    },
}

/// Connect to a portal server and open the peer QUIC to it.
///
/// See [`Reach`] for the two ways of being allowed to.
pub async fn connect(
    cfg: &P2pConfig,
    reach: Reach<'_>,
    shutdown: &CancellationToken,
) -> anyhow::Result<Connected> {
    // **One registration for both, and it has to be made here.** msquic looks
    // bindings up per registration, so a relay leg on one and the peer QUIC on
    // another can never share a binding: `set_share_binding` finds nothing, the
    // candidate offered below never validates, and the direct path silently
    // does not happen (`docs/p2p_mode_migration_plan.md` §2.2.3, §2.4).
    // `serve` does the same thing from the other end.
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);
    let session = match reach {
        Reach::Grant { peer } => connect_on_a_grant(cfg, peer, reg.clone()).await?,
        Reach::Capability {
            capability,
            listener_id,
        } => connect_on_a_capability(cfg, capability, listener_id, reg.clone()).await?,
    };
    open_the_peer_connection(cfg, session, reg, shutdown).await
}

/// Find the listener this client is paired with, and connect to it.
///
/// **The lookup is the point.** A Grant outlives the listener it was made
/// against — spec §8.8 keeps Listener out of its key precisely so that
/// restarting the server does not mean pairing again — but a `connect` still
/// names a listener, and that id is new after every restart. So the id is
/// asked for rather than remembered, and what the client holds onto is the
/// server's Endpoint ID, which does not change.
async fn connect_on_a_grant(
    cfg: &P2pConfig,
    peer: Option<&str>,
    reg: Arc<Registration>,
) -> anyhow::Result<InitiatorSession> {
    let directory = PeerDirectory::open(cfg)
        .await
        .context("open the proxy control plane")?;
    let reachable = directory.reachable().await?;
    let listener = choose_listener(&reachable, &cfg.protocol, peer)?;
    tracing::info!(
        listener = %listener.listener_id,
        peer = %listener.owner_endpoint,
        "connecting on a standing grant",
    );
    directory
        .connect(
            cfg,
            &listener.listener_id,
            &[],
            "127.0.0.1:0".parse().expect("valid loopback addr"),
            RelayOptions {
                unconnected: true,
                registration: Some(reg),
            },
        )
        .await
        .context("peer connect")
}

/// The one listener `peer` names, or the only one there is.
///
/// Separate and taking a slice so the awkward cases — none, several — can be
/// tested without a proxy, because they are the ones a caller meets and the
/// message is the whole of what they get.
fn choose_listener<'a>(
    reachable: &'a [ReachableListener],
    protocol: &str,
    peer: Option<&str>,
) -> anyhow::Result<&'a ReachableListener> {
    let matching: Vec<&ReachableListener> = reachable
        .iter()
        .filter(|l| l.protocol == protocol)
        .filter(|l| peer.is_none_or(|want| l.owner_endpoint == want))
        .collect();
    match matching.as_slice() {
        [one] => Ok(one),
        [] if peer.is_some() => anyhow::bail!(
            "no portal server reachable at `{}`. Pair with it first (--pair), or check \
             the Endpoint ID",
            peer.unwrap_or_default(),
        ),
        [] => anyhow::bail!(
            "no portal server is reachable. Pair with one first: the operator runs \
             `portal-server --pair` and you run `portal-client --pair <code>`",
        ),
        several => anyhow::bail!(
            "paired with {} portal servers; name one with --peer: {}",
            several.len(),
            several
                .iter()
                .map(|l| l.owner_endpoint.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
}

/// Connect with a hand-carried capability, which names its own listener.
async fn connect_on_a_capability(
    cfg: &P2pConfig,
    capability: &str,
    listener_id: &str,
    reg: Arc<Registration>,
) -> anyhow::Result<InitiatorSession> {
    InitiatorSession::connect_with_options(
        cfg,
        capability,
        listener_id,
        &[],
        "127.0.0.1:0".parse().expect("valid loopback addr"),
        RelayOptions {
            unconnected: true,
            registration: Some(reg),
        },
    )
    .await
    .context("peer connect")
}

/// Everything after "we have a relay session": the peer QUIC, its direct-path
/// candidate, and the datagram pump. The same whichever way the session was
/// authorized, which is why it is here and not duplicated in both.
async fn open_the_peer_connection(
    cfg: &P2pConfig,
    session: InitiatorSession,
    reg: Arc<Registration>,
    shutdown: &CancellationToken,
) -> anyhow::Result<Connected> {
    let _ = cfg;
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
    //
    // **And it is probed, as of phase 4.** `serve` above advertises the other
    // end's leg binding, which is the half this offer was waiting for — until
    // it landed, this candidate said where we could be reached to a peer with
    // no address to send to. `crate::path` is what happens once a path
    // validates.
    let candidate = wait_for_observed(&session, shutdown).await;

    let peer = transport::connect(
        Some(reg),
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

    let sessions = crate::udp::Sessions::start(peer.connection().clone(), shutdown.clone());
    Ok(Connected {
        session,
        peer,
        sessions,
        shutdown: shutdown.clone(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(owner: &str, protocol: &str, id: &str) -> ReachableListener {
        ReachableListener {
            listener_id: id.to_owned(),
            owner_endpoint: owner.to_owned(),
            protocol: protocol.to_owned(),
            metadata: None,
            expires_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    /// **The listener id is looked up, not remembered**, which is the whole of
    /// why a grant survives the server restarting: a restart gives it a new id
    /// and the same Endpoint ID, and this is what turns the second into the
    /// first.
    #[test]
    fn the_current_listener_is_found_by_the_endpoint_that_owns_it() {
        let reachable = [listener("ep:aaa", "isekai-portal-v1", "pl_after_restart")];
        let found = choose_listener(&reachable, "isekai-portal-v1", Some("ep:aaa"))
            .expect("the paired server");
        assert_eq!(found.listener_id, "pl_after_restart");
    }

    /// A camera and a portal on the same Endpoint are two listeners, and only
    /// one of them speaks this protocol. Connecting to the wrong one would fail
    /// at the ALPN, which is a much worse way to find out.
    #[test]
    fn a_listener_of_another_protocol_is_not_a_candidate() {
        let reachable = [
            listener("ep:aaa", "sample", "pl_camera"),
            listener("ep:aaa", "isekai-portal-v1", "pl_portal"),
        ];
        let found = choose_listener(&reachable, "isekai-portal-v1", None).expect("the portal");
        assert_eq!(found.listener_id, "pl_portal");
    }

    /// **The awkward cases are the whole reason this is a function.** Each one
    /// is something a person meets, and the message is all they get — so each
    /// says what to do rather than what went wrong.
    #[test]
    fn what_is_wrong_is_said_out_loud() {
        let none: [ReachableListener; 0] = [];
        let err = format!(
            "{:#}",
            choose_listener(&none, "isekai-portal-v1", None).expect_err("nothing to reach")
        );
        assert!(err.contains("--pair"), "says how to fix it: {err}");

        let err = format!(
            "{:#}",
            choose_listener(&none, "isekai-portal-v1", Some("ep:zzz")).expect_err("no such peer")
        );
        assert!(
            err.contains("ep:zzz"),
            "names the peer that was asked for: {err}",
        );

        let two = [
            listener("ep:aaa", "isekai-portal-v1", "pl_1"),
            listener("ep:bbb", "isekai-portal-v1", "pl_2"),
        ];
        let err = format!(
            "{:#}",
            choose_listener(&two, "isekai-portal-v1", None).expect_err("ambiguous")
        );
        assert!(
            err.contains("--peer") && err.contains("ep:aaa") && err.contains("ep:bbb"),
            "lists what to choose between: {err}",
        );
    }
}
