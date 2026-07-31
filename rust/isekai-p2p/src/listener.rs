//! The target side of a P2P connection: a private Peer Listener plus the relay
//! **bind** leg that forwards inbound relay UDP to a local address.
//!
//! A co-located service (e.g. the camera server's video QUIC listener) binds a
//! local socket; the relay delivers the initiator's traffic there. Because the
//! relay edge is allocated when the *initiator* connects, the bind leg needs the
//! `connection_id` the initiator produced — hence the two-phase API:
//! [`ListenerSession::create`] sets up the listener and capabilities, and
//! [`ListenerSession::bind`] attaches the relay once the initiator has connected.
//!
//! Exchange order (all values conveyed out of band):
//!
//! 1. initiator reveals its `endpoint_id`;
//! 2. this side [`create`](ListenerSession::create)s and
//!    [`issue_capability`](ListenerSession::issue_capability) for it, revealing
//!    `listener_id` + the capability;
//! 3. the initiator connects and reveals its `connection_id`;
//! 4. this side [`bind`](ListenerSession::bind)s that `connection_id`.

use std::net::SocketAddr;

use isekai_p2p_core::bind::{open_bind_session, BindSession, RelayOptions};
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};
use isekai_p2p_core::proxy::{Capability, ProxyClient};
use isekai_p2p_core::transport::MasqueH3Transport;
use tokio::sync::watch;

use crate::config::{issue_endpoint_token, P2pConfig};

/// A target-side P2P session. Holds the relay bind leg open until dropped or
/// [`close`](ListenerSession::close)d.
pub struct ListenerSession {
    /// The created Peer Listener's id — hand this to the initiator.
    pub listener_id: String,
    /// This Endpoint's id.
    pub endpoint_id: String,
    proxy_url: String,
    endpoint_token: String,
    key: EndpointKey,
    forward_to: SocketAddr,
    proxy: ProxyClient<MasqueH3Transport>,
    protocol: String,
    bind: Option<BindGuard>,
    opts: RelayOptions,
    /// Session-lifetime observed address, republished by each bind leg.
    ///
    /// Every [`bind`](ListenerSession::bind) opens a *new* leg with a *new*
    /// watch, but a caller that took a receiver before the first bind — which
    /// is the normal order, since binding waits on a connection id pasted by
    /// hand — must keep seeing updates across rebinds. So the leg's watch is
    /// forwarded into this one rather than handed out directly.
    observed_tx: watch::Sender<Option<ObservedAddress>>,
}

/// Keeps the spawned bind leg alive; cancels it on drop / close.
struct BindGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl ListenerSession {
    /// Obtain an Endpoint Token and create a private Peer Listener.
    ///
    /// `forward_to` is where the relay will deliver inbound traffic once
    /// [`bind`](ListenerSession::bind) runs — bind the local video listener
    /// there first. `ttl` is the listener TTL in seconds (`None` = default).
    pub async fn create(
        cfg: &P2pConfig,
        forward_to: SocketAddr,
        ttl: Option<u64>,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::create_with_token(cfg, &endpoint_token, forward_to, ttl).await
    }

    /// Like [`create`](Self::create) but choosing how the relay bind leg is
    /// opened.
    ///
    /// Pass `RelayOptions { unconnected: true, registration: Some(..) }` to make
    /// the leg usable for path migration: the direct path is opened from its
    /// binding, and [`observed_address`](Self::observed_address) then reports
    /// the address to advertise.
    pub async fn create_with_options(
        cfg: &P2pConfig,
        forward_to: SocketAddr,
        ttl: Option<u64>,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::create_with_token_and_options(cfg, &endpoint_token, forward_to, ttl, opts).await
    }

    /// Like [`create`](Self::create) but with an Endpoint Token the caller
    /// already holds, skipping the Identity API round-trip.
    ///
    /// Lets a caller that also downloads the relay certificate (which needs the
    /// same token) issue the token once. Only `proxy_url`, `protocol`, `key` and
    /// the Endpoint ID are read from `cfg`.
    pub async fn create_with_token(
        cfg: &P2pConfig,
        endpoint_token: &str,
        forward_to: SocketAddr,
        ttl: Option<u64>,
    ) -> anyhow::Result<Self> {
        Self::create_with_token_and_options(
            cfg,
            endpoint_token,
            forward_to,
            ttl,
            RelayOptions::default(),
        )
        .await
    }

    /// [`create_with_token`](Self::create_with_token) plus the relay-leg
    /// options — the form the other three delegate to.
    pub async fn create_with_token_and_options(
        cfg: &P2pConfig,
        endpoint_token: &str,
        forward_to: SocketAddr,
        ttl: Option<u64>,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let endpoint_token = endpoint_token.to_owned();
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token.clone(),
        );
        let listener = proxy.create_peer_listener(&cfg.protocol, ttl).await?;
        Ok(Self {
            listener_id: listener.listener_id,
            endpoint_id: cfg.endpoint_id(),
            proxy_url: cfg.proxy_url.clone(),
            endpoint_token,
            key: cfg.key.clone(),
            forward_to,
            proxy,
            protocol: cfg.protocol.clone(),
            bind: None,
            opts,
            observed_tx: watch::channel(None).0,
        })
    }

    /// How the proxy sees this Endpoint's relay bind leg — `None` until a leg
    /// is bound and reports.
    ///
    /// The server advertises this pair on each accepted video connection
    /// (`add_bound_addr` / `add_observed_addr`) so the initiator can punch a
    /// direct path to it. Safe to take before [`bind`](Self::bind): the
    /// receiver survives rebinds.
    ///
    /// Only meaningful when the session was created with
    /// `RelayOptions { unconnected: true, .. }`; a leg on a plain connected
    /// socket has no binding a direct path could use.
    pub fn observed_address(&self) -> ObservedAddressWatch {
        self.observed_tx.subscribe()
    }

    /// Mint a capability authorizing `allowed_endpoint` (the initiator's
    /// Endpoint ID) to connect to this listener. Returns the opaque token to
    /// hand to the initiator out of band.
    pub async fn issue_capability(
        &self,
        allowed_endpoint: &str,
        ttl: Option<u64>,
    ) -> anyhow::Result<Capability> {
        let cap = self
            .proxy
            .issue_capability(&self.listener_id, allowed_endpoint, &self.protocol, ttl)
            .await?;
        Ok(cap)
    }

    /// Attach the relay bind leg for `connection_id` (the id the initiator's
    /// `peer_connect` produced). Inbound relay UDP is forwarded to the
    /// `forward_to` given at [`create`](ListenerSession::create).
    ///
    /// Replaces any previous bind leg.
    pub async fn bind(&mut self, connection_id: &str) -> anyhow::Result<()> {
        let session = open_bind_session(
            &self.proxy_url,
            &self.endpoint_token,
            &self.key,
            connection_id,
            self.forward_to,
            self.opts.clone(),
        )
        .await?;
        // Own the session in a task that drains its notifications, so an unread
        // events channel can never stall the underlying MASQUE loop. Dropping
        // the task (on close) drops the session, whose Drop cancels the relay.
        let handle = tokio::spawn(drive_bind_session(session, self.observed_tx.clone()));
        if let Some(prev) = self.bind.replace(BindGuard { handle }) {
            prev.handle.abort();
        }
        Ok(())
    }

    /// Stop the relay bind leg (if any). The Peer Listener stays until its TTL
    /// expires or the process ends.
    pub async fn close(mut self) {
        if let Some(guard) = self.bind.take() {
            guard.handle.abort();
            let _ = guard.handle.await;
        }
    }
}

/// Drain the leg's notifications and republish its observed address into the
/// session-lifetime watch.
///
/// Both have to run for as long as the leg does: an unread events channel
/// stalls the MASQUE loop, and an unforwarded report leaves the server with no
/// address to advertise.
async fn drive_bind_session(
    mut session: BindSession,
    observed_tx: watch::Sender<Option<ObservedAddress>>,
) {
    let mut leg = session.observed();
    // The leg's watch ends when its connection does; keep draining events after
    // that rather than spinning on a closed channel.
    let mut leg_open = true;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(event) => tracing::debug!("bind session event: {event:?}"),
                None => break,
            },
            changed = leg.changed(), if leg_open => {
                leg_open = republish_observed(&mut leg, &observed_tx, changed.is_ok());
            }
        }
    }
}

/// Republish one change from a leg's watch into the session-lifetime watch.
///
/// Returns whether the leg's watch is still worth polling: once it has ended
/// (`changed_ok == false`) there is nothing more to forward.
///
/// Only a `Some` is forwarded. A leg that ends without ever reporting leaves
/// the session's last known address in place rather than blanking it — the
/// server would otherwise stop advertising a direct path across a rebind that
/// has not reported yet.
fn republish_observed(
    leg: &mut ObservedAddressWatch,
    out: &watch::Sender<Option<ObservedAddress>>,
    changed_ok: bool,
) -> bool {
    if !changed_ok {
        return false;
    }
    if let Some(observed) = *leg.borrow_and_update() {
        out.send_replace(Some(observed));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 59], port))
    }

    fn observed(port: u16) -> ObservedAddress {
        ObservedAddress {
            local: addr(port),
            observed: addr(port + 1),
        }
    }

    /// The point of the session-lifetime watch: a receiver taken *before* any
    /// leg exists still sees what a later leg reports. That is the normal
    /// order — binding waits on a connection id pasted by hand, long after the
    /// server started watching.
    #[test]
    fn a_receiver_taken_before_the_first_bind_sees_the_leg_report() {
        let session = watch::channel(None).0;
        let mut early = session.subscribe();
        assert_eq!(*early.borrow_and_update(), None);

        let (leg_tx, mut leg_rx) = watch::channel(None);
        leg_tx.send_replace(Some(observed(1000)));
        assert!(republish_observed(&mut leg_rx, &session, true));

        assert_eq!(*early.borrow_and_update(), Some(observed(1000)));
    }

    /// And it survives the leg being replaced: `bind` can be called again, and
    /// the same receiver picks up the new leg's address.
    #[test]
    fn the_watch_survives_a_rebind() {
        let session = watch::channel(None).0;
        let mut held = session.subscribe();

        let (first_tx, mut first_rx) = watch::channel(None);
        first_tx.send_replace(Some(observed(1000)));
        republish_observed(&mut first_rx, &session, true);
        assert_eq!(*held.borrow_and_update(), Some(observed(1000)));

        // The first leg ends; the session keeps its last known address.
        assert!(!republish_observed(&mut first_rx, &session, false));
        assert_eq!(*held.borrow(), Some(observed(1000)));

        // A second leg reports, and the *same* receiver sees it.
        let (second_tx, mut second_rx) = watch::channel(None);
        second_tx.send_replace(Some(observed(2000)));
        republish_observed(&mut second_rx, &session, true);
        assert_eq!(*held.borrow_and_update(), Some(observed(2000)));
    }

    /// A leg that changes to `None` must not blank an address the server is
    /// still advertising.
    #[test]
    fn an_empty_leg_report_does_not_clear_the_session_address() {
        let session = watch::channel(None).0;
        let held = session.subscribe();

        let (leg_tx, mut leg_rx) = watch::channel(None);
        leg_tx.send_replace(Some(observed(1000)));
        republish_observed(&mut leg_rx, &session, true);

        leg_tx.send_replace(None);
        republish_observed(&mut leg_rx, &session, true);
        assert_eq!(*held.borrow(), Some(observed(1000)));
    }
}
