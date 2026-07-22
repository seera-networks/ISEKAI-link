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

use isekai_p2p_core::bind::{open_bind_session, BindSession};
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::proxy::{Capability, ProxyClient};
use isekai_p2p_core::transport::MasqueH3Transport;

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
        })
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
        )?;
        // Own the session in a task that drains its notifications, so an unread
        // events channel can never stall the underlying MASQUE loop. Dropping
        // the task (on close) drops the session, whose Drop cancels the relay.
        let handle = tokio::spawn(drain_bind_events(session));
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

async fn drain_bind_events(mut session: BindSession) {
    while let Some(event) = session.events.recv().await {
        tracing::debug!("bind session event: {event:?}");
    }
}
