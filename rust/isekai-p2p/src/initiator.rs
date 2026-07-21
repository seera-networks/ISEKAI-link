//! The initiator side of a P2P connection: `peer_connect` plus the relay
//! **connect** leg, which exposes a local UDP address a co-located client dials.
//!
//! The client (e.g. the camera client's video QUIC connection) sends to
//! [`InitiatorSession::local_addr`] instead of a public address; the relay
//! carries it to the target's bound socket.

use std::net::SocketAddr;

use anyhow::Context as _;
use isekai_agent::bind::{open_connect_relay, ConnectRelay};
use isekai_agent::proxy::{Candidate, PeerConnection, ProxyClient};
use isekai_agent::transport::MasqueH3Transport;

use crate::config::{issue_endpoint_token, P2pConfig};

/// An initiator-side P2P session. Holds the relay connect leg open until dropped
/// or [`close`](InitiatorSession::close)d.
pub struct InitiatorSession {
    /// The local UDP address to send application traffic to.
    pub local_addr: SocketAddr,
    /// The `peer_connect` response, including `connection_id` (hand this to the
    /// target so it can bind) and the relay info.
    pub connection: PeerConnection,
    relay: ConnectRelay,
}

impl InitiatorSession {
    /// Obtain an Endpoint Token, `peer_connect` with `capability` +
    /// `listener_id`, and open the relay connect leg.
    ///
    /// `candidates` may be empty for relay-only use. `local_bind` is where the
    /// leg binds locally (`127.0.0.1:0` for an ephemeral port).
    pub async fn connect(
        cfg: &P2pConfig,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::connect_with_token(
            cfg,
            &endpoint_token,
            capability,
            listener_id,
            candidates,
            local_bind,
        )
        .await
    }

    /// Like [`connect`](Self::connect) but with an Endpoint Token the caller
    /// already holds, skipping the Identity API round-trip.
    ///
    /// Only `proxy_url`, `protocol` and `key` are read from `cfg`.
    pub async fn connect_with_token(
        cfg: &P2pConfig,
        endpoint_token: &str,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token,
        );
        let connection = proxy
            .peer_connect(capability, listener_id, &cfg.protocol, candidates)
            .await?;
        let relay = connection.relay.as_ref().context(
            "connect response has no relay info; the proxy did not allocate a relay edge",
        )?;
        let handle = open_connect_relay(
            &cfg.proxy_url,
            endpoint_token,
            &cfg.key,
            &connection.connection_id,
            &relay.masque_uri,
            local_bind,
        )
        .await?;
        Ok(Self {
            local_addr: handle.local_addr,
            connection,
            relay: handle,
        })
    }

    /// The connection id, to hand to the target so it can bind its relay leg.
    pub fn connection_id(&self) -> &str {
        &self.connection.connection_id
    }

    /// Tear down the relay connect leg.
    pub async fn close(self) {
        self.relay.close().await;
    }
}
