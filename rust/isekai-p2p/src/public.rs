//! Publishing a UDP service at an address the world can reach
//! (`docs/public_listener_client_plan.md` P2).
//!
//! Three things happen, in this order, and only the first is once:
//!
//! ```text
//!   create  ── the Listener, and the address it advertises
//!     │         idempotent; a restart gets the one it already had
//!   ticket  ── the paper that authorizes binding that address
//!     │         single use, 45 seconds, per *bind attempt*
//!   bind    ── the session that is the address
//! ```
//!
//! **There is no renewal loop.** A lease cannot cut a public session — the
//! data plane keeps no per-packet gate for these, deliberately (server-side
//! plan §12.8) — so the lease only decides whether a *next* ticket is issued.
//! A loop pushing it out would move nothing, and would teach whoever reads the
//! logs that renewing proves the address is live.
//!
//! **And no health check.** The senders are whoever finds the address, so
//! hearing from nobody is a normal Tuesday; a check built on silence would
//! report failure on a listener that works.

use std::net::SocketAddr;

use anyhow::Context as _;
use isekai_p2p_core::bind::{open_public_bind_session, BindSession, RelayOptions};
use isekai_p2p_core::proxy::{
    ControlPlaneTransport, ProxyClient, PublicAddress, PublicListener, PublicTarget, RelayRole,
};

use crate::config::P2pConfig;

/// A published UDP service, and the session carrying traffic to it.
pub struct PublicEndpoint {
    listener_id: String,
    advertised: PublicAddress,
    session: BindSession,
}

impl PublicEndpoint {
    /// The Listener this holds, so a caller can delete it when it is done.
    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }

    /// The address to give out — **as the control plane described it**,
    /// hostname and all.
    ///
    /// The data plane reports a `SocketAddr` for the session, which has no room
    /// for a name, so what it says is a poorer version of this rather than a
    /// second opinion worth comparing against (plan §3.3).
    pub fn advertised(&self) -> &PublicAddress {
        &self.advertised
    }

    /// What this session has received. **Nothing arriving is not a fault**; see
    /// the module note.
    pub fn inbound_activity(&self) -> isekai_p2p_core::bind::InboundActivity {
        self.session.inbound_activity()
    }

    /// Stop carrying traffic. The Listener stays; deleting it is a separate
    /// decision, because an address that is still advertised may want to
    /// survive this process.
    pub async fn close(self) {
        self.session.close().await;
    }
}

/// Declare `target` public, and open the session that serves its address.
///
/// `idempotency_key` is what stops a restart becoming a second Listener; give
/// it something stable about what is published rather than about this run (see
/// [`ProxyClient::create_public_listener`]).
pub async fn publish<T: ControlPlaneTransport>(
    cfg: &P2pConfig,
    proxy: &ProxyClient<T>,
    endpoint_token: &str,
    target: PublicTarget,
    forward_to: SocketAddr,
    options: PublishOptions<'_>,
) -> anyhow::Result<PublicEndpoint> {
    let listener = proxy
        .create_public_listener(
            &target,
            options.region,
            options.ttl,
            Some(options.idempotency_key),
        )
        .await
        .context("declare this service public")?;
    let session = open(
        cfg,
        proxy,
        endpoint_token,
        &listener.listener_id,
        forward_to,
    )
    .await?;
    Ok(session)
}

/// Open the session for a Listener that already exists.
///
/// **Also the way back after a disconnection**, and it re-tickets rather than
/// reusing: a ticket is single use, lasts 45 seconds, and is spent by the data
/// plane only once the bind has succeeded. It is asked for per *attempt*, not
/// per reconnection — a retry wrapped around the bind alone presents a spent or
/// stale one and is refused, in a way that reads as the data plane turning this
/// Endpoint away.
///
/// **It is also the only place a moved allocation shows up.** The server reads
/// the ledger again here rather than repeating what the Listener's row
/// remembers, so a retired data plane arrives as a different address in the
/// answer.
pub async fn open<T: ControlPlaneTransport>(
    cfg: &P2pConfig,
    proxy: &ProxyClient<T>,
    endpoint_token: &str,
    listener_id: &str,
    forward_to: SocketAddr,
) -> anyhow::Result<PublicEndpoint> {
    let ticketed = proxy
        .issue_public_listener_ticket(listener_id)
        .await
        .with_context(|| format!("get a ticket for {listener_id}"))?;

    check_ticket_role(&ticketed)?;
    let target = where_to_bind(&ticketed, &cfg.proxy_url).to_owned();
    let target = target.as_str();

    let session = open_public_bind_session(
        target,
        endpoint_token,
        &cfg.key,
        forward_to,
        ticketed.ticket.as_ref().map(|t| t.ticket.as_str()),
        RelayOptions::default(),
    )
    .await
    .with_context(|| format!("bind the public address for {listener_id}"))?;

    Ok(PublicEndpoint {
        listener_id: ticketed.listener_id,
        advertised: ticketed.public_address,
        session,
    })
}

/// Refuse a ticket that is not for a public address.
///
/// **Checked before it is presented.** Taken to the public path, a leg's
/// ticket is refused by the data plane — and the refusal names the ticket,
/// where the mistake was which door this request went to. That is the hardest
/// thing to see from here, so it is checked where it can still be said plainly.
fn check_ticket_role(listener: &PublicListener) -> anyhow::Result<()> {
    let Some(ticket) = &listener.ticket else {
        return Ok(());
    };
    anyhow::ensure!(
        ticket.role == RelayRole::Public,
        "the control plane issued a {:?} ticket for public listener {}; presenting it \
         would be refused as a relay leg",
        ticket.role,
        listener.listener_id,
    );
    Ok(())
}

/// Where to open the session: the data plane that was named, or the proxy this
/// client is configured to trust.
///
/// **`dp_id` is the signal, not the shape of the URI.** With no registered data
/// plane the control plane builds a `masque_uri` from its own default — a
/// production host — so reading "it has an authority" as "go there" sends a
/// development client's Endpoint Token to an origin nobody configured.
/// `bind.rs` reached the same conclusion for relay legs.
fn where_to_bind<'a>(listener: &'a PublicListener, proxy_url: &'a str) -> &'a str {
    listener
        .relay
        .as_ref()
        .filter(|relay| relay.dp_id.is_some())
        .map(|relay| relay.masque_uri.as_str())
        .unwrap_or(proxy_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use isekai_p2p_core::proxy::{RelayInfo, RelayTicket};

    fn listener(relay: Option<RelayInfo>, ticket: Option<RelayTicket>) -> PublicListener {
        PublicListener {
            listener_id: "ul_1".to_owned(),
            owner_endpoint: "ep:C".to_owned(),
            public_address: PublicAddress {
                hostname: None,
                ip: "203.0.113.9".to_owned(),
                port: 10042,
            },
            region: None,
            relay,
            ticket,
            status: "active".to_owned(),
            created_at: "c".to_owned(),
            expires_at: "e".to_owned(),
        }
    }

    fn relay(dp_id: Option<&str>) -> RelayInfo {
        RelayInfo {
            masque_uri: "https://dp1.example:8443/.well-known/masque/udp/%2A/%2A/".to_owned(),
            session_id: None,
            dp_id: dp_id.map(str::to_owned),
            spki_sha256: Vec::new(),
        }
    }

    fn ticket(role: RelayRole) -> RelayTicket {
        RelayTicket {
            ticket: "eyJ.JWT.sig".to_owned(),
            role,
            expires_at: "t".to_owned(),
            lease_expires_at: "t2".to_owned(),
        }
    }

    /// A named data plane is where the address is, so that is where the
    /// session goes.
    #[test]
    fn a_named_data_plane_is_dialled() {
        assert_eq!(
            where_to_bind(
                &listener(Some(relay(Some("dp1abc"))), None),
                "https://cp:6443"
            ),
            "https://dp1.example:8443/.well-known/masque/udp/%2A/%2A/",
        );
    }

    /// **Without `dp_id`, the URI is not an instruction.** The control plane
    /// fills it from a default that points at production, so following it would
    /// send a development client's Endpoint Token somewhere nobody configured.
    #[test]
    fn an_unchosen_relay_is_not_followed() {
        assert_eq!(
            where_to_bind(&listener(Some(relay(None)), None), "https://cp:6443"),
            "https://cp:6443",
        );
        assert_eq!(
            where_to_bind(&listener(None, None), "https://cp:6443"),
            "https://cp:6443",
            "no relay at all is the control plane's own data path",
        );
    }

    /// **A leg's ticket on this path is refused by the data plane**, naming the
    /// ticket rather than the door — so it is caught here, where it can still
    /// be said plainly.
    #[test]
    fn a_ticket_for_a_leg_never_reaches_the_wire() {
        let e = check_ticket_role(&listener(None, Some(ticket(RelayRole::Target))))
            .expect_err("refused");
        assert!(e.to_string().contains("relay leg"), "{e}");
        check_ticket_role(&listener(None, Some(ticket(RelayRole::Public)))).expect("public");
        // The control plane's own data path issues none, and that is not an
        // error: the session's Endpoint Token is what authorizes it.
        check_ticket_role(&listener(None, None)).expect("no ticket");
    }
}

/// What a caller chooses when publishing.
pub struct PublishOptions<'a> {
    /// Stable across restarts, and about what is published rather than about
    /// this run.
    pub idempotency_key: &'a str,
    /// Where the address should be, which decides only the **first**
    /// allocation this account ever gets.
    pub region: Option<&'a str>,
    /// Seconds, clamped by the server to 60..=86,400.
    pub ttl: Option<u64>,
}
