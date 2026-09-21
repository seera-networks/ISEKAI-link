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
use isekai_p2p_core::bind::{
    open_public_bind_session, BindSession, InboundActivity, MasqueClientEvent, RelayOptions,
};
use isekai_p2p_core::proxy::{
    ControlPlaneTransport, ProxyClient, PublicAddress, PublicListener, PublicTarget, RelayRole,
};

use tokio::sync::watch;

use crate::config::P2pConfig;

/// A published UDP service, and the session carrying traffic to it.
pub struct PublicEndpoint {
    listener_id: String,
    advertised: PublicAddress,
    /// What the data plane says it bound, once it has said anything.
    ///
    /// **Worth watching on one path.** Where the control plane named a data
    /// plane, this can only repeat the address that was already in the answer —
    /// both come from one read of the ledger. Where it named none, the bind
    /// lands on the control plane's own data path, which has branches of its
    /// own (a shared listener, a temporary address), and **this is the only
    /// place a bind that took some other port than the published one becomes
    /// visible** (plan §3.7).
    reported: watch::Receiver<Option<Vec<SocketAddr>>>,
    inbound: InboundActivity,
    /// Owns the session and drains its events. Dropping it drops the session,
    /// whose `Drop` cancels the bind.
    driver: Option<tokio::task::JoinHandle<()>>,
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
    pub fn inbound_activity(&self) -> InboundActivity {
        self.inbound.clone()
    }

    /// The addresses the data plane reports for this session, once it reports
    /// any — see [`reported`](Self::reported) on the struct for when they are
    /// worth reading.
    pub fn reported(&self) -> watch::Receiver<Option<Vec<SocketAddr>>> {
        self.reported.clone()
    }

    /// Stop carrying traffic. The Listener stays; deleting it is a separate
    /// decision, because an address that is still advertised may want to
    /// survive this process.
    pub async fn close(mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

impl Drop for PublicEndpoint {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// Drain the session's events for as long as it lives.
///
/// **Holding a `BindSession` without reading it stops the session.** The relay
/// task pushes into a 32-slot channel with an awaited send; full, it stops
/// draining the MASQUE client's events, and the client's loop then blocks
/// trying to push into *that* — and forwards nothing. A public address emits
/// one `NewRemoteHost` per distinct remote source, and its sources are
/// strangers, so the count that wedges it is reached by a scan or by ordinary
/// clients rotating ports. `listener.rs` drives its leg for the same reason.
async fn drive(mut session: BindSession, reported: watch::Sender<Option<Vec<SocketAddr>>>) {
    while let Some(event) = session.events.recv().await {
        match event {
            MasqueClientEvent::PublicAddresses(addresses) => {
                tracing::info!(?addresses, "the data plane reports this session's address");
                let _ = reported.send(Some(addresses));
            }
            // One per stranger, which is the ordinary traffic of this session
            // rather than news.
            MasqueClientEvent::NewRemoteHost(..) => {}
            other => tracing::debug!("public bind session event: {other:?}"),
        }
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
    match open(cfg, proxy, &listener.listener_id, forward_to).await {
        Ok(session) => Ok(session),
        // **The remembered reply can name a Listener that has died.** The
        // idempotency window is a day; a Listener may be given an hour, so a
        // restart in between is handed the id of something that is gone, and
        // asking for its ticket answers `404`. Creating again *without* the key
        // is the way past — it spends a row, but only where one was genuinely
        // needed, and the alternative is being unable to publish until the
        // cache forgets.
        Err(e) if is_listener_not_found(&e) => {
            tracing::info!(
                listener = %listener.listener_id,
                "the remembered Listener has expired; creating another",
            );
            let listener = proxy
                .create_public_listener(&target, options.region, options.ttl, None)
                .await
                .context("declare this service public again")?;
            open(cfg, proxy, &listener.listener_id, forward_to).await
        }
        Err(e) => Err(e),
    }
}

/// Whether the proxy said there is no such Listener.
fn is_listener_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|e| e.downcast_ref::<isekai_p2p_core::proxy::ProxyError>())
        .any(|e| e.kind() == Some("listener-not-found"))
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
    listener_id: &str,
    forward_to: SocketAddr,
) -> anyhow::Result<PublicEndpoint> {
    let ticketed = proxy
        .issue_public_listener_ticket(listener_id)
        .await
        .with_context(|| format!("get a ticket for {listener_id}"))?;

    check_ticket_role(&ticketed)?;
    // **One decision, not two.** A ticket authorizes an address on the host
    // that issued it, so declining to dial that host and presenting its paper
    // anyway sends a ticket somewhere it means nothing — and the refusal names
    // the ticket, which is the confusion `check_ticket_role` exists to keep a
    // caller out of.
    let (target, ticket) = match chosen_relay(&ticketed) {
        Some(relay) => (
            relay.masque_uri.clone(),
            ticketed.ticket.as_ref().map(|t| t.ticket.clone()),
        ),
        None => (cfg.proxy_url.clone(), None),
    };

    let session = open_public_bind_session(
        &target,
        // **Read here, not passed in.** The renewal loop replaces this every
        // few minutes, and `open` is the way back after a disconnection — a
        // caller that captured one at startup would present an expired token
        // hours later, and the refusal would read as the data plane turning
        // this Endpoint away. The relay leg reads it at bind time for the same
        // reason.
        &proxy.endpoint_token(),
        &cfg.key,
        forward_to,
        ticket.as_deref(),
        RelayOptions::default(),
    )
    .await
    .with_context(|| format!("bind the public address for {listener_id}"))?;

    let inbound = session.inbound_activity();
    let (reported_tx, reported) = watch::channel(None);
    Ok(PublicEndpoint {
        listener_id: ticketed.listener_id,
        advertised: ticketed.public_address,
        reported,
        inbound,
        driver: Some(tokio::spawn(drive(session, reported_tx))),
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

/// The data plane the control plane chose, if it chose one.
///
/// **This decides both halves**: where to dial, and whether there is a ticket
/// to present. They are one question — a ticket authorizes an address on the
/// host that issued it.
///
/// **`dp_id` is the signal, not the shape of the URI.** With no registered data
/// plane the control plane builds a `masque_uri` from its own default — a
/// production host — so reading "it has an authority" as "go there" sends a
/// development client's Endpoint Token to an origin nobody configured.
/// `bind.rs` reached the same conclusion for relay legs.
fn chosen_relay(listener: &PublicListener) -> Option<&isekai_p2p_core::proxy::RelayInfo> {
    listener
        .relay
        .as_ref()
        .filter(|relay| relay.dp_id.is_some())
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
    /// session goes — with the ticket that authorizes it there.
    #[test]
    fn a_named_data_plane_is_dialled_with_its_ticket() {
        let l = listener(Some(relay(Some("dp1abc"))), Some(ticket(RelayRole::Public)));
        let chosen = chosen_relay(&l).expect("a data plane was chosen");
        assert_eq!(
            chosen.masque_uri,
            "https://dp1.example:8443/.well-known/masque/udp/%2A/%2A/",
        );
    }

    /// **Without `dp_id`, the URI is not an instruction — and neither is the
    /// ticket beside it.** The control plane fills that field from a default
    /// pointing at production, so following it would send a development
    /// client's Endpoint Token somewhere nobody configured; and a ticket
    /// authorizes an address on the host that issued it, so carrying it to a
    /// host this request is not talking to only earns a refusal that names the
    /// ticket.
    #[test]
    fn an_unchosen_relay_takes_its_ticket_with_it() {
        assert!(
            chosen_relay(&listener(
                Some(relay(None)),
                Some(ticket(RelayRole::Public))
            ))
            .is_none(),
            "a relay the control plane did not choose is not one to dial",
        );
        assert!(chosen_relay(&listener(None, None)).is_none());
    }

    /// **A remembered Listener can be dead.** The idempotency window is a
    /// day and a Listener may be given an hour, so a restart in between is
    /// handed the id of something gone — and only `listener-not-found` says
    /// so. Anything else is a reason to stop, not to spend another row.
    #[test]
    fn only_a_missing_listener_earns_a_second_creation() {
        let gone = anyhow::Error::from(isekai_p2p_core::proxy::ProxyError::Problem {
            status: 404,
            problem: serde_json::from_str(
                r#"{"type":"https://proxy/problems/listener-not-found","status":404}"#,
            )
            .ok(),
            retry_after: None,
        })
        .context("get a ticket for ul_1");
        assert!(is_listener_not_found(&gone));

        let refused = anyhow::Error::from(isekai_p2p_core::proxy::ProxyError::Problem {
            status: 403,
            problem: serde_json::from_str(
                r#"{"type":"https://proxy/problems/insufficient-permission","status":403}"#,
            )
            .ok(),
            retry_after: None,
        });
        assert!(!is_listener_not_found(&refused));
        assert!(!is_listener_not_found(&anyhow::anyhow!("the network")));
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
