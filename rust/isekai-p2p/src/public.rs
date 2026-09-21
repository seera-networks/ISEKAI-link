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

use std::net::{IpAddr, SocketAddr};

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
    /// What the address used to be, when this open found a different one.
    moved: Option<AddressChange>,
}

/// An address that is not where it was.
///
/// **Whoever published the old one cannot be told by this process.** It is in
/// somebody's DNS, or a config file, or a message sent last week — places the
/// client cannot reach. So the only useful thing to do with this is say it
/// loudly and let a person decide; moving quietly to the new address would let
/// "it stopped working" happen entirely outside anywhere it would be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressChange {
    pub from: PublicAddress,
    pub to: PublicAddress,
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

    /// Where the address moved to, if this open found it somewhere else.
    ///
    /// **Only a re-open can answer this**, and only against an address the
    /// caller kept: the control plane re-reads its ledger when it issues a
    /// ticket, so a retired data plane shows up as a different answer there and
    /// nowhere else.
    pub fn moved(&self) -> Option<&AddressChange> {
        self.moved.as_ref()
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
async fn drive(
    mut session: BindSession,
    reported: watch::Sender<Option<Vec<SocketAddr>>>,
    expected: Option<PublicAddress>,
) {
    while let Some(event) = session.events.recv().await {
        match event {
            MasqueClientEvent::PublicAddresses(addresses) => {
                tracing::info!(?addresses, "the data plane reports this session's address");
                if expected
                    .as_ref()
                    .is_some_and(|expected| bound_elsewhere(expected, &addresses))
                {
                    tracing::warn!(
                        expected = %expected.as_ref().expect("checked just above"),
                        reported = ?addresses,
                        "the session was bound somewhere other than the address that was \
                         published; traffic sent to the published one arrives nowhere",
                    );
                }
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
    match open(
        cfg,
        proxy,
        &listener.listener_id,
        forward_to,
        options.published,
    )
    .await
    {
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
            open(
                cfg,
                proxy,
                &listener.listener_id,
                forward_to,
                options.published,
            )
            .await
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
    published: Option<&PublicAddress>,
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
    let chosen = chosen_relay(&ticketed).map(|relay| relay.masque_uri.clone());
    let (target, ticket) = match &chosen {
        Some(masque_uri) => (
            masque_uri.clone(),
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
    let expect_reported = worth_comparing(chosen.is_some(), &ticketed.public_address);
    Ok(PublicEndpoint {
        listener_id: ticketed.listener_id,
        moved: moved_since(published, &ticketed.public_address),
        advertised: ticketed.public_address,
        reported,
        inbound,
        driver: Some(tokio::spawn(drive(session, reported_tx, expect_reported))),
    })
}

/// What changed, if the address is not where it was.
///
/// **Said out loud here rather than left to the caller to notice.** The people
/// who need to know are wherever the old address was written down, and this
/// process cannot reach them; the least it can do is not be quiet about it.
fn moved_since(published: Option<&PublicAddress>, now: &PublicAddress) -> Option<AddressChange> {
    let from = published?;
    if !has_moved(from, now) {
        return None;
    }
    tracing::warn!(
        %from,
        to = %now,
        "this public address has moved; whatever was told the old one is now \
         talking to nothing",
    );
    Some(AddressChange {
        from: from.clone(),
        to: now.clone(),
    })
}

/// The address to check the data plane's report against, where checking it
/// means anything.
///
/// **With a data plane chosen there is nothing to learn.** What it reports and
/// what the answer said are two copies of one read of the ledger — the server
/// puts the same value in the response and in the ticket, and the data plane
/// echoes the ticket's rather than what it bound — so they agree by
/// construction, and comparing them would dress a tautology up as a check.
///
/// **With none, the bind lands on the control plane's own data path**, which
/// has branches of its own: a shared listener, or a temporary address. Then the
/// report can differ from what was published, and it is the only place that
/// difference is visible.
fn worth_comparing(relay_chosen: bool, published: &PublicAddress) -> Option<PublicAddress> {
    (!relay_chosen).then(|| published.clone())
}

/// Whether these are different addresses, rather than differently written
/// ones.
///
/// **A false alarm costs this warning its meaning**, and it is the only signal
/// a retired data plane gives. Two spellings of one IPv6 address are the same
/// address; so is the same allocation described once with a name and once
/// without, because `hostname` is optional in the answer and its absence is the
/// server saying nothing rather than saying there is no name.
///
/// A name that changed *while both answers gave one* is a real move: whoever
/// was handed the old name is now resolving to something else, which the pair
/// alone cannot see.
fn has_moved(from: &PublicAddress, to: &PublicAddress) -> bool {
    if from.port != to.port || !same_ip(&from.ip, &to.ip) {
        return true;
    }
    match (&from.hostname, &to.hostname) {
        (Some(from), Some(to)) => from != to,
        _ => false,
    }
}

/// Whether two textual IPs are the same address.
///
/// **Parsed where they parse.** `2001:db8::1` and `2001:0db8:0:0:0:0:0:1` are
/// one address written two ways, and a string comparison would report a move
/// that did not happen. Anything that does not parse is compared as it was
/// given — it is not this function's place to decide the server sent nonsense.
fn same_ip(from: &str, to: &str) -> bool {
    match (from.parse::<IpAddr>(), to.parse::<IpAddr>()) {
        (Ok(from), Ok(to)) => from == to,
        _ => from == to,
    }
}

/// Whether the session was bound somewhere other than the published address.
///
/// **A list, and any of it will do.** The header is comma-separated and a data
/// plane may advertise more than one; what matters is whether the published
/// address is among them, not which position it is in.
///
/// **A decision rather than a log line**, so that what is asserted in a test is
/// the judgement the running code makes.
fn bound_elsewhere(expected: &PublicAddress, reported: &[SocketAddr]) -> bool {
    if reported.is_empty() {
        return false;
    }
    !reported
        .iter()
        .any(|a| a.port() == expected.port && same_ip(&a.ip().to_string(), &expected.ip))
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

    fn address(ip: &str, port: u16, hostname: Option<&str>) -> PublicAddress {
        PublicAddress {
            hostname: hostname.map(str::to_owned),
            ip: ip.to_owned(),
            port,
        }
    }

    /// **The same address is not news.** A re-ticket happens on every reopen,
    /// so saying something each time would make the one time it matters
    /// indistinguishable from the rest.
    #[test]
    fn an_address_that_stayed_put_says_nothing() {
        let now = address("203.0.113.9", 10042, Some("udp-ap1.isekai.tools"));
        assert_eq!(moved_since(Some(&now.clone()), &now), None);
        assert_eq!(
            moved_since(None, &now),
            None,
            "a first publish has nothing to have moved from",
        );
    }

    /// **A retired data plane takes its addresses with it**, and this is the
    /// only place that shows up: the control plane re-reads its ledger when it
    /// issues a ticket.
    #[test]
    fn an_address_that_moved_is_reported_with_both_halves() {
        let from = address("203.0.113.9", 10042, None);
        let to = address("198.51.100.4", 10042, None);
        let change = moved_since(Some(&from), &to).expect("it moved");
        assert_eq!(change.from, from);
        assert_eq!(change.to, to);
        // A port that moved under the same IP counts too -- what was handed out
        // was the pair.
        assert!(moved_since(Some(&from), &address("203.0.113.9", 10043, None)).is_some());
    }

    /// **The name is part of what was handed out.** A published hostname that
    /// stops resolving to this session is the same failure as a moved port,
    /// and the pair alone cannot see it.
    #[test]
    fn a_changed_name_is_a_changed_address() {
        let from = address("203.0.113.9", 10042, Some("udp-ap1.isekai.tools"));
        let to = address("203.0.113.9", 10042, Some("udp-ap2.isekai.tools"));
        assert!(moved_since(Some(&from), &to).is_some());
    }

    /// **The report is only worth checking where it can disagree.** With a data
    /// plane chosen it repeats the answer's own address; on the control plane's
    /// own data path the session may land on a shared or temporary port, and
    /// then what was published receives nothing.
    #[test]
    fn a_session_bound_somewhere_else_is_worth_saying() {
        let published = address("203.0.113.1", 10007, None);
        assert!(
            !bound_elsewhere(&published, &[]),
            "nothing reported yet is not a disagreement",
        );
        assert!(
            !bound_elsewhere(
                &published,
                &[
                    "203.0.113.1:10007".parse().unwrap(),
                    "[2001:db8::1]:10007".parse().unwrap(),
                ],
            ),
            "the published address among several is the session being where it said",
        );
        assert!(
            bound_elsewhere(&published, &["203.0.113.1:54321".parse().unwrap()]),
            "another port on this host is somewhere else",
        );
        assert!(
            bound_elsewhere(&published, &["198.51.100.4:10007".parse().unwrap()]),
            "and so is the same port number on another address -- which a \
             port-only check calls a match",
        );
    }

    /// **A false alarm here costs the real one its meaning.** Two spellings of
    /// one IPv6 address are one address; an answer that omitted the hostname
    /// said nothing about the name rather than that there is none. Either read
    /// as a move would have this warning crying wolf on every reconnection.
    #[test]
    fn a_differently_written_address_has_not_moved() {
        let long = address("2001:0db8:0:0:0:0:0:1", 10042, None);
        let short = address("2001:db8::1", 10042, None);
        assert_eq!(moved_since(Some(&long), &short), None);

        let named = address("203.0.113.9", 10042, Some("udp-ap1.isekai.tools"));
        let unnamed = address("203.0.113.9", 10042, None);
        assert_eq!(
            moved_since(Some(&named), &unnamed),
            None,
            "the answer said nothing about the name, not that there is none",
        );
        assert_eq!(moved_since(Some(&unnamed), &named), None);
    }

    /// **Comparing the report where a data plane was chosen proves nothing**,
    /// and a check that cannot fail is worse than none: it reads as evidence.
    /// The two values there are one read of the ledger, delivered twice.
    #[test]
    fn the_report_is_only_checked_where_it_can_disagree() {
        let published = address("203.0.113.9", 10042, None);
        assert_eq!(worth_comparing(true, &published), None);
        assert_eq!(worth_comparing(false, &published), Some(published));
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
    /// The address this service was published at last time, if there was a
    /// last time.
    ///
    /// **Keep it across restarts.** A data plane that retires takes its
    /// addresses with it — they cannot be moved, being literally its IP — and
    /// the answer to a fresh ticket is the only place that shows up. Without
    /// something to compare against, an address that died is
    /// indistinguishable from one that never changed.
    pub published: Option<&'a PublicAddress>,
}
