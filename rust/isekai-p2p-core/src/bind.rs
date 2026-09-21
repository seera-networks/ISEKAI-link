//! MASQUE bind session for P2P relay (feature `msquic`).
//!
//! After `POST /v1/peer/connect` returns a connection id, each peer opens a
//! MASQUE CONNECT-UDP **bind** session tagged with that id. The proxy then binds
//! a public edge socket and injects its address into the connection as a `relay`
//! candidate (server side, phase 3b-2), which the peer learns via the connection
//! views. Inbound relay UDP is forwarded to the local P2P application.
//!
//! The bind session runs on the MASQUE data path, which authenticates the same
//! way as the control plane (spec §13): `Authorization` carries the **Endpoint
//! Token** — no Auth0 token, the Endpoint Token's `sub` is the user identity —
//! plus `X-Endpoint-Id` and the PoP headers. The proxy authorizes the relay
//! edge against the Endpoint that signed the request, so this Endpoint must be
//! a party of the connection.
//!
//! The PoP signature covers an empty body (spec §8.0, CONNECT-UDP variant): a
//! CONNECT-UDP body is the capsule stream and is not known at request time.
//!
//! We use `Forward` mode — unlike `WebRTC` mode it does **not** send
//! `seera-session-create`, so no WebRTC signaling session is created; only the
//! caller-set `seera-signaling-session-id` header ties the edge address to the
//! P2P connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use channel_masque::{
    CONNECT_UDP_BIND_PATH, ForwardLimits, H3Channel, MasqueClient, MasqueClientMode,
};
/// Re-exported so a caller of [`BindSession::inbound_activity`] can name what it
/// gets back, and one draining [`BindSession::events`] can match on them,
/// without depending on the MASQUE crate directly.
pub use channel_masque::{InboundActivity, MasqueClientEvent};
use h3_util::msquic_async::H3MsQuicAsyncConnector;
use h3_util::msquic_async::h3_msquic_async::msquic_async;
use http::Uri;
use http::header::{HeaderName, HeaderValue};
use http_body::Frame;
use http_body_util::StreamBody;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::auth::AddAuthorizationLayer;

use crate::endpoint::EndpointKey;
use crate::observed::{ObservedAddressWatch, spawn_observed_address_watch};
use crate::pop;
use crate::transport::make_client_config;

/// How a relay leg's underlying QUIC connection is set up.
///
/// The default reproduces the behaviour these legs have always had, so an
/// existing caller that does not care about path migration keeps working
/// unchanged.
#[derive(Clone, Default)]
pub struct RelayOptions {
    /// Put the leg on a shared, unconnected socket pinned to a real interface
    /// address.
    ///
    /// Required for connection migration: the direct path is opened *from* this
    /// leg's binding, and the address the proxy reports for it is what the
    /// video connection advertises as a candidate
    /// (`docs/p2p_mode_migration_plan.md` §2.2.3). Without it the leg gets a
    /// connected socket that no other path can share.
    pub unconnected: bool,
    /// The msquic registration to open the leg on.
    ///
    /// `None` uses this crate's shared registration. Pass the application's own
    /// when the video connection has to share a binding with the leg — binding
    /// lookup is per-registration, so they must match.
    pub registration: Option<Arc<msquic_async::Registration>>,
}

/// Where a relay leg is actually dialled.
///
/// **Only when the control plane says it chose a relay**, which `dp_id` is.
///
/// Not "when the `masque_uri` has an authority" — it always does. With no
/// registered relay the control plane builds it from `--p2p-relay-base-url`,
/// whose default is a hardcoded production host, so a local development
/// instance emits a URI pointing at that host. Reading the authority as an
/// instruction would send a dev client's Endpoint Token and PoP there: an
/// origin nobody configured, and a credential that never should have left the
/// one that was.
///
/// So the signal is the explicit one. No relay chosen, dial what we are
/// configured to trust.
fn relay_target(masque: &Uri, proxy_url: &str, dp_id: Option<&str>) -> anyhow::Result<Uri> {
    let Some(_) = dp_id else {
        return proxy_url.parse().context("invalid proxy target URI");
    };
    let Some(_) = masque.authority() else {
        return proxy_url.parse().context("invalid proxy target URI");
    };
    let mut parts = masque.clone().into_parts();
    parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    let uri = Uri::from_parts(parts).context("invalid masque_uri")?;
    check_relay_uri(&uri)?;
    Ok(uri)
}

/// `scheme://authority` — a leg's destination with the path dropped, which is
/// the base URL every route on that host hangs off.
fn origin_of(uri: &Uri) -> String {
    match (uri.scheme_str(), uri.authority()) {
        (Some(scheme), Some(authority)) => format!("{scheme}://{authority}"),
        // `relay_target` has already refused anything without both, so this is
        // unreachable in practice; returning the whole URI beats panicking.
        _ => uri.to_string(),
    }
}

/// A URL we are about to open a QUIC connection to.
///
/// **Checked here rather than left to the transport.** `h3-util` unwraps the
/// scheme, so a value with an authority and none — which `http::Uri` parses
/// happily from `host:port` — panics inside the buffered H3 worker, where it
/// surfaces as a hang rather than an error. This value comes from the control
/// plane, and a server field is not a reason to skip validating it.
fn check_relay_uri(uri: &Uri) -> anyhow::Result<()> {
    let scheme = uri
        .scheme_str()
        .context("relay URL has no scheme (expected https://...)")?;
    if scheme != "https" {
        anyhow::bail!("relay URL scheme must be https, not {scheme}");
    }
    uri.host().context("relay URL has no host")?;
    Ok(())
}

/// Build the H3 connector for a relay leg, along with the observed-address
/// watch fed by whatever connections it opens.
///
/// Both legs need exactly this, and getting the pairing wrong (a connector
/// whose reports nobody drains, or a watch attached to the wrong connection)
/// is the kind of mistake that only shows up as a direct path that never
/// materialises — so they are built together.
fn relay_connector(
    uri: Uri,
    opts: &RelayOptions,
    shutdown: CancellationToken,
) -> anyhow::Result<(H3MsQuicAsyncConnector, ObservedAddressWatch)> {
    let (registration, config) = make_client_config(opts.registration.clone(), false)?;
    let (registration, config_qmux) = make_client_config(Some(registration), true)?;
    // The leg goes to the same proxy the control plane does, and gets the same
    // check: the certificate has to name the host dialled (#134).
    let host = uri.host().context("relay URI has no host")?.to_owned();
    let connector = H3MsQuicAsyncConnector::new(
        uri,
        config,
        Some(config_qmux),
        opts.unconnected,
        registration,
    )
    .with_peer_certificate_callback(crate::hostname::refuse_other_hosts(host));
    let (conn_tx, conn_rx) = mpsc::channel(4);
    let observed = spawn_observed_address_watch(conn_rx, shutdown);
    Ok((connector.with_channel(conn_tx), observed))
}

/// The PoP proof for the single CONNECT-UDP request a session issues: a
/// signature over `path` with an empty body (spec §8.0, CONNECT-UDP variant).
///
/// Signing once as the session is opened matches that request, since each
/// session makes exactly one. The proxy allows ±60 s of timestamp skew, so the
/// request must go out promptly after this.
fn sign_connect_udp(key: &EndpointKey, path: &str) -> pop::PopHeaders {
    pop::sign_request(key, "CONNECT", path, b"")
}

fn header_value(value: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(value).context("PoP header value is not a valid HTTP header value")
}

/// Header the relay ticket travels in (spec §8.14.3).
const RELAY_TICKET_HEADER: &str = "seera-relay-ticket";

/// Add `Seera-Relay-Ticket` to a leg's request when there is one to add.
///
/// **A leg with no ticket is not an error here.** A proxy that predates §8.14
/// issues none and asks for none; one that has `--relay-require-ticket` off
/// still binds the leg, on a single lease it will not renew. Only a proxy with
/// the flag on refuses, and it says so with `relay-ticket-required` — which is
/// the signal that this side is the one that needs upgrading, not the proxy.
fn ticket_header(ticket: Option<&str>) -> anyhow::Result<Option<(HeaderName, HeaderValue)>> {
    let Some(ticket) = ticket else {
        return Ok(None);
    };
    Ok(Some((
        HeaderName::from_static(RELAY_TICKET_HEADER),
        HeaderValue::from_str(ticket).context("relay ticket is not a valid header value")?,
    )))
}

/// Every header a bound-UDP request carries besides its bearer token.
///
/// **A value rather than a stack of layers**, because *which headers go out* is
/// the contract with the data plane — it reads them to decide whether this is a
/// relay leg or a public address — and a contract that can only be read by
/// tracing a `ServiceBuilder` chain is one a test cannot hold. This is what the
/// request gets, and what the tests below assert on.
fn bound_udp_headers(
    pop: &pop::PopHeaders,
    kind: BoundUdp<'_>,
    ticket: Option<&str>,
) -> anyhow::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut headers = vec![
        (
            HeaderName::from_static(pop::HEADER_ENDPOINT_ID),
            header_value(&pop.endpoint_id)?,
        ),
        (
            HeaderName::from_static(pop::HEADER_POP_NONCE),
            header_value(&pop.nonce)?,
        ),
        (
            HeaderName::from_static(pop::HEADER_POP_TIMESTAMP),
            header_value(&pop.timestamp)?,
        ),
        (
            HeaderName::from_static(pop::HEADER_POP_SIGNATURE),
            header_value(&pop.signature)?,
        ),
    ];
    headers.extend(temporary_address_header(kind));
    headers.extend(session_header(kind)?);
    headers.extend(ticket_header(ticket)?);
    Ok(headers)
}

/// `Seera-Signaling-Session-Id`, for the session a leg meets its peer on.
///
/// **Absent for a public address**, and that absence is what the data plane
/// reads to know which of the two it is looking at.
fn session_header(kind: BoundUdp<'_>) -> anyhow::Result<Option<(HeaderName, HeaderValue)>> {
    let (BoundUdp::BindLeg { connection_id } | BoundUdp::ConnectLeg { connection_id }) = kind
    else {
        return Ok(None);
    };
    Ok(Some((
        HeaderName::from_static("seera-signaling-session-id"),
        HeaderValue::from_str(connection_id).context("invalid connection id header value")?,
    )))
}

/// `Seera-Prefer-Temporary-Public-Address`, which asks a proxy not to spend
/// this user's allocated address on a leg.
///
/// **Absent for a public address, where the allocated one is the whole point.**
/// A co-located control plane reads this header and binds an ephemeral port
/// instead — the session comes up, and the `ip:port` handed to the world
/// receives nothing.
fn temporary_address_header(kind: BoundUdp<'_>) -> Option<(HeaderName, HeaderValue)> {
    match kind {
        BoundUdp::BindLeg { .. } => Some((
            HeaderName::from_static("seera-prefer-temporary-public-address"),
            HeaderValue::from_static("?1"),
        )),
        BoundUdp::ConnectLeg { .. } | BoundUdp::PublicAddress => None,
    }
}

/// A running MASQUE bind session. Keep it alive for the duration of the P2P
/// connection; dropping it cancels the session.
pub struct BindSession {
    /// MASQUE client events (e.g. [`MasqueClientEvent::PublicAddresses`] carries
    /// this Endpoint's edge/relay addresses).
    pub events: mpsc::Receiver<MasqueClientEvent>,
    relay_origin: String,
    observed: ObservedAddressWatch,
    inbound: InboundActivity,
    shutdown: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl BindSession {
    /// The origin this leg was actually dialled at.
    ///
    /// **The leg reports it rather than the caller recomputing it**, because
    /// the routes that act on a leg have to reach the same host it went to.
    /// Since §8.14 `POST /v1/relay/sessions/{id}/renew` is served by the *data
    /// plane* — the relay's own host — while the ticket it spends comes from
    /// the control plane. Working the destination out a second time somewhere
    /// else is how those two drift apart, and they fail quietly when they do:
    /// the control plane answers `connection-not-found` for a leg it does not
    /// hold, which reads as "the relay forgot us" rather than "you asked the
    /// wrong host".
    pub fn relay_origin(&self) -> &str {
        &self.relay_origin
    }
    /// How the proxy sees this leg — `None` until the first report arrives.
    ///
    /// The server advertises this pair to the video connection via
    /// `add_bound_addr` / `add_observed_addr` so the peer can punch a direct
    /// path to it.
    pub fn observed(&self) -> ObservedAddressWatch {
        self.observed.clone()
    }

    /// What this leg has received from the peer.
    ///
    /// The only first-hand evidence this side has that the peer is still there.
    /// A listener holds a leg until somebody tells it not to, so holding one
    /// says nothing; datagrams arriving on it do. See
    /// [`InboundActivity`](channel_masque::InboundActivity).
    pub fn inbound_activity(&self) -> InboundActivity {
        self.inbound.clone()
    }

    /// Cancel the session and wait for it to wind down.
    pub async fn close(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            wind_down("bind", task).await;
        }
    }
}

/// How long a relay leg's task may take to notice it has been cancelled.
///
/// Generous next to the one thing it has to do — stop — and short enough that
/// somebody who pressed Ctrl+C does not conclude the program is stuck.
const WIND_DOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait for a cancelled leg's task, but not forever.
///
/// **`task.await` on its own was unbounded**, and for [`ConnectRelay::close`]
/// that is on the path out of every initiator here: `InitiatorSession::close`
/// ends by closing its relay, and that is what a Ctrl+C reaches. A task that
/// does not observe the cancel — parked in an H3 send to a relay that has gone,
/// say — held the process open with nothing said and no way out, because the
/// first Ctrl+C had already replaced SIGINT's default disposition.
///
/// [`BindSession::close`] has no caller in this workspace today; the listener
/// side tears its legs down inside `ListenerSession::close`, which aborts
/// before awaiting and is itself bounded by whatever waits on `listener::run`.
/// Bounding this one too is for the caller that turns up later, not for a bug
/// it has now.
///
/// The leg is being torn down either way; the timeout only decides whether this
/// waits to see it happen. Aborting after it is what makes the difference
/// between a tidy exit and a hung one.
async fn wind_down(what: &str, task: tokio::task::JoinHandle<()>) {
    let aborter = task.abort_handle();
    if tokio::time::timeout(WIND_DOWN_TIMEOUT, task).await.is_err() {
        tracing::warn!(
            ?WIND_DOWN_TIMEOUT,
            "the {what} leg did not stop in time; abandoning it",
        );
        aborter.abort();
    }
}

impl Drop for BindSession {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Open a MASQUE bind session tagged with `connection_id`, forwarding inbound
/// relay UDP to `forward_to` (the local P2P application).
///
/// `endpoint_token` and `key` must belong to the Endpoint that is a party of
/// the connection: the proxy authorizes the relay edge against the Endpoint the
/// PoP signature proves possession of, not against the user.
///
/// `ticket` is the relay ticket for **this Endpoint's** leg (spec §8.14),
/// fetched with `ProxyClient::issue_relay_ticket`. It is what brings the leg
/// into existence on a proxy that has §8.14; `None` is the pre-§8.14 behaviour
/// and is refused by a proxy running `--relay-require-ticket`.
///
/// Returns only once the CONNECT-UDP bind session is **established** — i.e. the
/// proxy has bound the relay edge and the leg can carry datagrams. Awaiting
/// this before the application starts relaying closes a startup race where the
/// far peer's first packets reached the edge before this leg was ready and were
/// dropped (the tunneled QUIC handshake then stalled).
#[allow(clippy::too_many_arguments)]
pub async fn open_bind_session(
    target: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    connection_id: &str,
    forward_to: SocketAddr,
    ticket: Option<&str>,
    opts: RelayOptions,
) -> anyhow::Result<BindSession> {
    open_bound_udp(
        target,
        endpoint_token,
        key,
        BoundUdp::BindLeg { connection_id },
        forward_to,
        ticket,
        opts,
    )
    .await
}

/// Open the bound-UDP session that **is** this Endpoint's public address
/// (`docs/public_listener_client_plan.md` P1).
///
/// The socket the proxy binds for this session is the `ip:port` the control
/// plane allocated, so traffic anyone sends there arrives here and is forwarded
/// to `forward_to`. `target` is the `masque_uri` from the Listener's `relay`,
/// and `ticket` the paper from `POST /v1/public-listeners/{id}/ticket`.
///
/// **`ticket` is `None` only when the address is on the control plane's own
/// data path** — the case where the Listener's answer carried no `relay`.
/// There the session's Endpoint Token is the authorization. A registered data
/// plane with no ticket has nothing to check and refuses.
///
/// # Why this is not [`open_bind_session`] with an argument
///
/// A relay leg and a public address differ by two headers, and **the data
/// plane decides which request it is looking at from them** rather than from
/// the ticket inside — deliberately, so that a ticket cannot choose the check
/// applied to it. Reusing the leg's call would send both:
///
/// | header | on a leg | here |
/// | --- | --- | --- |
/// | `Seera-Signaling-Session-Id` | names the session the two halves meet on | **absent.** Sending it puts a `role: public` ticket on the leg path, which refuses it |
/// | `Seera-Prefer-Temporary-Public-Address` | asks for a throwaway address | **absent.** Sending it makes a co-located control plane skip the allocated port and bind an ephemeral one — **the bind succeeds and the published address is dead** |
///
/// The second is the reason this is a separate function rather than an
/// `Option` parameter: it fails silently, on the deployment that looks
/// simplest.
///
/// # One socket per stranger
///
/// **This session forwards in [`MasqueClientMode::Forward`], which binds a
/// fresh local UDP socket for every remote source address it sees.** On a relay
/// leg that is one peer. Here the senders are whoever finds the address: a
/// single datagram from an unseen source port costs a socket and a context id,
/// nothing authenticates the sender — the ticket checked at bind time says
/// nothing about who sends afterwards — and there is no cap and no eviction.
///
/// **A caller that publishes an address before that is bounded is publishing a
/// way to exhaust its own file descriptors.** The cap is P1b of
/// `docs/public_listener_client_plan.md`, and it is deliberately ordered before
/// anything that uses this: binding an address and exposing it are the same
/// act.
#[allow(clippy::too_many_arguments)]
pub async fn open_public_bind_session(
    target: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    forward_to: SocketAddr,
    ticket: Option<&str>,
    opts: RelayOptions,
) -> anyhow::Result<BindSession> {
    open_bound_udp(
        target,
        endpoint_token,
        key,
        BoundUdp::PublicAddress,
        forward_to,
        ticket,
        opts,
    )
    .await
}

/// How many senders a public address keeps sockets for, and how long one may
/// stay quiet.
///
/// **Numbers chosen to be wrong in the cheaper direction.** Too low evicts
/// somebody real; too high leaves more sockets held than anyone needed. So the
/// count sits far above any audience this is likely to have — a service behind
/// one published address — and the idle window far above the gap between two
/// datagrams of a conversation that is still going, while staying short enough
/// that a flood is reclaimed in minutes rather than for the life of the
/// session.
const PUBLIC_FORWARD_LIMITS: ForwardLimits = ForwardLimits {
    max_sources: 1024,
    idle_after: std::time::Duration::from_secs(120),
};

/// Which of the two bound-UDP sessions is being opened.
///
/// **The difference is a pair of headers, and it is not a flag.** What the data
/// plane does with the request turns entirely on them, so naming the two cases
/// is what keeps a caller from asking for one and sending the other's headers.
#[derive(Debug, Clone, Copy)]
enum BoundUdp<'a> {
    /// The listener's side of a relay, which binds the edge itself.
    ///
    /// **Asks not to be given the user's allocated public address**: this leg
    /// wants any address that carries packets, and spending the one somebody
    /// published would take it away from what published it.
    BindLeg { connection_id: &'a str },
    /// The initiator's side, which binds an ephemeral loopback source.
    ///
    /// **Asks for nothing about public addresses**, because it is not being
    /// given one — the question does not arise on this side, and asking anyway
    /// would be a header sent on the strength of a shared code path rather
    /// than of what the request is.
    ConnectLeg { connection_id: &'a str },
    /// A public address, which meets nobody and is exactly the allocated one.
    PublicAddress,
}

#[allow(clippy::too_many_arguments)]
async fn open_bound_udp(
    target: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    kind: BoundUdp<'_>,
    forward_to: SocketAddr,
    ticket: Option<&str>,
    opts: RelayOptions,
) -> anyhow::Result<BindSession> {
    let uri: Uri = target.parse().context("invalid proxy target URI")?;
    // **Checked on this path too.** The connect leg validates inside
    // `relay_target`; a bind leg took its target on trust, so a
    // `relay_base_url` with no scheme — which `http::Uri` parses happily from
    // `host:port` — got as far as the transport and failed per request. The
    // lease loop would then retry that to the lapse, arriving at the same
    // ten-minute death this route was fixed to avoid.
    check_relay_uri(&uri)?;
    // Taken before the URI is moved into the connector.
    let dialled = origin_of(&uri);
    let pop = sign_connect_udp(key, CONNECT_UDP_BIND_PATH);
    let shutdown = CancellationToken::new();
    let (connector, observed) = relay_connector(uri.clone(), &opts, shutdown.clone())?;
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );

    // **One list, and the request carries exactly it.** Spelled as a stack of
    // layers, what a request sends could only be checked by reading the stack —
    // so a test could confirm every helper and still miss a layer deleted from
    // the assembly, which is the one edit that turns a public bind into a leg.
    let headers = bound_udp_headers(&pop, kind, ticket)?;
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(endpoint_token))
        .map_request(move |mut req: http::Request<_>| {
            for (name, value) in headers.clone() {
                req.headers_mut().append(name, value);
            }
            req
        })
        .service(channel);

    let (out_tx, out_rx) = mpsc::channel(32);
    // Signals that `start` has established the session (or failed to). The
    // caller awaits this so it only returns once the leg is ready.
    let (ready_tx, ready_rx) = oneshot::channel();
    let session_shutdown = shutdown.clone();
    // Built here rather than in the task so its activity handle can be taken
    // before it moves; afterwards there is nothing left to ask.
    let mut client = MasqueClient::new(channel, None);
    // **A public address's senders are not a known set** (§3.5), so the sockets
    // they cost have to have an end. A relay leg gets no limit, because a limit
    // on its one peer is a limit on nothing.
    if let BoundUdp::PublicAddress = kind {
        client = client.with_forward_limits(PUBLIC_FORWARD_LIMITS);
    }
    let inbound = client.inbound_activity();
    let task = tokio::spawn(async move {
        match client
            .start(MasqueClientMode::Forward(forward_to), session_shutdown)
            .await
        {
            Ok(mut events) => {
                let _ = ready_tx.send(Ok(()));
                // Keep the client alive and forward events until it ends.
                while let Some(event) = events.recv().await {
                    if out_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                let _ = ready_tx.send(Err(anyhow::anyhow!(
                    "failed to start MASQUE bind session: {e:?}"
                )));
            }
        }
    });

    match ready_rx.await {
        Ok(Ok(())) => Ok(BindSession {
            events: out_rx,
            // Normalized the same way the connect leg does, so the two report
            // the same shape and `/renew` is appended to a base URL either way.
            relay_origin: dialled,
            observed,
            inbound,
            shutdown,
            task: Some(task),
        }),
        Ok(Err(e)) => {
            shutdown.cancel();
            Err(e)
        }
        Err(_) => {
            shutdown.cancel();
            Err(anyhow::anyhow!(
                "MASQUE bind session ended before it was established"
            ))
        }
    }
}

/// A running CONNECT-UDP forward-proxy relay leg (the **initiator** side). Keep
/// it alive for the duration of the P2P connection; dropping it cancels the
/// session.
pub struct ConnectRelay {
    /// The local UDP address the application should send its traffic to.
    pub local_addr: SocketAddr,
    relay_origin: String,
    observed: ObservedAddressWatch,
    shutdown: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl ConnectRelay {
    /// The origin this leg was actually dialled at.
    ///
    /// **The leg reports it rather than the caller recomputing it**, because
    /// the routes that act on a leg have to reach the same host it went to.
    /// Since §8.14 `POST /v1/relay/sessions/{id}/renew` is served by the *data
    /// plane* — the relay's own host — while the ticket it spends comes from
    /// the control plane. Working the destination out a second time somewhere
    /// else is how those two drift apart, and they fail quietly when they do:
    /// the control plane answers `connection-not-found` for a leg it does not
    /// hold, which reads as "the relay forgot us" rather than "you asked the
    /// wrong host".
    pub fn relay_origin(&self) -> &str {
        &self.relay_origin
    }
    /// How the proxy sees this leg — `None` until the first report arrives.
    ///
    /// Note this is *not* [`local_addr`](ConnectRelay::local_addr), which is the
    /// loopback socket the application sends to. This is the leg's own binding
    /// out on the network, and the pair the video connection passes to
    /// `add_candidate_addr` to offer a direct path.
    pub fn observed(&self) -> ObservedAddressWatch {
        self.observed.clone()
    }

    /// The token that winds this leg down, for a holder that has to end the
    /// session from somewhere else.
    ///
    /// Cancelling it is the local half of a teardown: the leg stops, the video
    /// connection riding it fails, and the application sees the session end.
    /// [`close`](Self::close) does the same and then waits.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Cancel the relay and wait for it to wind down.
    pub async fn close(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            wind_down("connect relay", task).await;
        }
    }
}

impl Drop for ConnectRelay {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Open the initiator relay leg: a concrete-target CONNECT-UDP session to
/// `masque_uri` through the proxy at `proxy_url`, bridging a local UDP socket
/// bound at `local_bind` (the local application sends/receives there).
///
/// **Where the connection goes** is the relay the control plane chose — the one
/// `dp_id` names — and `proxy_url` when it chose none. What travels as the
/// CONNECT-UDP target is the **path** of `masque_uri`, which is also what the
/// PoP signs over; the two are separate, and were conflated before: the
/// authority was parsed and thrown away, so a relay on another host was named
/// in the response and never reached. The session carries
/// `seera-signaling-session-id: <connection_id>` so the proxy binds this leg to
/// the relay rendezvous (ephemeral loopback source) — the same identifier the
/// target's bind leg uses. Returns the bound local address.
///
/// Authenticated with the initiator's Endpoint Token + PoP, like the bind leg.
/// `ticket` is the initiator's relay ticket (spec §8.14) — the `connect`
/// response carries it, so this side rarely has to ask for one.
#[allow(clippy::too_many_arguments)]
pub async fn open_connect_relay(
    proxy_url: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    connection_id: &str,
    masque_uri: &str,
    local_bind: SocketAddr,
    ticket: Option<&str>,
    // The relay the control plane chose, from `RelayInfo::dp_id`. `None` — no
    // registered relay — dials `proxy_url`.
    dp_id: Option<&str>,
    opts: RelayOptions,
) -> anyhow::Result<ConnectRelay> {
    let masque: Uri = masque_uri.parse().context("invalid masque_uri")?;
    let target_path = masque
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| masque.path().to_owned());
    // Signed over the path actually sent as `:path`, which is the masque_uri's
    // path.
    let pop = sign_connect_udp(key, &target_path);

    // **Dial the host the `masque_uri` names**, not the control plane.
    //
    // This used to take the path and discard the authority, so every leg went
    // to the proxy the control plane happens to live on. That was invisible
    // while the two were one process — and it is exactly what "the control
    // plane decides which data plane you use, in its answer" was supposed to
    // mean. A relay on another host was named in the response and never dialled.
    //
    // `proxy_url` remains the fallback for a `masque_uri` with no authority,
    // which is what a control plane that has no registered relay still returns.
    let uri = relay_target(&masque, proxy_url, dp_id)?;
    // Kept as the leg's own answer to "where did this go", so nothing has to
    // work it out again — see [`ConnectRelay::relay_origin`].
    let dialled = origin_of(&uri);
    let shutdown = CancellationToken::new();
    let (connector, observed) = relay_connector(uri.clone(), &opts, shutdown.clone())?;
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );
    // **An initiator's leg, which is not a bind leg.** It meets its peer on
    // the same session, and asks nothing about public addresses: it binds
    // an ephemeral loopback source rather than being handed an address.
    let headers = bound_udp_headers(&pop, BoundUdp::ConnectLeg { connection_id }, ticket)?;
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(endpoint_token))
        .map_request(move |mut req: http::Request<_>| {
            for (name, value) in headers.clone() {
                req.headers_mut().append(name, value);
            }
            req
        })
        .service(channel);

    let socket = Arc::new(
        tokio::net::UdpSocket::bind(local_bind)
            .await
            .context("failed to bind local relay socket")?,
    );
    let local_addr = socket
        .local_addr()
        .context("failed to read local relay socket address")?;

    let session_shutdown = shutdown.clone();
    // Signals that `start_connect_udp` has established the leg (or failed to).
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut client = MasqueClient::new(channel, None);
        match client
            .start_connect_udp(&target_path, Vec::new(), socket, session_shutdown.clone())
            .await
        {
            Ok(()) => {
                let _ = ready_tx.send(Ok(()));
            }
            Err(e) => {
                let _ = ready_tx.send(Err(anyhow::anyhow!(
                    "failed to start CONNECT-UDP relay leg: {e:?}"
                )));
                return;
            }
        }
        // Keep the client (and its H3 connection) alive until shutdown.
        session_shutdown.cancelled().await;
    });

    match ready_rx.await {
        Ok(Ok(())) => Ok(ConnectRelay {
            local_addr,
            relay_origin: dialled,
            observed,
            shutdown,
            task: Some(task),
        }),
        Ok(Err(e)) => {
            shutdown.cancel();
            Err(e)
        }
        Err(_) => {
            shutdown.cancel();
            Err(anyhow::anyhow!(
                "CONNECT-UDP relay leg ended before it was established"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names a request would carry, in order.
    fn names(headers: &[(HeaderName, HeaderValue)]) -> Vec<&str> {
        headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    fn value_of<'a>(headers: &'a [(HeaderName, HeaderValue)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap())
    }

    fn a_pop() -> pop::PopHeaders {
        sign_connect_udp(&EndpointKey::generate(), CONNECT_UDP_BIND_PATH)
    }

    /// **The whole request, not the helpers.** Asserting each helper leaves the
    /// assembly free to drop one: a public bind that sent the session header
    /// would be taken for a relay leg, and one that sent the temporary-address
    /// preference would come up bound to an ephemeral port while the published
    /// address received nothing. So what is read here is the list the request
    /// actually carries.
    #[test]
    fn a_public_address_carries_neither_of_the_legs_headers() {
        let headers =
            bound_udp_headers(&a_pop(), BoundUdp::PublicAddress, Some("eyJ.JWT")).unwrap();
        assert_eq!(
            names(&headers),
            vec![
                pop::HEADER_ENDPOINT_ID,
                pop::HEADER_POP_NONCE,
                pop::HEADER_POP_TIMESTAMP,
                pop::HEADER_POP_SIGNATURE,
                RELAY_TICKET_HEADER,
            ],
            "a public bind sends its PoP and its ticket, and nothing that says `leg`",
        );
    }

    /// The listener's leg meets its peer, and asks not to be handed the
    /// address somebody published.
    #[test]
    fn a_bind_leg_meets_its_peer_and_declines_the_allocated_address() {
        let kind = BoundUdp::BindLeg {
            connection_id: "conn_1",
        };
        let headers = bound_udp_headers(&a_pop(), kind, None).unwrap();
        assert_eq!(
            value_of(&headers, "seera-signaling-session-id"),
            Some("conn_1"),
        );
        assert_eq!(
            value_of(&headers, "seera-prefer-temporary-public-address"),
            Some("?1"),
        );
        assert!(
            value_of(&headers, RELAY_TICKET_HEADER).is_none(),
            "none given"
        );
    }

    /// **The initiator's leg asks nothing about public addresses.** It binds an
    /// ephemeral loopback source, so the question does not arise — and sending
    /// the header anyway would be a header sent on the strength of a shared
    /// code path rather than of what the request is.
    #[test]
    fn a_connect_leg_says_nothing_about_public_addresses() {
        let kind = BoundUdp::ConnectLeg {
            connection_id: "conn_1",
        };
        let headers = bound_udp_headers(&a_pop(), kind, Some("eyJ.JWT")).unwrap();
        assert_eq!(
            value_of(&headers, "seera-signaling-session-id"),
            Some("conn_1"),
        );
        assert!(value_of(&headers, "seera-prefer-temporary-public-address").is_none());
        assert_eq!(value_of(&headers, RELAY_TICKET_HEADER), Some("eyJ.JWT"));
    }

    /// **What the leg reports is a base URL, not the CONNECT-UDP path.**
    ///
    /// `relay_origin` is what the lease loop appends
    /// `/v1/relay/sessions/{id}/renew` to, so carrying the leg's own long
    /// `.well-known/masque/...` path through would address a route that does
    /// not exist.
    #[test]
    fn the_origin_a_leg_reports_is_the_hosts_base_url() {
        let masque: Uri = "https://dp1abc.relay.example:8443/.well-known/masque/udp/10.0.0.1/443/"
            .parse()
            .unwrap();
        let dialled = relay_target(&masque, "https://cp.example:6443", Some("dp1abc")).unwrap();
        assert_eq!(origin_of(&dialled), "https://dp1abc.relay.example:8443");
    }

    /// With no relay chosen the origin is the control plane's own, so the
    /// renewal path needs no special case for the co-located data plane.
    #[test]
    fn with_no_relay_the_origin_is_the_control_plane() {
        let masque: Uri = "https://ignored.example:8443/.well-known/masque/udp/10.0.0.1/443/"
            .parse()
            .unwrap();
        let dialled = relay_target(&masque, "https://cp.example:6443", None).unwrap();
        assert_eq!(origin_of(&dialled), "https://cp.example:6443");
    }

    /// **Where a leg is dialled is what the control plane chose**, and the
    /// choice arrives as `dp_id`, not as the shape of the URI.
    ///
    /// This took the path and discarded the host, so every leg went to the
    /// control plane whatever the response said — which made a relay on
    /// another host something that was named and never dialled.
    #[test]
    fn a_chosen_relay_is_where_the_leg_is_dialled() {
        let masque: Uri =
            "https://dp1abc.relay.example:8443/.well-known/masque/udp/127.0.0.1/30001/"
                .parse()
                .unwrap();
        let dialled = relay_target(&masque, "https://cp.example:6443", Some("dp1abc")).unwrap();
        assert_eq!(dialled.host(), Some("dp1abc.relay.example"));
        assert_eq!(dialled.port_u16(), Some(8443));
        // The connection goes to the relay's root; the masque_uri's path is
        // what travels as `:path`, and the two are separate values.
        assert_eq!(dialled.path(), "/");
    }

    /// **A URI pointing elsewhere is not an instruction to go there.**
    ///
    /// With no registered relay the control plane builds `masque_uri` from
    /// `--p2p-relay-base-url`, whose default is a hardcoded production host —
    /// so a local development instance emits a URI naming that host. Reading
    /// the authority as the destination would send a dev client's Endpoint
    /// Token and PoP to an origin nobody configured.
    #[test]
    fn no_chosen_relay_dials_the_configured_proxy_however_the_uri_looks() {
        let masque: Uri = "https://link.isekai.tools:6443/.well-known/masque/udp/127.0.0.1/30001/"
            .parse()
            .unwrap();
        let dialled = relay_target(&masque, "https://localhost:8443", None).unwrap();
        assert_eq!(
            dialled.host(),
            Some("localhost"),
            "a client with no relay chosen was sent to the URI's host",
        );
        assert_eq!(dialled.port_u16(), Some(8443));
    }

    /// A relay URL with no scheme parses as an authority and panics deep in
    /// the H3 worker, where it shows up as a hang. Refused here instead.
    #[test]
    fn a_relay_url_without_a_scheme_is_refused() {
        let masque: Uri = "dp1abc.relay.example:8443".parse().unwrap();
        assert!(relay_target(&masque, "https://cp.example:6443", Some("dp1abc")).is_err());
        let plain: Uri = "http://dp1abc.relay.example:8443/x".parse().unwrap();
        assert!(
            relay_target(&plain, "https://cp.example:6443", Some("dp1abc")).is_err(),
            "a relay leg must not be opened over plaintext",
        );
    }
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::Verifier;

    /// What the proxy verifies: the signature covers `CONNECT`, the exact path
    /// on the wire, and an empty body — never the capsule stream.
    #[test]
    fn connect_udp_pop_is_verifiable_over_an_empty_body() {
        let key = EndpointKey::generate();
        let pop = sign_connect_udp(&key, CONNECT_UDP_BIND_PATH);

        assert_eq!(pop.endpoint_id, key.endpoint_id());
        let canonical = pop::canonical_pop_string(
            "CONNECT",
            CONNECT_UDP_BIND_PATH,
            &pop.endpoint_id,
            &pop.timestamp,
            &pop.nonce,
            b"",
        );
        let sig = Signature::from_der(&URL_SAFE_NO_PAD.decode(&pop.signature).unwrap()).unwrap();
        let public = p256::PublicKey::from_jwk_str(&key.public_jwk().to_string()).unwrap();
        assert!(
            p256::ecdsa::VerifyingKey::from(public)
                .verify(canonical.as_bytes(), &sig)
                .is_ok()
        );
        // A signature made for the bind path must not verify for a relay leg's
        // concrete target: the path is bound by the signature.
        let other = pop::canonical_pop_string(
            "CONNECT",
            "/.well-known/masque/udp/127.0.0.1/30001/",
            &pop.endpoint_id,
            &pop.timestamp,
            &pop.nonce,
            b"",
        );
        assert_ne!(canonical, other);
    }

    /// A leg with no ticket adds no header, and one with a ticket adds
    /// exactly it.
    ///
    /// **`None` is not an error here** (spec §8.14.5): a proxy that predates
    /// tickets asks for none, and one that wants one says so on the leg with
    /// `relay-ticket-required` — which names the real problem where a local
    /// error about a missing ticket would not.
    #[test]
    fn the_ticket_header_is_added_only_when_there_is_a_ticket() {
        assert!(ticket_header(None).unwrap().is_none());
        assert!(ticket_header(Some("eyJ.JWT.sig")).unwrap().is_some());
        // A ticket is a JWT, so this cannot normally happen — but a value that
        // would not survive as a header must fail here rather than silently
        // opening an unticketed leg.
        assert!(ticket_header(Some("bad\nvalue")).is_err());
    }

    /// Every PoP value must survive as an HTTP header value.
    #[test]
    fn pop_values_are_valid_header_values() {
        let key = EndpointKey::generate();
        let pop = sign_connect_udp(&key, "/.well-known/masque/udp/127.0.0.1/30001/");
        for (_, value) in pop.as_pairs() {
            header_value(value).expect("PoP value is a valid header value");
        }
    }
}
