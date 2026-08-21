//! The parts of holding a peer QUIC connection that are not about what it
//! carries.
//!
//! **`docs/portal_plan.md` §4.4.** `camera-core::video` is ~1,700 lines of
//! which the MJPEG is the small part; the rest — dialling across the peer's
//! bind gap, the certificate callback, keepalives, the registration lifecycle —
//! is peer-QUIC plumbing that a second consumer would otherwise fork, and every
//! fix this year with it.
//!
//! The entry point is [`dial`]: one call that opens a configuration, dials
//! across the peer's relay-bind gap, refuses a certificate that is for the
//! wrong name or is not the key the peer signed for, and hands back a
//! [`PeerSession`] that owns everything msquic needs kept alive.
//!
//! Under it are the rules, which came first (1a) because each is a way to hang
//! a process that every consumer would otherwise rediscover — phase 0
//! rediscovered two of them inside a week:
//!
//! * [`PeerSession`], the rule that a `Configuration` outlives its
//!   `Connection` and a registration outlives both
//! * [`drain_registration`], the rule that a registration is emptied before it
//!   is dropped, and [`PeerSession::drain`], which owns that rule rather than
//!   restating it
//! * [`client_config`] (1b) and the constants it reads, chosen for a connection
//!   that rides a MASQUE relay leg and may migrate off it
//! * [`AttestedPeer`] and [`install_certificate_check`] (1c-i) — what settles
//!   whether the connection is to the Endpoint the proxy named, and the
//!   callback that enforces that and the hostname
//!
//! What stays in `camera-core` is what the connection carries: MJPEG frames,
//! the path-event loop, the video listener.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use isekai_p2p_core::attestation::Attestation;
use isekai_p2p_core::proxy::PeerConnection;
use time::OffsetDateTime;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

use crate::agent::ObservedAddress;

/// How long a video connection may carry nothing before it is closed.
///
/// Also the answer to "was this connection still alive?" for anything that
/// could not watch it — an iOS viewer coming back from the background knows
/// only how long it was away, and longer than this means the connection is
/// gone whatever the app still holds. Exported for that.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the whole connection may go without sending before it gets a PING.
///
/// Distinct from [`DIRECT_PATH_KEEPALIVE`], which is per path; this one is
/// reset by any activity and so only fires on a connection carrying nothing.
/// Well inside the 30 s idle timeout, with two attempts to spare.
pub const CONNECTION_KEEPALIVE: Duration = Duration::from_secs(10);

/// How long a path may go without sending before it gets a PING.
///
/// `PathKeepAliveIntervalMs`, and **not** `KeepAliveIntervalMs`. The two look
/// interchangeable and are not: the connection keepalive is re-armed by
/// `QuicConnResetIdleTimeout` on every ack-eliciting packet received and on the
/// first packet put in flight, so it fires only once the *whole connection* has
/// gone quiet. A video connection is never quiet — that is what it is for — so
/// it never fired, and the direct path decayed exactly as it did before, with
/// the setting apparently in place. This one is counted per path, from what that
/// path itself carried, and nothing resets it.
///
/// Both ends still have to set it: the timer runs off each connection's own
/// settings, and the default is 0, meaning no PING is ever sent.
///
/// Ten seconds is well inside the 30 s idle timeout and cheap — a path that is
/// carrying traffic on its own never gets a redundant PING.
pub const DIRECT_PATH_KEEPALIVE: Duration = Duration::from_secs(10);

use msquic_async::{msquic, Connection, ConnectionError, ConnectionStartError, Registration};

/// Shut a registration down and wait for its handles, returning whether they
/// went.
///
/// **A registration dropped with any live handle blocks in
/// `RegistrationClose`**, uninterruptibly and with no message. Applications
/// avoid meeting it by leaving through `_exit` (see
/// `camera_core::shutdown::shutdown_and_exit`); tests and libraries have to
/// wait properly, and the four ways to get this wrong are written up in
/// `docs/portal_plan.md` §4.4.
///
/// What must be gone first is every **tracked** handle: connections, their
/// streams, and listeners.
///
/// **A `Configuration` is not one of them, and goes the other way round.**
/// msquic-async leaves it untracked deliberately and says to drop it *after*
/// `wait_idle` resolves (`submodules/msquic-async-rs/docs/registration-wait-idle-design.md`
/// §7). Dropping it first is what [`PeerSession`]'s field order exists to
/// prevent, and what [`PeerSession::drain`] orders around this call — which is
/// why this sentence is worth being exact about.
///
/// Takes the registration by reference because the caller usually holds an
/// `Arc`.
pub async fn drain_registration(reg: &Registration, timeout: Duration) -> bool {
    reg.shutdown();
    let drained = tokio::time::timeout(timeout, reg.wait_idle()).await.is_ok();
    if !drained {
        tracing::warn!(?timeout, "msquic registration still has live handles");
    }
    drained
}

/// What [`client_config`] should build.
pub struct ClientOptions<'a> {
    /// The protocol this connection speaks. Distinct per application: a peer
    /// that offers a different one should fail at the handshake rather than at
    /// the first frame.
    pub alpn: &'a str,
    /// Let msquic validate the peer's certificate chain. Off is dev-only.
    ///
    /// **This is chain validation and nothing else.** Nothing here checks that
    /// the certificate names the host dialled: on the quictls platforms msquic
    /// verifies with a bare `X509_verify_cert` and never sets
    /// `X509_VERIFY_PARAM_set1_host`, so a chain-valid certificate issued for
    /// *any* name is accepted. That is #134, and what closes it is
    /// [`install_certificate_check`].
    ///
    /// **[`dial`] installs it; this is the low-level way in.** A caller that
    /// builds its own configuration, sets this, and installs nothing has #134
    /// back — which is why [`DialOptions::verify`] means both and this one does
    /// not.
    pub verify: bool,
    /// Offer a direct path and let the connection use it.
    pub enable_migration: bool,
    /// Ask to be shown the peer's certificate, so a caller can check it.
    pub pinning: bool,
    /// Advertise that this end will receive QUIC datagrams.
    ///
    /// **Off means the *peer* may not send them.** `max_datagram_frame_size` is
    /// what a receiver advertises, so leaving this unset denies the other
    /// direction: msquic-async answers `DgramSendError::Denied` and nothing
    /// leaves. The camera does not use datagrams and pays nothing for that;
    /// portal's UDP forwarding needs both directions and so needs this.
    pub datagrams: bool,
}

/// A client configuration for a peer QUIC connection.
///
/// **Moved from `camera-core::video::video_client_config` unchanged**, with the
/// ALPN made a parameter (plan §4.4, phase 1b). Every number below was chosen
/// for a connection that rides a MASQUE relay leg and may migrate off it —
/// which is what this layer is about — and the comments are the reasoning
/// rather than decoration: the MTU cap is sized to the CONNECT-UDP tunnel, and
/// the two keepalives cover two different things that cost a field test to tell
/// apart.
pub fn client_config(
    reg: Option<Arc<Registration>>,
    opts: ClientOptions<'_>,
) -> anyhow::Result<(Arc<Registration>, msquic::Configuration)> {
    let ClientOptions {
        alpn,
        verify,
        enable_migration,
        pinning,
        datagrams,
    } = opts;
    let reg = match reg {
        Some(reg) => reg,
        None => Arc::new(Registration::new(&msquic::RegistrationConfig::default())?),
    };
    let alpn = [msquic::BufferRef::from(alpn)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(IDLE_TIMEOUT.as_millis() as u64)
        // Keep a single unanswered handshake alive long enough to span
        // the peer's relay-bind gap: msquic keeps retransmitting the
        // Initial on ONE connection until the far leg comes up, rather
        // than many short-lived attempts (which poison the relay path).
        .set_HandshakeIdleTimeoutMs(60_000)
        // Keep the connection from going idle into the timeout above.
        //
        // The other keepalive, and both are wanted. `DIRECT_PATH_KEEPALIVE`
        // below explains why this one does not keep a *path* warm: it is
        // re-armed by activity anywhere on the connection, so on a connection
        // carrying video it never fires at all. What it covers is the case
        // where there is no video — the camera stopped streaming, or has not
        // started — and the connection would otherwise be dropped at thirty
        // seconds with the viewer still sitting there. The listener side has
        // had this all along (`isekai_link_utils`); this side had not.
        .set_KeepAliveIntervalMs(CONNECTION_KEEPALIVE.as_millis() as u32)
        // msquic clamps `MaximumMtu` up to QUIC_DPLPMTUD_MIN_MTU
        // (1248), so asking for less is silently ignored — 1248 is what
        // this connection actually uses, and stating it keeps the code
        // honest about the cap it is applying.
        //
        // The cap exists so a video QUIC packet plus CONNECT-UDP
        // encapsulation fits inside the relay tunnel's HTTP datagram.
        // Without it the default 1500 overflows the tunnel and packets
        // are dropped as `TooLarge`. The outer connection's
        // `MinimumMtu` (see `isekai_p2p_core::transport`, which does the
        // arithmetic) is what is sized to carry 1248 plus that
        // encapsulation. Deliberately not repeated here: this said 1400
        // for a while after that floor became 1350, and a number in two
        // places is a number that disagrees with itself.
        .set_MaximumMtu(1248)
        .set_PeerUnidiStreamCount(100)
        .set_StreamMultiReceiveEnabled();
    // Asked for by whoever will receive them, which is why it is an option
    // rather than always on: this advertises to the *peer* that it may send.
    let settings = if datagrams {
        settings.set_DatagramReceiveEnabled()
    } else {
        settings
    };
    // NAT-traversal mode is what makes the peer probe our candidate address and
    // report a `PathValidated` for the direct path; the observed-address reports
    // are the other half of the exchange.
    //
    // Multipath goes on top of that rather than instead of it. NAT traversal is
    // what opens a path between two peers behind NATs — an application adding
    // paths by hand cannot hole-punch — so the probing stays exactly as it was;
    // what multipath changes is what a validated path *becomes*: another active
    // path instead of somewhere to migrate to.
    //
    // And the path keepalive is what stops the second path decaying while
    // nothing is sent on it, which is the whole of risk #24. It is not optional,
    // it is not the connection keepalive — see `DIRECT_PATH_KEEPALIVE` for why
    // that distinction cost a field test — and it is not symmetric with the
    // listener's: the timer runs off each connection's own settings, so this
    // side pinging says nothing about the other side. The listener sets its own
    // (`isekai_link_utils::PATH_KEEP_ALIVE_INTERVAL_MS`), which is why both ends
    // ping rather than one.
    //
    // **These PINGs are also what tells the camera this viewer is still here.**
    // Once the video is on the direct path they are the only thing this side
    // still sends across the relay leg, and the camera renews the connection's
    // lease only while something arrives on it
    // (`ListenerSession::renew_connections`). Reading this as "the direct path's
    // keepalive, so the relay path does not need it" would cut this viewer off
    // one connect TTL into watching.
    let settings = if enable_migration {
        settings
            .set_ReceiveObservedAddressReports()
            .set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
            .set_MultipathEnabled()
            .set_PathKeepAliveIntervalMs(DIRECT_PATH_KEEPALIVE.as_millis() as u32)
    } else {
        settings
    };
    let config = reg.open_configuration(&alpn, Some(&settings))?;
    // The video connection has its own `CredentialConfig`, separate from the
    // control/relay one in `isekai_p2p_core::transport`, so it needs the same
    // treatment rather than inheriting it.
    //
    // **`USE_TLS_BUILTIN_CERTIFICATE_VALIDATION` is deliberately not set here.**
    // It was, briefly, and it is wrong on three of the four platforms:
    //
    // * Windows builds msquic with schannel (`CMakeLists.txt`), and
    //   `tls_schannel.c` answers `QUIC_STATUS_INVALID_PARAMETER` to any
    //   credential carrying this flag -- so `load_credential` fails and *every*
    //   client connection stops being possible, insecure escape hatch included.
    // * Linux and Android are `CX_PLATFORM_LINUX`, where `tls_quictls.c` ORs
    //   the flag in itself. Setting it changes nothing.
    // * Darwin is the one platform where it does something, and what it does is
    //   a regression: it replaces msquic's `CxPlatCertVerifyRawCertificate`
    //   (SecTrust, with the dialed name) with a bare `X509_verify_cert` against
    //   `SSL_CTX_set_default_verify_paths()` -- an empty store on iOS.
    //
    // What Android actually needed is below: a CA file, because it has no
    // system PEM for the default paths to find.
    let mut cred = msquic::CredentialConfig::new_client();
    // Android ships no system PEM file, so the default verify paths find
    // nothing; the app copies a bundle out of its assets and points
    // `SSL_CERT_FILE` at it. Setting `CaCertificateFile` drives
    // `SSL_CTX_load_verify_locations()` directly rather than depending on the
    // environment variable being honoured by this quictls build.
    //
    // An unset variable leaves the platform's own defaults alone, which is what
    // every other platform wants. An empty one is ignored rather than passed
    // on: `load_verify_locations` failing is fatal to the whole credential.
    if let Some(ca_file) = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| !p.is_empty())
    {
        cred = cred.set_ca_certificate_file(ca_file);
    }
    // The same dev-only opt-in the proxy and Identity connections honour
    // (`isekai_p2p_core::transport`), which this one ignored — so the one switch
    // an operator has did not cover the one connection that carries the video.
    // It is only an escape hatch; never set in production.
    let skip_verify = std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_some();
    if verify && skip_verify {
        tracing::warn!("ISEKAI_INSECURE_SKIP_VERIFY set: skipping peer TLS certificate validation");
    }
    if !verify || skip_verify {
        cred = cred.set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    }
    if (verify && !skip_verify) || pinning {
        // **Added to whatever validation is already happening, not instead of
        // it.** The flags are OR'd, so nothing msquic does is switched off;
        // this asks to be shown the certificate as well, in a form that parses
        // on every platform.
        //
        // Asked for whenever the name has to be checked (#134) **or** there is
        // a key to pin — including with the insecure switch on. That switch
        // means "do not validate the certificate"; it has never meant "ignore
        // what the peer signed for", and msquic raises the indication even with
        // `NO_CERTIFICATE_VALIDATION`, so the pin can go on holding. A
        // certificate that is never handed over cannot be checked at all.
        cred = cred
            .set_credential_flags(msquic::CredentialFlags::INDICATE_CERTIFICATE_RECEIVED)
            .set_credential_flags(msquic::CredentialFlags::USE_PORTABLE_CERTIFICATES);
    }
    config.load_credential(&cred)?;
    Ok((reg, config))
}

// ── What the peer said about its own key ─────────────────────────────────────
//
// Moved from `camera-core::video` (plan §4.4, phase 1c). Not video-specific:
// what it settles is whether the connection is to the Endpoint the proxy named,
// which every consumer of this layer wants and none of them should implement
// twice.

/// Why a connection has nothing to pin.
///
/// Only the first is ordinary. The other two are a connect response that does
/// not hold together, and saying so is the difference between a peer that has
/// not adopted this yet and a proxy behaving oddly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unpinnable {
    /// The peer has published no statement. The transitional default.
    NoStatement,
    /// A statement arrived, but the response does not name the peer it should
    /// have come from — so there is nothing to check it against.
    NoPeerEndpoint,
    /// A statement arrived, but the response names no host to dial.
    NoHost,
}

impl std::fmt::Display for Unpinnable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStatement => f.write_str(
                "the peer published no statement about its key; trusting the proxy about \
                 which certificate is right",
            ),
            Self::NoPeerEndpoint => f.write_str(
                "the peer signed for its key, but the proxy named no endpoint to check the \
                 statement against; not pinning",
            ),
            Self::NoHost => f.write_str(
                "the peer signed for its key, but the proxy named no host to dial; not pinning",
            ),
        }
    }
}

/// What the peer said about its own key, and who it had to be.
///
/// Carried together because checking one without the others proves nothing: a
/// signature is only meaningful once it is known to be *this peer's*, about
/// *this name*.
#[derive(Debug, Clone)]
pub struct AttestedPeer {
    /// The statement, from the `peer_connect` response.
    pub attestation: Attestation,
    /// Who the proxy says is on the other end. The statement has to be signed
    /// by this Endpoint or it is about somebody else.
    pub peer_endpoint: String,
    /// The name being dialed, which is inside the signed text.
    pub video_host: String,
}

impl AttestedPeer {
    /// What a `peer_connect` response says about the peer's key, if anything.
    ///
    /// `None` where there is nothing to pin — a peer that has published no
    /// statement, or a proxy with no certificates configured. That is the
    /// ordinary case while this is being adopted, and it leaves the connection
    /// exactly as it was: validated by name and no more.
    ///
    /// Called by the initiator, so the peer is the target. `peer_endpoint` is
    /// what the connect response names it; `target_endpoint` is the same thing
    /// under the name the listing uses, and is taken when the first is absent.
    ///
    /// **The three ways this comes back empty are not the same**, and this is
    /// the fail-open path of a security control, so it says which. A peer that
    /// published nothing is ordinary. A response carrying a statement but no
    /// name to check it against is the proxy answering strangely, and reporting
    /// that as "the camera published nothing" blames the wrong party.
    pub fn from_connection(connection: &PeerConnection) -> Result<Self, Unpinnable> {
        let Some(attestation) = connection.video_attestation.clone() else {
            return Err(Unpinnable::NoStatement);
        };
        let peer_endpoint = connection
            .peer_endpoint
            .clone()
            .or_else(|| connection.target_endpoint.clone())
            .ok_or(Unpinnable::NoPeerEndpoint)?;
        let video_host = connection.video_host.clone().ok_or(Unpinnable::NoHost)?;
        Ok(Self {
            attestation,
            peer_endpoint,
            video_host,
        })
    }

    /// Whether `der` is the certificate this peer signed for.
    ///
    /// The statement does not carry the key's digest — it does not need to.
    /// The verifier already has a candidate in front of it, so the digest of
    /// the presented certificate goes into the signed text and the signature
    /// either verifies or does not. **Verification and pinning are the same
    /// operation.**
    fn accepts(&self, der: &[u8]) -> Result<(), String> {
        let spki = isekai_p2p_core::certificate::spki_sha256_of_certificate(der)
            .ok_or_else(|| "the peer's certificate could not be read".to_owned())?;
        isekai_p2p_core::attestation::verify(
            &self.attestation,
            &self.peer_endpoint,
            &self.video_host,
            &spki,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| format!("{e}"))
    }
}

/// Refuse the handshake unless the certificate names `host` and, where the peer
/// published one, is the key `pin` vouches for.
///
/// Either check can be absent: `host` is `None` when validation is off, and
/// `pin` is `None` for a peer that has published nothing. At least one is
/// always present, or this is not installed at all.
///
/// The handler runs on msquic's thread during the handshake and its return
/// status is the verdict, so everything it needs is copied in beforehand and it
/// does no I/O.
///
/// A rejection is logged at `warn` and not swallowed: a certificate for the
/// wrong name, or one on a connection that expected an attested key, is either
/// a misconfiguration or the thing this exists to catch, and both want saying.
/// # The credential must carry `USE_PORTABLE_CERTIFICATES`
///
/// **Not a style note.** With it, msquic hands the callback a `QUIC_BUFFER` of
/// DER, which is what the body casts to. Without it, it hands over the
/// platform's own handle — an `X509*`, a `PCCERT_CONTEXT` — and the same cast
/// reads two words of a different object as a pointer and a length. That is
/// type confusion, not a check that fails.
///
/// [`client_config`] sets it whenever `pinning` is asked for, alongside
/// `INDICATE_CERTIFICATE_RECEIVED`, and a configuration built any other way has
/// to set both. This is a precondition rather than an assertion because the
/// flags live on the `Configuration` and this is handed a `Connection`.
///
/// [`dial`] settles this by deciding both from the same [`DialOptions`], a line
/// apart, so no caller holds the two halves. This is public for anything that
/// builds its own configuration, and then the precondition is its own.
pub fn install_certificate_check(
    conn: &Connection,
    // The host to hold the certificate against, or `None` when validation is
    // off and only the pin is left to check.
    host: Option<String>,
    pin: Option<AttestedPeer>,
    // **Read this before retrying.** A `Some` here is the one answer that is not
    // worth another attempt: the certificate was refused, and it will be refused
    // the same way every time. A caller that takes the slot because the
    // signature asks for it and never looks at it retries for its whole deadline
    // and then reports a timeout -- which is #141 with the reason in hand.
    refused: Arc<Mutex<Option<String>>>,
) {
    conn.set_peer_certificate_received_callback(move |certificate, _flags, _status, _chain| {
        // `USE_PORTABLE_CERTIFICATES` makes this a `QUIC_BUFFER` of DER. It is
        // msquic's memory and lives only for this call, so nothing is kept.
        let der = unsafe {
            (certificate as *const msquic::ffi::QUIC_BUFFER)
                .as_ref()
                .map(|buffer| msquic::BufferRef::from_ffi_ref(buffer).as_bytes())
        };
        let verdict = match der {
            // The name first: a certificate for somebody else is somebody
            // else's whatever it carries, and saying so names the right
            // problem.
            Some(der) => host
                .as_deref()
                .map_or(Ok(()), |host| {
                    isekai_p2p_core::hostname::certificate_matches(der, host)
                })
                .and_then(|()| match &pin {
                    Some(pin) => pin.accepts(der),
                    None => Ok(()),
                }),
            None => Err("the peer presented no certificate".to_owned()),
        };
        match verdict {
            Ok(()) if pin.is_none() => {
                tracing::debug!(
                    host = host.as_deref().unwrap_or_default(),
                    "the video certificate is for the host dialled",
                );
                Ok(())
            }
            Ok(()) => {
                // Said at `info`, and once per handshake. "We are going to
                // check" and "it held" are different facts, and only the second
                // one is the protection — an operator who sees the first and
                // then silence cannot tell which of them happened.
                tracing::info!(
                    peer = pin
                        .as_ref()
                        .map(|p| p.peer_endpoint.as_str())
                        .unwrap_or_default(),
                    "the peer presented the key it signed for; the connection is pinned to it",
                );
                Ok(())
            }
            Err(reason) => {
                tracing::warn!(
                    peer = pin
                        .as_ref()
                        .map(|p| p.peer_endpoint.as_str())
                        .unwrap_or_default(),
                    host = host.as_deref().unwrap_or_default(),
                    "refusing the video connection: {reason}",
                );
                // Left where the dial can find it. The handshake is about to
                // fail, and every other reason it fails is worth retrying — so
                // without this the one answer that means *stop* is retried for
                // fifteen minutes and then reported as something else entirely.
                *refused.lock().expect("pin verdict lock poisoned") = Some(reason);
                Err(msquic::Status::from(
                    msquic::ffi::QUIC_STATUS_BAD_CERTIFICATE,
                ))
            }
        }
    });
}

// ── Dialling, and what the dial hands back ───────────────────────────────────
//
// Moved from `camera-core::video::dial_video` (plan §4.4, phase 1c-ii). This is
// where §4.4's four ways to hang stop being written down and start being
// enforced: what the dial returns owns everything msquic needs kept alive, in
// the order it needs releasing, and the drain takes that by value.

/// How long to keep retrying the handshake before giving up.
///
/// This spans an entirely manual gap: the initiator opens its relay leg, and the
/// peer can only bind *its* leg once a human has carried the connection id
/// across — reading it off a phone, typing it into the camera server, starting
/// the camera, pressing bind. Two minutes looked generous and was not: every
/// field failure we chased for a day ended at exactly this deadline, with the
/// relay leg still healthy and the operator still typing.
///
/// So it is set to a span no operator will lose a race against. Waiting costs
/// nothing here — the connection retransmits an Initial every few seconds — and
/// the caller can stop it at any time by cancelling `shutdown`, which is what
/// the disconnect button does.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(900);
/// Delay between handshake attempts.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(500);
/// How often to report what the handshake is doing while it is still
/// unanswered.
const HANDSHAKE_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// A dialled peer connection, and the two handles it may not outlive.
///
/// **msquic shuts a connection down when the `Configuration` it was started
/// with is dropped.** The symptom is not a message about configurations: it is
/// `connection shutdown by local` arriving milliseconds after a handshake that
/// plainly succeeded, and then a `RegistrationClose` that blocks forever on the
/// handle left behind. A function that keeps both as locals never meets this,
/// which is why `camera-core` never did; anything that *returns* a connection
/// does, which is how the portal spike found out.
///
/// So this returns instead of a `Connection`, and **dropping it releases all
/// three in msquic's order**: fields drop in declaration order, so the
/// connection goes first, then the configuration, then this reference to the
/// registration. The connection releases its own reference to the configuration
/// as it closes, so by the time the configuration's own drop runs there is
/// nothing left holding it. ([`drain`](Self::drain) puts the configuration after
/// `wait_idle` instead; that rule is about ordering against a wait, and this
/// path does not wait.)
///
/// There is deliberately no `impl Drop`. Field order is what releases, and a
/// `Drop` impl would forbid [`drain`](Self::drain) from taking the three apart —
/// which it has to, because the one thing `Drop` cannot do is wait.
///
/// **So `Drop` releases; it does not wait.** If something else still holds a
/// *clone* of the connection — a spawned reader, a stream — the handle it holds
/// is still tracked, and dropping the last `Registration` reference then blocks
/// in `RegistrationClose` forever. Stop those first and call
/// [`drain`](Self::drain); a caller that keeps its own `Arc<Registration>`, as
/// the camera apps do, never reaches that drop here at all.
pub struct PeerSession {
    connection: Connection,
    // Ordered after `connection` deliberately: fields drop in declaration
    // order, and the configuration has to outlive what was started with it.
    _config: msquic::Configuration,
    registration: Arc<Registration>,
}

impl PeerSession {
    /// Pair a connection with the configuration it was started with and the
    /// registration both belong to.
    ///
    /// [`dial`] is the usual way to get one. This is for anything that has to
    /// build its own connection — and the ordering rule above applies to it
    /// just the same, which is why there is no way to hand back the connection
    /// on its own.
    pub fn new(
        connection: Connection,
        config: msquic::Configuration,
        registration: Arc<Registration>,
    ) -> Self {
        Self {
            connection,
            _config: config,
            registration,
        }
    }

    /// The connection. Cloning it is fine; outliving this value is not.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The registration this connection was opened on, for anything that has
    /// to share it — msquic looks bindings up per registration, so a direct
    /// path between two connections needs them on the same one.
    pub fn registration(&self) -> &Arc<Registration> {
        &self.registration
    }

    /// Release everything and wait for msquic to be finished with it.
    ///
    /// **Takes `self` by value because that is the mechanism, not a
    /// convenience.** `wait_idle` resolves once every tracked handle is gone,
    /// so a caller that waits while still holding the connection is waiting for
    /// something that cannot happen — one of the four ways to hang in §4.4, and
    /// the one that reads as a test binary that simply never exits.
    ///
    /// Ownership of *this* handle is not ownership of every clone taken off it.
    /// Anything holding one has to be stopped first.
    ///
    /// The order below is msquic's: the connection releases its own reference
    /// to the configuration when it closes, and the configuration is dropped
    /// after `wait_idle` rather than before —
    /// `submodules/msquic-async-rs/docs/registration-wait-idle-design.md` §7,
    /// which is also why [`drain_registration`] does not touch it.
    ///
    /// `false` if the timeout ran out with handles still live.
    ///
    /// **And then the registration is deliberately leaked.** `false` says a
    /// tracked handle is still open, and that is exactly the state in which
    /// dropping the last `Arc<Registration>` blocks in `RegistrationClose` —
    /// uninterruptibly, with no message. Returning `false` and then hanging on
    /// the way out would make this function the fifth way to hang rather than
    /// the answer to four of them, and it would hang *hardest* in the case the
    /// return value exists to report. So the handle is forgotten instead: one
    /// leaked registration that the caller can log, assert on, or `_exit`
    /// past, rather than a process that stops here and says nothing.
    pub async fn drain(self, timeout: Duration) -> bool {
        let Self {
            connection,
            _config: config,
            registration,
        } = self;
        drop(connection);
        let drained = drain_registration(&registration, timeout).await;
        if drained {
            // Only now: msquic-async's contract puts the configuration after
            // `wait_idle` rather than before
            // (`submodules/msquic-async-rs/docs/registration-wait-idle-design.md`
            // §7), and the registration is safe to close with nothing left in
            // it.
            drop(config);
        } else {
            std::mem::forget(config);
            std::mem::forget(registration);
        }
        drained
    }
}

/// What [`dial`] needs to reach a peer.
pub struct DialOptions<'a> {
    /// The protocol this connection speaks — see [`ClientOptions::alpn`].
    pub alpn: &'a str,
    /// The name to dial, which is also the name the certificate has to be for.
    ///
    /// A *name*, never an address to resolve; [`dial`] says why at length.
    pub host: &'a str,
    /// The loopback port the relay bridge is listening on.
    pub port: u16,
    /// Validate the peer's certificate chain, and hold it against `host`.
    ///
    /// Unlike [`ClientOptions::verify`], this covers both: [`dial`] installs
    /// the name check itself, so there is no second thing to remember.
    pub verify: bool,
    /// What the peer signed for about its own key, where it published
    /// anything. `None` leaves the connection on name validation alone, which
    /// is the ordinary case while this is being adopted.
    pub pin: Option<AttestedPeer>,
    /// How the proxy sees this session's relay leg. `Some` offers it as a
    /// direct-path candidate and turns migration on.
    pub candidate: Option<ObservedAddress>,
    /// Receive QUIC datagrams — see [`ClientOptions::datagrams`].
    pub datagrams: bool,
}

/// Dial a peer, letting a single handshake ride across its relay-bind gap;
/// retry only as a fallback, until the deadline or `shutdown`.
///
/// Over the P2P relay the initiator opens its own leg first and only then does
/// the peer bind *its* leg — it needs the connection id out of band (e.g. a
/// human pasting it into the camera server). Until both legs are bridged, the
/// handshake's packets reach a half-open relay edge and go unanswered. A
/// completed handshake is itself the readiness signal (both legs are up), and
/// there is nothing on the control plane to poll — the loopback relay
/// rendezvous injects no reachable candidate.
///
/// The key is to keep **one** connection retransmitting its Initial for the
/// whole gap (a long `HandshakeIdleTimeoutMs`) rather than firing many
/// short-lived attempts. Local relay testing showed rapid short attempts
/// (a few seconds each) leave the relay path wedged so it never recovers even
/// after the bind lands, whereas a single persistent handshake completes as
/// soon as the far leg comes up. The retry loop below is therefore a
/// last-resort fallback for a genuinely failed handshake, not the mechanism
/// that bridges the gap.
///
/// `host` is a *name*, never an address to look up. Every caller dials the relay
/// bridge on loopback, and the name is the per-endpoint FQDN the listener's relay
/// certificate is issued for — it exists so the certificate can be validated, and
/// its only DNS record points back at `127.0.0.1`. Pinning the remote address
/// below says that outright, and keeps msquic from resolving the name: msquic
/// resolves with a blocking `getaddrinfo` on the connection's worker thread, and
/// that worker also drives the relay leg, so a slow resolver takes the leg down
/// with it. A loopback-only name is exactly what mobile resolvers are slowest
/// about — DNS64 will not synthesise an AAAA for `127.0.0.0/8`, and resolvers
/// with rebinding protection refuse to return it at all — which is why this
/// showed up on iOS long before it would have anywhere else.
///
/// # The configuration is built here on purpose
///
/// [`install_certificate_check`] is only sound on a credential carrying
/// `USE_PORTABLE_CERTIFICATES`, and until 1c-ii the two halves sat in
/// different crates: whoever built the configuration had to remember what
/// whoever installed the callback needed. Building the configuration inside
/// the dial retires the question — the flags and the callback are decided
/// from the same [`DialOptions`], a line apart.
///
/// # What comes back
///
/// A [`PeerSession`]: the connection, the configuration it may not outlive,
/// and the registration both belong to. Returning a bare `Connection` is what
/// phase 0 did, and it hung.
pub async fn dial(
    reg: Option<Arc<Registration>>,
    opts: DialOptions<'_>,
    shutdown: &CancellationToken,
) -> anyhow::Result<PeerSession> {
    let DialOptions {
        alpn,
        host,
        port,
        verify,
        pin,
        candidate,
        datagrams,
    } = opts;
    // Both flags are read off the same options the loop below reads, rather
    // than passed in beside them: a caller that asked to pin and got a
    // configuration built without `USE_PORTABLE_CERTIFICATES` would not fail a
    // check, it would read an `X509*` as a buffer.
    let (reg, config) = client_config(
        reg,
        ClientOptions {
            alpn,
            verify,
            enable_migration: candidate.is_some(),
            pinning: pin.is_some(),
            datagrams,
        },
    )?;
    let deadline = Instant::now() + CONNECT_DEADLINE;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let conn = Connection::new(&reg)?;
        // Every attempt builds a fresh connection, so the setup below has to be
        // redone on each one.
        conn.set_remote_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|e| anyhow::anyhow!("could not pin the relay bridge address: {e}"))?;
        if let Some(candidate) = candidate {
            prepare_for_migration(&conn, candidate)?;
        }
        // One slot per attempt: a verdict from a connection that has been
        // dropped says nothing about this one.
        let refused: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        // The name is checked when this connection validates; the pin is
        // checked whenever the peer published one, insecure switch included.
        let check_name = verify && std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_none();
        if check_name || pin.is_some() {
            install_certificate_check(
                &conn,
                check_name.then(|| host.to_owned()),
                pin.clone(),
                Arc::clone(&refused),
            );
        }
        // The handshake can stay unanswered for a long time by design, and until
        // it is answered there is nothing else to go on. Report what it is doing
        // while it waits: whether our packets are still leaving tells a peer
        // that has not bound its leg apart from a path that has stopped
        // carrying anything, and those want opposite fixes.
        let start = conn.start(&config, host, port);
        tokio::pin!(start);
        let mut probe = tokio::time::interval(HANDSHAKE_PROBE_INTERVAL);
        probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Carried out of the loop because the failure below has to describe a
        // connection it has already had to drop.
        let mut last: Option<(u64, u64)> = None;
        let result = loop {
            tokio::select! {
                _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing the peer"),
                r = &mut start => break r,
                _ = probe.tick() => match conn.get_stats() {
                    Ok(stats) => {
                        last = Some((stats.Send.TotalPackets, stats.Recv.TotalPackets));
                        log_connection_stats(&conn, &stats, "handshake");
                    }
                    Err(e) => tracing::debug!("could not read handshake stats: {e}"),
                },
            }
        };
        // Checked before the retry decision, because it is the one failure that
        // retrying cannot help: the peer signed for a key, and this certificate
        // is not it. Trying again produces the same answer, ~1,700 times, and
        // the error finally reported would be the relay-leg timeout — which is
        // what "the operator has not pasted the connection id yet" looks like.
        // The two want opposite responses.
        if let Some(reason) = refused.lock().expect("pin verdict lock poisoned").take() {
            // Deliberately not naming the attestation: the same slot carries a
            // name mismatch, and pointing an operator at a statement the peer
            // never published sends them to the wrong problem.
            anyhow::bail!("the peer's certificate was refused, so this is not the peer it claims to be: {reason}");
        }
        match result {
            Ok(()) => return Ok(PeerSession::new(conn, config, reg)),
            Err(e) => {
                let observed = conn
                    .get_stats()
                    .ok()
                    .map(|s| (s.Send.TotalPackets, s.Recv.TotalPackets))
                    .or(last);
                drop(conn);
                // The other answer retrying cannot help, and the one #141 was
                // filed for. The slot above only carries verdicts *our*
                // callback reached; a chain msquic itself rejects never runs
                // it, so an untrusted or expired certificate looked exactly
                // like a peer that has not bound its leg and was asked again
                // 1,766 times before the deadline reported a timeout.
                if let Some(code) = permanent_verdict(&e) {
                    return Err(anyhow::Error::new(e).context(format!(
                        "the transport refused the handshake to {host}:{port} with \
                         {code}, which is its answer on every attempt"
                    )));
                }
                if Instant::now() >= deadline {
                    // Say what was seen, not what it might mean. The old wording
                    // asserted the peer had not bound its leg, and a day went
                    // into chasing that assertion while it was wrong; the packet
                    // counts distinguish the cases without guessing. Nothing
                    // received at all is the peer never answering — a leg not
                    // bridged yet, or an operator who has not finished carrying
                    // the connection id across.
                    let seen = match observed {
                        Some((sent, received)) => {
                            format!("{sent} packets sent, {received} received")
                        }
                        None => "no packet counts available".to_owned(),
                    };
                    return Err(anyhow::Error::new(e).context(format!(
                        "QUIC handshake to {host}:{port} did not complete within \
                         {CONNECT_DEADLINE:?} ({attempt} attempts, {seen})"
                    )));
                }
                // Debug, not Display: the transport status is what names the
                // cause — an untrusted certificate and an unanswered handshake
                // both read as "connection lost" otherwise.
                tracing::debug!("handshake attempt {attempt} failed: {e:?}");
                tokio::select! {
                    _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing the peer"),
                    _ = sleep(CONNECT_RETRY_DELAY) => {}
                }
            }
        }
    }
}

/// The TLS alert a handshake was refused with, when that refusal will read the
/// same on every attempt.
///
/// **This is #141.** The `refused` slot [`install_certificate_check`] writes
/// into only ever carries verdicts *our* callback reached. A chain msquic
/// itself rejects never runs it — an untrusted root, an expired certificate, a
/// name schannel or SecTrust throws out — so nothing was recorded, and the dial
/// treated the one permanent answer there is exactly like the most ordinary
/// transient one: a peer that has not bridged its relay leg. A CI run spent
/// fifteen minutes and 1,767 attempts on a status that was in the first one.
///
/// # Alerts, not the statuses msquic gives names to
///
/// A handshake the local TLS stack rejects closes with
/// `QuicErrorCodeToStatus(QUIC_ERROR_CRYPTO_ERROR(alert))`, which is
/// `QUIC_STATUS_TLS_ALERT(alert)` — so **the only certificate verdicts that can
/// reach here are alerts**, and reading the alert back out is what makes the
/// list complete.
///
/// Matching msquic's named statuses instead looks equivalent and is not, in the
/// one direction that matters. On the quictls platforms — Linux and Android,
/// where msquic ORs `USE_TLS_BUILTIN_CERTIFICATE_VALIDATION` in itself — a
/// chain that does not verify goes through `ssl_x509err2alert`, and
/// `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, `DEPTH_ZERO_SELF_SIGNED_CERT` and
/// `SELF_SIGNED_CERT_IN_CHAIN` all come out as `unknown_ca` (48). **msquic has
/// no named status for that alert**, so a `StatusCode` list silently misses the
/// most ordinary refusal there is on two of our four platforms — and looks
/// comprehensive while doing it. Darwin and Windows report the same certificate
/// as `bad_certificate` (42), which is why #141's log shows a status with a
/// name: it was captured on macOS.
///
/// `QUIC_STATUS_CERT_EXPIRED`, `QUIC_STATUS_CERT_UNTRUSTED_ROOT` and
/// `QUIC_STATUS_CERT_NO_CERT` are not in this list because they cannot appear
/// here at all: they are a different range (`CERT_ERROR_BASE`, and Windows
/// crypto `HRESULT`s) that msquic produces only as the deferred-validation
/// `ValidationResult`, never as a close status. An earlier version of this
/// function matched them, which is what made it read as though untrusted roots
/// were covered.
///
/// # What is deliberately left retryable
///
/// #141 also asks whether anything else the transport reports is being retried
/// when it cannot succeed. The candidates are ALPN and version negotiation,
/// which are answers rather than silence, and `decrypt_error` (51), which is
/// raised for handshake signatures as well as certificate ones. They are left
/// retryable because the asymmetry is not close: a status wrongly called
/// permanent is a viewer that fails where it used to work, while one wrongly
/// called transient is the behaviour we have today. What a half-open relay edge
/// answers with before both legs are bridged is not characterised well enough
/// to say otherwise — and the tests below pin the transient side too, so
/// narrowing this later is a test change rather than a guess.
fn permanent_verdict(e: &ConnectionStartError) -> Option<CertificateAlert> {
    let status = match e {
        ConnectionStartError::ConnectionLost(ConnectionError::ShutdownByTransport(status, _)) => {
            status
        }
        ConnectionStartError::OtherError(status) => status,
        // `ShutdownByLocal` is our own cancellation, `ShutdownByPeer` is an
        // application error code from a peer that completed a handshake, and
        // the rest are states rather than verdicts. None of them says the next
        // attempt reads the same.
        _ => return None,
    };
    let alert = tls_alert(status)?;
    matches!(
        alert,
        // What the TLS stack made of the certificate: bad, unsupported,
        // revoked, expired, unknown.
        42..=46
            // No path to a trusted root. The one with no name in msquic, and
            // the ordinary one on Linux and Android.
            | 48
            // A peer that presented nothing where one was required. Not
            // something that changes inside this deadline either.
            | 116
    )
    .then_some(CertificateAlert(alert))
}

/// The alert a handshake was closed with, if it was closed with one.
///
/// `QUIC_STATUS_CLOSE_NOTIFY` is `QUIC_STATUS_TLS_ALERT(0)` on every platform,
/// so the alert is the distance from it — which is how this stays right without
/// knowing whether the platform's `QUIC_STATUS` is an errno-shaped `u32` or an
/// `HRESULT`. Anything outside 0..=255 of it is not an alert at all.
fn tls_alert(status: &msquic::Status) -> Option<u8> {
    u8::try_from(status.0.wrapping_sub(msquic::ffi::QUIC_STATUS_CLOSE_NOTIFY)).ok()
}

/// A TLS alert that refuses the peer's certificate, for the operator who has to
/// read it.
///
/// Named rather than numbered because the one that matters most has no name in
/// msquic to borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CertificateAlert(u8);

impl std::fmt::Display for CertificateAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.0 {
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            48 => "unknown_ca",
            116 => "certificate_required",
            _ => "certificate refused",
        };
        write!(f, "{name} (TLS alert {})", self.0)
    }
}

/// Put the connection on a shared, unconnected socket and offer the relay
/// leg's address as a direct-path candidate. Must run before `start`.
///
/// The order is fixed: `set_unconnected_socket` requires a shared binding, and
/// an unconnected socket requires a specific — non-wildcard — local address.
/// That address is deliberately **loopback**: this connection's own traffic
/// goes to the relay bridge on `127.0.0.1`, and pinning it to a real interface
/// address instead cannot work on Windows at all. The direct path does not need
/// it, because `add_candidate_addr` accepts an address that is not bound here
/// yet — msquic opens the path from the relay leg's binding once the peer's
/// ADD_ADDRESS arrives (`docs/p2p_mode_migration_plan.md` §2.2.3).
fn prepare_for_migration(conn: &Connection, candidate: ObservedAddress) -> anyhow::Result<()> {
    // All three are required for a direct path to be validated at all — without
    // them msquic never raises `PathValidated`, whatever candidate is offered.
    conn.set_share_binding(true)
        .map_err(|e| anyhow::anyhow!("could not share the UDP binding: {e}"))?;
    conn.set_unconnected_socket(true)
        .map_err(|e| anyhow::anyhow!("could not use an unconnected socket: {e}"))?;
    conn.set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| anyhow::anyhow!("could not pin the local address: {e}"))?;
    conn.add_candidate_addr(candidate.local, candidate.observed)
        .map_err(|e| anyhow::anyhow!("could not offer a direct-path candidate: {e}"))?;
    // Also offer the host address itself. A peer on the same LAN can reach it
    // directly, while the observed one is only reachable from outside the NAT —
    // and a NAT that does not hairpin (most of them) drops a packet sent from
    // inside to its own public address, so without this two peers behind the
    // same NAT can never find each other. Across the internet this candidate
    // simply fails to validate and the observed one wins.
    if candidate.local != candidate.observed {
        if let Err(e) = conn.add_candidate_addr(candidate.local, candidate.local) {
            tracing::debug!("could not offer the host candidate: {e}");
        }
    }
    tracing::info!(
        local = %candidate.local,
        observed = %candidate.observed,
        "offered direct-path candidates to the peer",
    );
    Ok(())
}

/// Log what the connection is actually doing, which is the difference between
/// "the migration stalled" and "the migration broke the connection".
///
/// `Send.PathMtu` is worth watching when a path has just been opened, since it
/// has to size itself.
///
/// For loss, `send_lost` alone says very little: it counts packets the loss
/// detector *declared* lost, and `send_spurious_lost` is how many of those
/// turned out to have arrived after all. A high first number with a high second
/// is an over-eager loss detector, not a lossy path, and the two want opposite
/// fixes. `send_congestion` and the byte counters give the other half — whether
/// the congestion controller is actually backing off, and what throughput that
/// leaves.
pub fn log_connection_stats(conn: &Connection, stats: &msquic::ffi::QUIC_STATISTICS, when: &str) {
    tracing::debug!(
        when,
        local = ?conn.get_local_addr().ok(),
        remote = ?conn.get_remote_addr().ok(),
        rtt_us = stats.Rtt,
        send_path_mtu = stats.Send.PathMtu,
        send_packets = stats.Send.TotalPackets,
        send_lost = stats.Send.SuspectedLostPackets,
        send_spurious_lost = stats.Send.SpuriousLostPackets,
        send_congestion = stats.Send.CongestionCount,
        send_persistent_congestion = stats.Send.PersistentCongestionCount,
        send_bytes = stats.Send.TotalBytes,
        recv_packets = stats.Recv.TotalPackets,
        recv_dropped = stats.Recv.DroppedPackets,
        recv_bytes = stats.Recv.TotalBytes,
        "peer connection stats",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use msquic::ffi::QUIC_STATUS;
    use msquic::StatusCode;

    /// A close status carrying `alert`, built the way msquic builds one.
    fn alert(alert: u8) -> ConnectionStartError {
        lost(msquic::Status::from(
            msquic::ffi::QUIC_STATUS_CLOSE_NOTIFY.wrapping_add(alert as QUIC_STATUS),
        ))
    }

    fn lost(status: msquic::Status) -> ConnectionStartError {
        ConnectionStartError::ConnectionLost(ConnectionError::ShutdownByTransport(status, 0))
    }

    /// The arithmetic that reads an alert back out of a close status, pinned
    /// against the statuses msquic names itself.
    ///
    /// **This is the part that is not the same on every platform.**
    /// `QUIC_STATUS` is an errno-shaped `u32` on Linux and Android and a signed
    /// `HRESULT` on Windows, so "the distance from `CLOSE_NOTIFY`" has to hold
    /// for both — and nothing else here would notice if it did not.
    #[test]
    fn the_alert_is_read_back_out_of_the_status() {
        for (status, expected) in [
            (msquic::ffi::QUIC_STATUS_CLOSE_NOTIFY, 0),
            (msquic::ffi::QUIC_STATUS_BAD_CERTIFICATE, 42),
            (msquic::ffi::QUIC_STATUS_UNSUPPORTED_CERTIFICATE, 43),
            (msquic::ffi::QUIC_STATUS_REVOKED_CERTIFICATE, 44),
            (msquic::ffi::QUIC_STATUS_EXPIRED_CERTIFICATE, 45),
            (msquic::ffi::QUIC_STATUS_UNKNOWN_CERTIFICATE, 46),
            (msquic::ffi::QUIC_STATUS_REQUIRED_CERTIFICATE, 116),
        ] {
            assert_eq!(
                tls_alert(&msquic::Status::from(status)),
                Some(expected),
                "{status} should read as alert {expected}",
            );
        }

        // And a status from another range is not mistaken for one. The three
        // `QUIC_STATUS_CERT_*` values are exactly that — msquic produces them
        // as a deferred-validation result, never as a close status — and an
        // earlier version of this file listed them as terminal, which is what
        // made it look as though untrusted roots were covered.
        for status in [
            msquic::ffi::QUIC_STATUS_CERT_EXPIRED,
            msquic::ffi::QUIC_STATUS_CERT_UNTRUSTED_ROOT,
            msquic::ffi::QUIC_STATUS_CERT_NO_CERT,
            msquic::ffi::QUIC_STATUS_CONNECTION_TIMEOUT,
        ] {
            assert_eq!(
                tls_alert(&msquic::Status::from(status)),
                None,
                "{status} is not a TLS alert",
            );
        }
    }

    /// Every alert that refuses the peer's certificate ends the dial. Our own
    /// callback never sees these — msquic rejects the chain before it runs — so
    /// without this they are retried for the full fifteen minutes and then
    /// reported as a handshake that went unanswered (#141).
    #[test]
    fn a_certificate_the_transport_rejects_is_not_retried() {
        for a in [42, 43, 44, 45, 46, 48, 116] {
            assert_eq!(
                permanent_verdict(&alert(a)),
                Some(CertificateAlert(a)),
                "alert {a} is the same answer on every attempt",
            );
        }
    }

    /// **`unknown_ca` deserves its own test**, because it is the one with no
    /// `QUIC_STATUS` name to match on and the one Linux and Android actually
    /// send: quictls maps `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`,
    /// `DEPTH_ZERO_SELF_SIGNED_CERT` and `SELF_SIGNED_CERT_IN_CHAIN` to it, so
    /// it is what an untrusted root looks like on two of our four platforms.
    /// The first version of this classification matched msquic's named statuses
    /// and missed it, while listing three `QUIC_STATUS_CERT_*` values that can
    /// never be a close status.
    #[test]
    fn an_untrusted_root_is_refused_by_the_name_it_actually_arrives_under() {
        let verdict = permanent_verdict(&alert(48)).expect("unknown_ca is terminal");
        assert_eq!(
            verdict.to_string(),
            "unknown_ca (TLS alert 48)",
            "and it is reported by a name, since msquic has none to borrow",
        );
    }

    /// And the failure the fifteen minutes exist for stays retryable. The peer
    /// binds its relay leg only once an operator has carried the connection id
    /// across, so until then nothing answers — calling any of this permanent
    /// would fail every P2P connection that waits on a human.
    #[test]
    fn an_unanswered_handshake_is_still_retried() {
        for e in [
            lost(msquic::Status::new(
                StatusCode::QUIC_STATUS_CONNECTION_TIMEOUT,
            )),
            lost(msquic::Status::new(StatusCode::QUIC_STATUS_CONNECTION_IDLE)),
            lost(msquic::Status::new(
                StatusCode::QUIC_STATUS_CONNECTION_REFUSED,
            )),
            lost(msquic::Status::new(StatusCode::QUIC_STATUS_UNREACHABLE)),
            // Considered and deliberately left retryable: what the half-open
            // relay edge answers with before both legs are bridged is not
            // characterised well enough to call an answer.
            lost(msquic::Status::new(
                StatusCode::QUIC_STATUS_ALPN_NEG_FAILURE,
            )),
            lost(msquic::Status::new(StatusCode::QUIC_STATUS_VER_NEG_ERROR)),
            // Alerts that are not about the peer's certificate. `decrypt_error`
            // is raised for handshake signatures too, and `close_notify` is an
            // orderly shutdown.
            alert(0),
            alert(40),
            alert(51),
            alert(80),
            // Our own cancellation, and a peer that got far enough to send an
            // application error code. Neither is a verdict on a certificate.
            ConnectionStartError::ConnectionLost(ConnectionError::ShutdownByLocal),
            ConnectionStartError::ConnectionLost(ConnectionError::ShutdownByPeer(0)),
        ] {
            assert_eq!(permanent_verdict(&e), None, "{e:?}");
        }
    }

    /// The three ways there is nothing to pin are told apart, because only one
    /// of them is ordinary and the other two are the proxy answering strangely.
    /// Reporting all of them as "the peer published nothing" blames the camera
    /// for the proxy's behaviour.
    #[test]
    fn not_pinning_says_which_of_the_three_it_is() {
        let plain: PeerConnection = serde_json::from_str(
            r#"{"connection_id":"c","state":"relay","listener_id":"pl_1",
                "peer_endpoint":"ep:b","protocol":"mjpeg","relay_session_id":"s",
                "candidates":[],"peer_candidates":[]}"#,
        )
        .expect("a connect response");
        assert_eq!(
            AttestedPeer::from_connection(&plain).unwrap_err(),
            Unpinnable::NoStatement,
            "no statement is the ordinary case",
        );

        let attested: PeerConnection = serde_json::from_str(
            r#"{"connection_id":"c","state":"relay","listener_id":"pl_1",
                "peer_endpoint":"ep:b","protocol":"mjpeg","relay_session_id":"s",
                "candidates":[],"peer_candidates":[],
                "video_attestation":{"jwk":{},"expires_at":"2099-01-01T00:00:00Z",
                                     "signature":"x"}}"#,
        )
        .expect("a connect response with a statement");
        assert_eq!(
            AttestedPeer::from_connection(&attested).unwrap_err(),
            Unpinnable::NoHost,
            "a statement with nowhere to dial is not the camera's doing",
        );
    }
}
