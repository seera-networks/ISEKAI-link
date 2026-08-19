//! The parts of holding a peer QUIC connection that are not about what it
//! carries.
//!
//! **Slice 1 of `docs/portal_plan.md` §4.4.** `camera-core::video` is ~1,700
//! lines of which the MJPEG is the small part; the rest — dialling across the
//! peer's bind gap, the certificate callback, keepalives, the registration
//! lifecycle — is peer-QUIC plumbing that a second consumer would otherwise
//! fork. What is here is the subset with no camera types in it and no
//! load-bearing prose to move:
//!
//! * [`Dialed`], the rule that a `Configuration` outlives its `Connection`
//! * [`drain_registration`], the rule that a registration is emptied before it
//!   is dropped
//!
//! Both are *rules* rather than helpers, which is why they came first: each one
//! is a way to hang a process that every consumer would otherwise have to
//! rediscover, and phase 0 rediscovered both.
//!
//! What is deliberately still in `camera-core`, and why:
//!
//! | | |
//! | --- | --- |
//! | `video_client_config` | 150 lines whose comments carry the reasoning for the MTU cap, the two keepalives and the handshake idle timeout. Worth moving exactly, not approximately |
//! | `dial_video`, `install_certificate_check` | tied to `AttestedPeer`, which has to move with them |
//!
//! Neither is video-specific in substance. Both are the next slices.

use std::sync::Arc;
use std::time::Duration;

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

use msquic_async::{msquic, Connection, Registration};

/// A connection and the configuration it may not outlive.
///
/// **msquic shuts a connection down when the `Configuration` it was started
/// with is dropped.** The symptom is not a message about configurations: it is
/// `connection shutdown by local` arriving milliseconds after a handshake that
/// plainly succeeded, and then a `RegistrationClose` that blocks forever on the
/// handle left behind.
///
/// A function that keeps both as locals never meets this, which is why
/// `camera-core` never did. Anything that *returns* a connection has to return
/// this instead — the type is here so the next one does not find out the way
/// the portal spike did.
pub struct Dialed {
    connection: Connection,
    // Ordered after `connection` deliberately: fields drop in declaration
    // order, and the configuration has to outlive what was started with it.
    _config: msquic::Configuration,
}

impl Dialed {
    /// Pair a connection with the configuration it was started with.
    pub fn new(connection: Connection, config: msquic::Configuration) -> Self {
        Self {
            connection,
            _config: config,
        }
    }

    /// The connection. Cloning it is fine; outliving this value is not.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

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
/// §7). Dropping it first is what [`Dialed`] exists to prevent — which is why
/// this sentence is worth being exact about, thirty lines below that type.
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
    /// Validate the peer's certificate. Off is dev-only.
    pub verify: bool,
    /// Offer a direct path and let the connection use it.
    pub enable_migration: bool,
    /// Ask to be shown the peer's certificate, so a caller can check it.
    pub pinning: bool,
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
        tracing::warn!(
            "ISEKAI_INSECURE_SKIP_VERIFY set: skipping video TLS certificate validation"
        );
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
