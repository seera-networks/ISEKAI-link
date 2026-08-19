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

use std::time::Duration;

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
/// Takes the registration by reference because the caller usually holds an
/// `Arc`; what matters is that every *other* handle — connections, streams,
/// listeners, configurations — is gone before this is called.
pub async fn drain_registration(reg: &Registration, timeout: Duration) -> bool {
    reg.shutdown();
    let drained = tokio::time::timeout(timeout, reg.wait_idle()).await.is_ok();
    if !drained {
        tracing::warn!(?timeout, "msquic registration still has live handles");
    }
    drained
}
