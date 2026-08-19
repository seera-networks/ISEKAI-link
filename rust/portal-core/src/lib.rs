//! ISEKAI portal — forwarding a TCP service over the P2P session.
//!
//! **Phase 0 of `docs/portal_plan.md`.** TCP only, a catalogue built in code,
//! no configuration file, no UI, no UDP. What it exists to answer is whether
//! the framing and the stream mapping hold up; everything the plan lists after
//! this is deliberately absent.
//!
//! Two things it does not do yet, and both are on purpose:
//!
//! * **It does not open the P2P session.** The pieces for that —
//!   `isekai_p2p::InitiatorSession` and `ListenerSession`, the relay leg, the
//!   pin, the paired-Endpoint check — are built and running in the camera apps.
//!   Wiring them in is phase 1's job, after the connection layer is extracted
//!   out of `camera-core` (plan §4.4) rather than copied into a second place.
//! * **It has no transport of its own.** [`spike`] stands up a plain loopback
//!   QUIC connection so the framing can be exercised end to end today. It is
//!   the first thing phase 1 deletes.
//!
//! ```text
//!   client                                   server
//!   TCP accept ─▶ QUIC bidi stream ─▶ open ─▶ catalogue lookup
//!                                    ◀ status ─
//!                 ◀────── raw bytes, both ways ──────▶ TCP to the target
//! ```

pub mod client;
pub mod frame;
pub mod server;
/// Behind a feature so the insecure dialer is not part of what this crate
/// offers by default: it validates nothing and generates its own certificate,
/// which is fine for a loopback test and nowhere else.
#[cfg(feature = "spike")]
pub mod spike;

/// The ALPN this speaks. Distinct from the video's `sample`: a connection is
/// one or the other, and a peer that offers neither should fail at the
/// handshake rather than at the first frame.
pub const PORTAL_ALPN: &str = "isekai-portal-v1";
