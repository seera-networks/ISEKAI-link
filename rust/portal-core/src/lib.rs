//! ISEKAI portal — forwarding a TCP service over the P2P session.
//!
//! **Phase 0 of `docs/portal_plan.md`.** TCP only, a catalogue built in code,
//! no configuration file, no UI, no UDP. What it exists to answer is whether
//! the framing and the stream mapping hold up; everything the plan lists after
//! this is deliberately absent.
//!
//! One thing it does not do yet, and it is on purpose:
//!
//! * **It does not open the P2P session.** [`transport`] dials a peer with the
//!   real connection layer as of phase 1c-iii-b, but what puts a proxy in front
//!   of it — `isekai_p2p::InitiatorSession` and `ListenerSession`, the relay
//!   leg, the pin, the paired-Endpoint check — is 1c-iii-c. Until then the only
//!   caller is the loopback test.
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
pub mod transport;

/// The ALPN this speaks. Distinct from the video's `sample`: a connection is
/// one or the other, and a peer that offers neither should fail at the
/// handshake rather than at the first frame.
pub const PORTAL_ALPN: &str = "isekai-portal-v1";
