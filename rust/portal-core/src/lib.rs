//! ISEKAI portal — forwarding a TCP service over the P2P session.
//!
//! **Phase 0 of `docs/portal_plan.md`.** TCP only, a catalogue built in code,
//! no configuration file, no UI, no UDP. What it exists to answer is whether
//! the framing and the stream mapping hold up; everything the plan lists after
//! this is deliberately absent.
//!
//! [`session`] opens the P2P session both ways as of phase 1c-iii-c-ii, so
//! `portal-server` and `portal-client` reach each other over a proxy. What is
//! still phase 0 about this crate is what it forwards: TCP only, and a
//! catalogue built in code.
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
pub mod session;
pub mod transport;

/// The ALPN this speaks. Distinct from the video's `sample`: a connection is
/// one or the other, and a peer that offers neither should fail at the
/// handshake rather than at the first frame.
pub const PORTAL_ALPN: &str = "isekai-portal-v1";
