//! ISEKAI portal — forwarding a TCP or UDP service over the P2P session.
//!
//! No UI. The catalogue is a file as of phase 2 ([`config`]), and UDP is served
//! as of phase 3b ([`udp`]).
//!
//! [`session`] opens the P2P session both ways as of phase 1c-iii-c-ii, so
//! `portal-server` and `portal-client` reach each other over a proxy — on a
//! Grant from pairing since phase 6 ([`session::Reach`]), which is what lets a
//! client reconnect, and outlive the server restarting, without the operator.
//!
//! ```text
//!   client                                   server
//!   TCP accept ─▶ QUIC bidi stream ─▶ open ─▶ catalogue lookup
//!                                    ◀ status ─
//!                 ◀────── raw bytes, both ways ──────▶ TCP to the target
//!
//!   UDP datagram ▶ QUIC bidi stream ─▶ open ─▶ catalogue lookup
//!    from :51314                      ◀ status ─   one socket per session
//!                 ◀── [ session ][ payload ] ──────▶ UDP to the target
//! ```
//!
//! **The two are not the same shape and the difference is the point.** A TCP
//! forward is a stream that *is* the connection; a UDP forward is a stream that
//! only says a session exists, while the payloads ride as datagrams beside it —
//! because UDP's semantics are datagram semantics, and carrying them on a
//! stream would add reliability and ordering the application did not ask for
//! and head-of-line blocking it does not expect.

pub mod client;
pub mod config;
pub mod datagram;
pub mod frame;
pub mod login;
pub mod path;
pub mod server;
pub mod session;
pub mod transport;
pub mod udp;

/// The ALPN this speaks. Distinct from the video's `sample`: a connection is
/// one or the other, and a peer that offers neither should fail at the
/// handshake rather than at the first frame.
pub const PORTAL_ALPN: &str = "isekai-portal-v1";
