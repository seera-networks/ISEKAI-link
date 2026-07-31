//! ISEKAI P2P Connect — client-side **protocol primitives**.
//!
//! The low-level building blocks for the MASQUE proxy's P2P Connect feature.
//! They manage an Endpoint keypair, prove possession of it on every request
//! (PoP), obtain an Endpoint Token from the Identity API, drive the proxy's P2P
//! control plane (Peer Listeners / Capabilities / Peer Connect / connection
//! state), and open the MASQUE relay legs tagged with the connection id so the
//! proxy can relay via the edge address.
//!
//! The high-level session API that ties these into end-to-end flows, and the
//! CLI, live in the `isekai-p2p` crate, which builds on this one.
//!
//! Foundation, transport-independent:
//!
//! * [`endpoint`] — the Endpoint keypair, its JWK (`cnf`) and its Endpoint ID
//!   (derived identically to the proxy, spec §4.2);
//! * [`pop`] — Proof-of-Possession header generation (spec §8.0).
//!
//! The Identity API client, the proxy H3 control-plane client (via
//! `channel-masque`), and the MASQUE relay legs build on top of these.

pub mod endpoint;
/// HTTPS (HTTP/1.1 + HTTP/2) transport for the Identity API.
pub mod https;
pub mod identity;
pub mod pop;
pub mod proxy;

/// msquic HTTP/3 transport for the proxy control plane (feature `msquic`).
#[cfg(feature = "msquic")]
pub mod transport;

/// MASQUE bind session for P2P relay (feature `msquic`).
#[cfg(feature = "msquic")]
pub mod bind;

/// Observed-address reports from a relay leg (feature `msquic`).
#[cfg(feature = "msquic")]
pub mod observed;
