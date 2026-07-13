//! ISEKAI Agent — the **P2P Connect client** side.
//!
//! This crate is the client counterpart to the MASQUE proxy's P2P Connect
//! feature. It manages an Endpoint keypair, proves possession of it on every
//! request (PoP), obtains an Endpoint Token from the Identity API, drives the
//! proxy's P2P control plane (Peer Listeners / Capabilities / Peer Connect /
//! connection state), and opens a MASQUE bind session tagged with the
//! connection id so the proxy can relay via the edge address.
//!
//! This first slice provides the transport-independent foundation:
//!
//! * [`endpoint`] — the Endpoint keypair, its JWK (`cnf`) and its Endpoint ID
//!   (derived identically to the proxy, spec §4.2);
//! * [`pop`] — Proof-of-Possession header generation (spec §8.0).
//!
//! The Identity API client, the proxy H3 control-plane client (via
//! `channel-masque`), and the MASQUE bind session build on top of these.

pub mod endpoint;
pub mod identity;
pub mod pop;
pub mod proxy;

/// msquic HTTP/3 transport for the proxy control plane (feature `msquic`).
#[cfg(feature = "msquic")]
pub mod transport;
