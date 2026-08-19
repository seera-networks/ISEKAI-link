//! High-level P2P Connect orchestration over the `isekai-p2p-core` primitives.
//!
//! `isekai-p2p-core` provides the protocol pieces (Endpoint keys and PoP, the
//! Identity API client, the proxy control-plane client, the MASQUE relay legs).
//! This crate ties them into the two end-to-end flows an application actually
//! runs, so a co-located service can stream over the relay without driving each
//! step by hand:
//!
//! * [`ListenerSession`] — the target: create a Peer Listener, issue
//!   capabilities, and bind the relay leg to a local address.
//! * [`InitiatorSession`] — the initiator: `peer_connect` and open the relay
//!   connect leg, exposing a local address the application dials.
//!
//! Both are configured by a [`P2pConfig`] and built on the same
//! [`issue_endpoint_token`] step.
//!
//! For convenience the `isekai-p2p-core` types these APIs hand back or take are
//! re-exported under [`agent`].

pub mod auth;
pub mod auth0;
pub mod config;
pub mod initiator;
pub mod listener;
pub mod secret;

pub use auth::{Auth0TokenSource, StaticAuth0Token};
pub use config::{issue_endpoint_token, load_or_generate_key, proxy_client, P2pConfig};
pub use initiator::{InitiatorSession, PeerDirectory};
pub use listener::{
    AcceptPolicy, LegDirectory, ListenerSession, SignalingEvent, SignalingState,
    MAX_CONCURRENT_PEERS,
};

/// Re-exports of the `isekai-p2p-core` items that appear in this crate's API.
pub mod peer;

pub mod agent {
    /// Holding a peer QUIC connection safely — see [`crate::peer`].
    pub use crate::peer::{drain_registration, Dialed};
    pub use isekai_p2p_core::attestation::{attest, verify, Attestation, AttestationError};
    pub use isekai_p2p_core::bind::RelayOptions;
    pub use isekai_p2p_core::endpoint::EndpointKey;
    /// Whether a peer certificate names the host that was dialled (#134).
    pub use isekai_p2p_core::hostname::certificate_matches;
    pub use isekai_p2p_core::identity::EndpointToken;
    pub use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};
    pub use isekai_p2p_core::proxy::{
        pairing_code_from_input, pairing_code_in_uri, pairing_uri, Candidate, CandidateType,
        Capability, CertBundle, ConnectionStateFilter, Grant, ListenerConnections, ListenerEvent,
        PairingCode, PeerConnection, ReachableListener,
    };
    pub use isekai_p2p_core::proxy::{
        CachedCertificate, CertificateParameters, IssuedCertificate, ProxyClient, ProxyError,
    };
    pub use isekai_p2p_core::transport::{drain_msquic, shutdown_msquic, MasqueH3Transport};
}
