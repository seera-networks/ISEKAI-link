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
/// Reading and retiring the Endpoints an account owns (§8.1.3 / §8.1.4 / §8.7).
pub mod endpoints;
/// Managing Enrollment Keys from the owner's side (§8.8.2 / §8.8.9).
pub mod enrollment;
pub mod initiator;
pub mod listener;
/// Where an unattended job's workload identity assertion comes from.
pub mod oidc;
/// Holding a relay leg's lease open (proxy spec §8.14).
pub mod relay_lease;
pub mod secret;

pub use auth::{AssertionSource, Auth0TokenSource, Credential, Enrollment, StaticAuth0Token};
pub use config::{issue_endpoint_token, load_or_generate_key, proxy_client, P2pConfig};
pub use initiator::{InitiatorSession, PeerDirectory};
pub use listener::{
    AcceptPolicy, LegDirectory, ListenerSession, SignalingEvent, SignalingState,
    MAX_CONCURRENT_PEERS,
};
// Documented by their own module headers, which is where the rules are written
// down. An outer doc comment here would be concatenated in front of those and
// resolved in *this* scope, so every `[`dial`]` in it would break.
pub mod direct_path;
pub mod endpoint_cert;
pub mod peer;
/// Measuring the relays so a near one is chosen (`relay_proximity_plan.md`).
pub mod relay_rtt;

/// Re-exports of the `isekai-p2p-core` items that appear in this crate's API.
pub mod agent {
    pub use isekai_p2p_core::attestation::{attest, verify, Attestation, AttestationError};
    pub use isekai_p2p_core::bind::RelayOptions;
    pub use isekai_p2p_core::endpoint::EndpointKey;
    /// Whether a peer certificate names the host that was dialled (#134).
    pub use isekai_p2p_core::hostname::certificate_matches;
    pub use isekai_p2p_core::identity::{
        Binding, EndpointDetail, EndpointList, EndpointSummary, EndpointToken, Enrolled,
        EnrollmentKeyRecord, EnrollmentRecord, IdentityAuth, IdentityError, IssuedEnrollmentKey,
        NewEnrollmentKey, RevokeAuth, RevokeEffects, RevokeReason, Revoked, RevokedEnrollmentKey,
    };
    pub use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};
    pub use isekai_p2p_core::proxy::{
        pairing_code_from_input, pairing_code_in_uri, pairing_uri, proxy_authority, redact_secrets,
        secret_prefix, ticket_from_transfer, ticket_transfer, BindingView, Candidate,
        CandidateType, Capability, CertBundle, ConnectionStateFilter, Grant, ListenerConnections,
        ListenerEvent, PairingCode, PeerConnection, ProvisioningBinding, ProvisioningKey,
        ProvisioningKeyRecord, ProvisioningRedemption, ReachableListener, RedeemedProvisioningKey,
        RedeemedTicket, Ticket, TicketListener, TicketRecord, TicketRedemption, TicketTransfer,
        ENROLLMENT_KEY_PREFIX, PROVISIONING_KEY_PREFIX, TICKET_PREFIX, TICKET_TRANSFER_PREFIX,
    };
    pub use isekai_p2p_core::proxy::{
        CachedCertificate, CertificateParameters, IssuedCertificate, ProxyClient, ProxyError,
    };
    pub use isekai_p2p_core::proxy::{RelayCandidate, RelayRttSample};
    pub use isekai_p2p_core::transport::{drain_msquic, shutdown_msquic, MasqueH3Transport};
}
