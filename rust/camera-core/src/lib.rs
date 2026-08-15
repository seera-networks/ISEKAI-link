//! Video transport and P2P wiring for the camera apps, free of OpenCV / egui.
//!
//! The GUIs (`camera-server`, `camera-client`) handle camera capture and
//! rendering; everything about moving frames over QUIC — directly or over the
//! P2P relay — lives here so it builds and is tested on its own.
//!
//! * [`video`] — the `sample`-ALPN MJPEG-over-QUIC transport (server + client
//!   halves), usable over any address.
//! * [`server`] — server-side P2P orchestration ([`spawn_p2p_server`]): bind the
//!   video listener, create a P2P `ListenerSession` relaying to it, and drive
//!   capability issuance / the relay bind leg from the GUI.
//! * [`tls`] — the dev self-signed certificate for the video listener.
//! * [`paired`] — the Endpoints this device paired with, so a later connection
//!   can be held against the one the code was read off.

pub mod cameras;
pub mod paired;
pub mod privacy;
pub mod server;
pub mod shutdown;
pub mod tls;
pub mod video;

pub use cameras::{connects_on_grant, display_name, one_per_camera};
pub use isekai_p2p::agent::{
    pairing_code_from_input, pairing_code_in_uri, pairing_uri, Grant, PairingCode,
    ReachableListener,
};
pub use isekai_p2p::{AcceptPolicy, PeerDirectory, SignalingEvent, MAX_CONCURRENT_PEERS};
pub use server::{spawn_p2p_server, ServerCommand, ServerHandle, ServerInfo};
pub use shutdown::{drain_registration, shutdown_and_exit};
pub use video::{
    bind_video_listener, receive_frames, receive_frames_with, serve_frames, serve_frames_with,
    AttestedPeer, PathEvent, RelayLegs, ServeOptions, VideoRecvOptions, VIDEO_ALPN,
    VIDEO_IDLE_TIMEOUT,
};

/// Re-exports of the P2P types the camera apps build on.
pub use isekai_p2p::agent::{CertBundle, EndpointToken, ObservedAddressWatch, RelayOptions};
/// Signing in to Auth0 and staying signed in — what keeps a camera's Endpoint
/// Token renewable for longer than one access token's lifetime.
pub use isekai_p2p::{auth0, Auth0TokenSource, StaticAuth0Token};
pub use isekai_p2p::{issue_endpoint_token, load_or_generate_key, InitiatorSession, P2pConfig};

/// Open the msquic registration an application should run everything on.
///
/// One per process, shared by the relay leg and the video listener or
/// connection. msquic looks bindings up per registration, so a direct path
/// opened from the leg's binding is not reachable from a connection on a
/// different one — that mismatch produces a path that validates and then
/// carries nothing, which is a hard failure to read from the outside.
///
/// Pair it with [`shutdown::shutdown_and_exit`] on the way out.
pub fn new_registration() -> anyhow::Result<std::sync::Arc<msquic_async::Registration>> {
    use anyhow::Context as _;
    Ok(std::sync::Arc::new(
        msquic_async::Registration::new(&msquic_async::msquic::RegistrationConfig::default())
            .context("could not open the msquic registration")?,
    ))
}
