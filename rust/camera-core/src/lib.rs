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

pub mod server;
pub mod shutdown;
pub mod tls;
pub mod video;

pub use isekai_p2p::agent::{Grant, PairingCode, ReachableListener};
pub use isekai_p2p::{AcceptPolicy, PeerDirectory, SignalingEvent};
pub use server::{spawn_p2p_server, ServerCommand, ServerHandle, ServerInfo};
pub use shutdown::{drain_registration, shutdown_and_exit};
pub use video::{
    bind_video_listener, receive_frames, receive_frames_with, serve_frames, serve_frames_with,
    PathEvent, ServeOptions, VideoRecvOptions, VIDEO_ALPN,
};

/// Re-exports of the P2P types the camera apps build on.
pub use isekai_p2p::agent::{CertBundle, ObservedAddressWatch, RelayOptions};
pub use isekai_p2p::{load_or_generate_key, InitiatorSession, P2pConfig};

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
