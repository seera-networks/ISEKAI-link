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
pub mod tls;
pub mod video;

pub use server::{spawn_p2p_server, ServerCommand, ServerHandle, ServerInfo};
pub use video::{
    bind_video_listener, receive_frames, serve_frames, serve_frames_with, ServeOptions, VIDEO_ALPN,
};

/// Re-exports of the P2P types the camera apps build on.
pub use isekai_p2p::agent::CertBundle;
pub use isekai_p2p::{load_or_generate_key, InitiatorSession, P2pConfig};
