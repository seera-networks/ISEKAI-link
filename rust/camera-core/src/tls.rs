//! The TLS material the video listener presents, under the names this crate's
//! apps and tests already import.
//!
//! **All of it moved to [`isekai_p2p::endpoint_cert`]** (plan §4.4, phase
//! 1c-iii). Nothing in it was ever about video except these names: what the
//! certificate settles is which Endpoint answered, which `portal-server` asks
//! exactly as the camera does.
//!
//! Kept as re-exports rather than rewriting the call sites, because
//! `load_or_generate_video_key` names a file that exists on every device this
//! has shipped to and `VideoCert` is what the apps and the loopback tests
//! spell. The layer's names say what the thing is; these say where it is used.

pub use isekai_p2p::endpoint_cert::{
    bundle as video_cert, certificate_request, dev_cert, issue as issue_video_cert,
    load_or_generate_cert_key as load_or_generate_video_key, spki_sha256,
    spki_sha256_of_certificate, DevCert, EndpointCert as VideoCert,
};
