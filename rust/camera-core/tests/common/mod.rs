//! What the two certificate tests both need: a throwaway CA, and one round of
//! serve-and-dial over a real QUIC connection.
//!
//! They are a pair — `certificate_name.rs` varies the **name** inside the
//! certificate, `untrusted_chain.rs` varies the **CA that signed it** — and
//! each has one `#[test]` in its own file because both set `SSL_CERT_FILE`,
//! which is process-wide. Separate test binaries are separate processes; two
//! tests in one file would not be.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use camera_core::tls::video_cert;
use camera_core::video::{bind_video_listener, receive_frames, serve_frames};
use msquic_async::Registration;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Serve on `cert` and dial `host` with validation on, until a frame arrives or
/// the handshake is refused.
///
/// `host` never resolves: the dial pins the remote address to loopback itself,
/// so the name is only ever the TLS one.
pub async fn dial_against(
    reg: &Arc<Registration>,
    cert: camera_core::tls::VideoCert,
    // `'static` because the dial is spawned: both callers pass a `const`.
    host: &'static str,
) -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let (_reg, listener, addr) = bind_video_listener(
        Some(reg.clone()),
        "127.0.0.1:0".parse().unwrap(),
        Some(&cert),
    )
    .expect("bind the listener");
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let serve = tokio::spawn(serve_frames(listener, frame_rx, shutdown.clone()));

    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let client = tokio::spawn(receive_frames(
        Some(reg.clone()),
        host,
        addr.port(),
        true,
        recv_tx,
        shutdown.clone(),
    ));

    // The server only fans out to connected clients, so keep offering frames
    // until one lands or the dial gives up.
    let payload = Bytes::from_static(b"frame");
    let mut client = client;
    let outcome = loop {
        if frame_tx.send(payload.clone()).await.is_err() {
            break Err(anyhow::anyhow!("the server stopped accepting frames"));
        }
        tokio::select! {
            frame = recv_rx.recv() => if frame.is_some() { break Ok(()) },
            // The dial giving up is the other way this ends, and it is the one
            // the failing half takes.
            joined = &mut client => break match joined.expect("the client task did not panic") {
                Ok(()) => Err(anyhow::anyhow!("the client returned without a frame")),
                Err(e) => Err(e),
            },
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    };

    shutdown.cancel();
    let _ = serve.await;
    outcome
}

/// A throwaway CA, and leaves signed by it.
pub struct Authority {
    pub pem: String,
    certificate: rcgen::Certificate,
    key: KeyPair,
}

impl Authority {
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.self_signed(&key).expect("self-sign the CA");
        Self {
            pem: certificate.pem(),
            certificate,
            key,
        }
    }

    /// A leaf for `name`, signed by this CA, bundled the way the listener wants.
    pub fn issue(&self, name: &str) -> camera_core::tls::VideoCert {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
        let leaf = params
            .signed_by(&key, &self.certificate, &self.key)
            .expect("sign the leaf");
        // Leaf first, then the CA: the client has the root already, but a chain
        // that stops at the leaf is not one msquic will build a path from.
        let chain = format!("{}{}", leaf.pem(), self.pem);
        video_cert(name, &chain, &key).expect("bundle the certificate")
    }
}
