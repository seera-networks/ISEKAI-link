//! A certificate that is perfectly valid and is for somebody else does not get
//! a connection (#134).
//!
//! **This is the test the unit ones cannot be.** `certificate_matches` is
//! exercised directly elsewhere, but a matcher that is never reached looks
//! exactly like a matcher that works: the callback has to be installed, the
//! credential has to carry the flags that make msquic hand the certificate
//! over, and the verdict has to reach the handshake. Only a real connection
//! shows all three.
//!
//! So there is a throwaway CA here. Without one the wrong-name certificate
//! would be refused for chain reasons before the name was ever looked at, and
//! the test would pass while proving nothing. With it, both certificates below
//! are ones the client fully trusts — the *only* difference between the two
//! halves is the name inside.
//!
//! One test rather than two, and one `#[test]` in the file: it sets
//! `SSL_CERT_FILE`, which is process-wide.
//!
//! # Why this only runs on the quictls platforms
//!
//! `SSL_CERT_FILE` is how the throwaway CA gets trusted, and it is read by the
//! quictls path — Linux and Android. Windows validates through schannel and
//! Apple through SecTrust, and **neither has any way to be told about a CA
//! invented for one test**. There, both certificates below are untrusted, so
//! the wrong-name one is refused for chain reasons before its name is looked
//! at: the test would report success while proving nothing, and the right-name
//! half would fail outright.
//!
//! The property still holds on those platforms — a certificate for another host
//! does not get a connection — it is just that their own verifiers are what
//! enforce it, so this is not the test that shows it. (A refusal from msquic's
//! own validation still never reaches the slot the dial reads; since #141 it is
//! classified off the transport's status instead, so finding out no longer
//! costs the full retry deadline.)

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use camera_core::tls::video_cert;
use camera_core::video::{bind_video_listener, receive_frames, serve_frames};
use msquic_async::{msquic, Registration};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The name the client asks for. It never resolves: the video dial pins the
/// remote address to loopback itself, so the name is only ever the TLS one.
const DIALED: &str = "right.test";
/// The name the certificate in the failing half is for.
const OTHER: &str = "wrong.test";

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_for_another_host_does_not_get_a_connection() {
    let ca = Authority::new();
    let ca_file = std::env::temp_dir().join(format!("isekai-test-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_file, &ca.pem).expect("write the CA");
    // Read when the client credential is built, which is inside the dial below.
    std::env::set_var("SSL_CERT_FILE", &ca_file);
    // Both halves validate for real. If this were set, neither would prove
    // anything — and it leaks in from the environment on a developer machine.
    std::env::remove_var("ISEKAI_INSECURE_SKIP_VERIFY");

    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());

    // ── The half that must fail ─────────────────────────────────────────────
    let refusal = dial_against(&reg, ca.issue(OTHER)).await;
    let refusal = refusal.expect_err("a certificate for another host must not connect");
    let refusal = format!("{refusal:#}");
    assert!(
        refusal.contains(OTHER) && refusal.contains(DIALED),
        "the refusal should say which name arrived and which was wanted: {refusal}",
    );

    // ── The same setup, one name different ──────────────────────────────────
    //
    // Without this the first half would also pass if nothing connected at all —
    // a broken CA, a listener that never binds, a handshake that fails for its
    // own reasons.
    dial_against(&reg, ca.issue(DIALED))
        .await
        .expect("the certificate for the dialed host must connect");

    let _ = std::fs::remove_file(&ca_file);
    camera_core::shutdown::drain_registration(&reg, Duration::from_secs(5)).await;
}

/// Serve on `cert` and dial [`DIALED`] with validation on, until a frame
/// arrives or the handshake is refused.
async fn dial_against(
    reg: &Arc<Registration>,
    cert: camera_core::tls::VideoCert,
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
        DIALED,
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
struct Authority {
    pem: String,
    certificate: rcgen::Certificate,
    key: KeyPair,
}

impl Authority {
    fn new() -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "ISEKAI link test CA");
        let certificate = params.self_signed(&key).expect("self-sign the CA");
        Self {
            pem: certificate.pem(),
            certificate,
            key,
        }
    }

    /// A leaf for `name`, signed by this CA, bundled the way the listener wants.
    fn issue(&self, name: &str) -> camera_core::tls::VideoCert {
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
