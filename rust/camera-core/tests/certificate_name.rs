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
//! `untrusted_chain.rs` is the other half of the pair. There the name is right
//! and the *issuer* is the difference, so the refusal comes from msquic's own
//! validation instead of from the callback below — and never reaches the slot
//! the dial reads, which is #141.
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

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{dial_against, Authority};
use msquic_async::{msquic, Registration};

/// The name the client asks for. It never resolves: the video dial pins the
/// remote address to loopback itself, so the name is only ever the TLS one.
const DIALED: &str = "right.test";
/// The name the certificate in the failing half is for.
const OTHER: &str = "wrong.test";

/// Not `#[tokio::test]`: the environment is settled before the runtime exists.
///
/// `set_var` is a data race against every other thread in the process, which is
/// why Rust 2024 makes it `unsafe` — and a multi-threaded runtime has its
/// workers running by the time a `#[tokio::test]` body starts. `isekai-p2p-core`
/// is edition 2024 already, so this is also what stops compiling when
/// `camera-core` follows.
#[test]
fn a_certificate_for_another_host_does_not_get_a_connection() {
    let ca = Authority::new("ISEKAI link test CA");
    let ca_file = std::env::temp_dir().join(format!("isekai-test-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_file, &ca.pem).expect("write the CA");
    // Read when the client credential is built, which is inside the dial below.
    std::env::set_var("SSL_CERT_FILE", &ca_file);
    // Both halves validate for real. If this were set, neither would prove
    // anything — and it leaks in from the environment on a developer machine.
    std::env::remove_var("ISEKAI_INSECURE_SKIP_VERIFY");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime, once the environment is settled")
        .block_on(async {
            let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());

            // ── The half that must fail ──────────────────────────────────────
            let refusal = dial_against(&reg, ca.issue(OTHER), DIALED).await;
            let refusal = refusal.expect_err("a certificate for another host must not connect");
            let refusal = format!("{refusal:#}");
            assert!(
                refusal.contains(OTHER) && refusal.contains(DIALED),
                "the refusal should say which name arrived and which was wanted: {refusal}",
            );

            // ── The same setup, one name different ───────────────────────────
            //
            // Without this the first half would also pass if nothing connected at
            // all — a broken CA, a listener that never binds, a handshake that
            // fails for its own reasons.
            dial_against(&reg, ca.issue(DIALED), DIALED)
                .await
                .expect("the certificate for the dialed host must connect");

            let _ = std::fs::remove_file(&ca_file);
            camera_core::shutdown::drain_registration(&reg, Duration::from_secs(5)).await;
        });
}
