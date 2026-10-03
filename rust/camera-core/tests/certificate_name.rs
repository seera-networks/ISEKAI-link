//! A certificate that is perfectly valid and is for somebody else does not get
//! a connection (#134).
//!
//! **Since seera-msquic 2.7.0 the refusal comes from msquic, not from us.**
//! It validates the name itself and answers `bad_certificate` without
//! indicating the certificate, so `install_certificate_check` never runs and
//! the `refused` slot the dial reads stays empty — which is precisely the case
//! `untrusted_chain.rs` was written for, now reached by a name as well as by an
//! issuer. Nothing is less safe: the connection is refused, and classified off
//! the transport's status as permanent rather than retried to the deadline,
//! which is what #141 was about. What is gone is the message naming the name
//! that arrived, because this side never sees it.
//!
//! **So this test no longer shows that a verdict from our callback reaches the
//! handshake**, and that is worth stating rather than leaving to be discovered.
//! It was the only integration test that did: `certificate_matches` has unit
//! tests, but a matcher that is never reached looks exactly like a matcher that
//! works. The mechanism is intact and still has a user — the key pin in
//! `isekai_p2p::peer::install_certificate_check`, where the chain is valid and
//! the name is right and only the key is wrong, so msquic indicates the
//! certificate and the callback decides. **A test for that is the way to get
//! this coverage back**, and there is not one yet.
//!
//! What is still checked here is what the bug was: a certificate that is
//! perfectly valid and is for somebody else gets no connection, promptly, with
//! an error an operator can act on.
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
//! `untrusted_chain.rs` is the other half of the pair: there the name is right
//! and the *issuer* is the difference. Both refusals now come from msquic's own
//! validation and neither reaches the slot the dial reads; they differ in the
//! alert the transport sends, which is why each test asserts its own number.
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

/// How long the refused half may take before the refusal counts as a retry.
///
/// The same thirty seconds `untrusted_chain.rs` allows, and for the same
/// reason: a permanent answer that is retried is the bug, and the only way a
/// test sees the difference is the clock.
const REFUSAL_BUDGET: Duration = Duration::from_secs(30);

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

            // ── The half that must fail, and must fail quickly ───────────────
            //
            // **The budget is half the assertion.** A certificate for another
            // host is refused on every attempt, so a dial that is still going
            // is one retrying a permanent answer — the #141 failure, which
            // costs a viewer the full fifteen-minute deadline and then reports
            // a timeout.
            let refusal =
                tokio::time::timeout(REFUSAL_BUDGET, dial_against(&reg, ca.issue(OTHER), DIALED))
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                    "still dialling after {REFUSAL_BUDGET:?}: a certificate for another host is \
                     being retried rather than classified, which is #141",
                )
                    })
                    .expect_err("a certificate for another host must not connect");
            let refusal = format!("{refusal:#}");
            // **The name dialled, not the name that arrived.** msquic refuses
            // this itself now and does not hand the certificate over, so the
            // other name never reaches this side — see the module header.
            assert!(
                refusal.contains(DIALED),
                "the refusal should name the host that was dialled, which is the one an \
                 operator can do something about: {refusal}",
            );
            // 42 is `bad_certificate`, which is what this platform's verifier
            // sends for a name mismatch. Asserted for the same reason
            // `untrusted_chain.rs` asserts 48: without it the test passes on
            // any refusal at all, including ones that have nothing to do with
            // the name.
            assert!(
                refusal.contains("TLS alert 42"),
                "the refusal should name the alert the transport actually sent for a name \
                 mismatch: {refusal}",
            );
            assert!(
                !refusal.contains("did not complete within"),
                "reported as a handshake that went unanswered, which is the failure #141 \
                 describes: {refusal}",
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
