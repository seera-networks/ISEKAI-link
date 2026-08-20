//! A certificate signed by a CA the client does not have is refused **at
//! once**, not fifteen minutes later (#141).
//!
//! `certificate_name.rs` is the other half of this pair: there the two
//! certificates are both trusted and the only difference is the name inside,
//! and the refusal comes from our own peer-certificate callback. Here the name
//! is right and the only difference is **who signed it**, so the refusal never
//! reaches that callback at all — msquic's own validation fails first, and the
//! `refused` slot the dial reads stays empty.
//!
//! That is the whole of #141. The dial retries for fifteen minutes by design,
//! because a peer binds its relay leg only once an operator has carried the
//! connection id across; a certificate nothing will ever trust was
//! indistinguishable from that, and what finally surfaced was a timeout that
//! reads as "the operator has not finished typing".
//!
//! **So this test is about the clock as much as the error.** A regression puts
//! it back to the 900-second deadline, and the budget below is what turns that
//! into a failure with a reason instead of a job that runs out of time.
//!
//! # Why the alert number is asserted
//!
//! The first fix classified msquic's *named* statuses, which looks equivalent
//! and is not: quictls maps `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`,
//! `DEPTH_ZERO_SELF_SIGNED_CERT` and `SELF_SIGNED_CERT_IN_CHAIN` — every way
//! this test's chain can fail — to `unknown_ca` (48), and **msquic has no named
//! status for that alert**. So the case below was the one the fix missed, on
//! the platforms it runs on. Asserting the number is asserting that.
//!
//! # Why this only runs on the quictls platforms
//!
//! Same reason as `certificate_name.rs`: the trusted half needs a CA invented
//! for one test to be trusted, and `SSL_CERT_FILE` is how that is done on the
//! quictls path — Linux and Android. Windows validates through schannel and
//! Apple through SecTrust, and neither can be told about it. There the same
//! certificate is refused as `bad_certificate` (42), which msquic does name.

#![cfg(any(target_os = "linux", target_os = "android"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{dial_against, Authority};
use msquic_async::{msquic, Registration};

/// The name both certificates below are for. Only the issuer differs.
const DIALED: &str = "right.test";

/// How long a refusal may take before this test calls it a retry loop.
///
/// Generously above a loopback handshake that fails on its first flight, and
/// far below `isekai_p2p::peer::CONNECT_DEADLINE` — the fifteen minutes a
/// missed classification spends before reporting a timeout. Anything in between
/// is the bug.
const REFUSAL_BUDGET: Duration = Duration::from_secs(30);

/// The trusted half is an ordinary handshake and gets an ordinary budget; it is
/// here to show the harness works, not to measure anything.
const CONNECT_BUDGET: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread")]
async fn a_chain_the_client_cannot_build_is_refused_at_once() {
    let trusted = Authority::new("ISEKAI link test CA");
    // Freshly generated, so it is in no store anywhere — not this test's, and
    // not the system's. That is what makes the failing half fail for the one
    // reason it is supposed to.
    let stranger = Authority::new("ISEKAI link stranger CA");

    let ca_file = std::env::temp_dir().join(format!("isekai-chain-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_file, &trusted.pem).expect("write the CA");
    // Read when the client credential is built, which is inside the dial below.
    std::env::set_var("SSL_CERT_FILE", &ca_file);
    // Both halves validate for real. If this were set, neither would prove
    // anything — and it leaks in from the environment on a developer machine.
    std::env::remove_var("ISEKAI_INSECURE_SKIP_VERIFY");

    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());

    // ── The half that must fail, and must fail quickly ──────────────────────
    let refusal = tokio::time::timeout(
        REFUSAL_BUDGET,
        dial_against(&reg, stranger.issue(DIALED), DIALED),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "still dialling after {REFUSAL_BUDGET:?}: a chain the client cannot build is being \
             retried rather than classified, which is #141 and costs a viewer fifteen minutes \
             of a spinner",
        )
    })
    .expect_err("a certificate from an unknown CA must not connect");
    let refusal = format!("{refusal:#}");
    assert!(
        refusal.contains("TLS alert 48"),
        "the refusal should name the alert the transport actually sent — 48 is `unknown_ca`, \
         the one msquic has no status name for and the one this platform sends for every way \
         this chain can fail: {refusal}",
    );
    assert!(
        !refusal.contains("did not complete within"),
        "reported as a handshake that went unanswered, which is the failure #141 describes: \
         {refusal}",
    );

    // ── The same certificate from the CA the client has ─────────────────────
    //
    // Without this the first half would also pass if nothing connected at all —
    // a listener that never binds, a name that does not match, a handshake that
    // fails for its own reasons and happens to be quick about it.
    tokio::time::timeout(
        CONNECT_BUDGET,
        dial_against(&reg, trusted.issue(DIALED), DIALED),
    )
    .await
    .expect("the trusted half connected within a minute")
    .expect("the certificate from the trusted CA must connect");

    let _ = std::fs::remove_file(&ca_file);
    camera_core::shutdown::drain_registration(&reg, Duration::from_secs(5)).await;
}
