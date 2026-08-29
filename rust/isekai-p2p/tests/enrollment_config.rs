//! `issue_endpoint_token` on the unattended credential: enrol once, then renew.
//!
//! `token_flow.rs` covers the attended branch. This one exists for the part
//! that is not a translation of the spec but a decision about state — **which
//! call enrols and which renews** — and for the invariant that decision has to
//! hold: a keypair registers exactly one Endpoint, so a second enrolment is
//! `409 endpoint-already-registered`, which is unrecoverable *and* does not
//! free the slot it spent.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use axum::Router;
use isekai_p2p::agent::EndpointKey;
use isekai_p2p::config::{issue_endpoint_token, P2pConfig};
use isekai_p2p::{AssertionSource, Credential, Enrollment};
use serde_json::{json, Value};

/// Every request the mock Identity API saw: (path, body).
#[derive(Clone, Default)]
struct Hits(Arc<Mutex<Vec<(String, Value)>>>);

impl Hits {
    fn paths(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }

    fn bodies(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b.clone())
            .collect()
    }
}

async fn record(state: &Hits, path: &str, body: Bytes) {
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state.0.lock().unwrap().push((path.to_owned(), value));
}

fn challenge_response() -> Json<Value> {
    Json(json!({
        "challenge_id": "chl_1",
        "challenge": "CHALLENGE_VALUE",
        "expires_at": "2026-08-28T00:02:00Z",
    }))
}

async fn serve(hits: Hits) -> String {
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "enroll/challenge", b).await;
                    challenge_response()
                },
            ),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "enroll", b).await;
                    Json(json!({
                        "endpoint_id": "ep:abc",
                        "endpoint_token": "TOKEN.FROM.ENROL",
                        "expires_in": 900,
                        "permissions": ["peer-connect:initiate"],
                        "protocols": ["isekai-portal-v1"],
                    }))
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh/challenge",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "refresh/challenge", b).await;
                    challenge_response()
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "refresh", b).await;
                    Json(json!({
                        "endpoint_token": "TOKEN.FROM.REFRESH",
                        "token_type": "Bearer",
                        "expires_in": 900,
                        "endpoint_id": "ep:abc",
                        "permissions": ["peer-connect:initiate"],
                        "protocols": ["isekai-portal-v1"],
                    }))
                },
            ),
        )
        .with_state(hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Counts how many times an assertion was asked for, and for which audience.
#[derive(Default)]
struct CountingAssertions {
    calls: AtomicUsize,
    audiences: Mutex<Vec<String>>,
}

impl AssertionSource for CountingAssertions {
    fn assertion<'a>(
        &'a self,
        audience: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.audiences.lock().unwrap().push(audience.to_owned());
        Box::pin(async move { Ok(format!("ASSERTION.FOR.{audience}")) })
    }
}

fn config(identity_url: String, credential: Credential) -> P2pConfig {
    P2pConfig {
        identity_url,
        identity_http3: false,
        proxy_url: String::new(),
        credential,
        protocol: "isekai-portal-v1".into(),
        device_name: Some("gha-4821".into()),
        token_ttl: Some(900),
        key: EndpointKey::generate(),
    }
}

#[tokio::test]
async fn the_first_call_enrols_and_the_rest_renew() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let cfg = config(url, Credential::enrollment("enr1_SECRET"));

    let first = issue_endpoint_token(&cfg).await.expect("enrol");
    assert_eq!(first.endpoint_token, "TOKEN.FROM.ENROL");
    // The enrolment response carries the first token (§8.8.5), so the caller
    // that did the work must not go on to spend a renewal getting a second.
    assert_eq!(hits.paths(), vec!["enroll/challenge", "enroll"]);

    let second = issue_endpoint_token(&cfg).await.expect("renew");
    assert_eq!(second.endpoint_token, "TOKEN.FROM.REFRESH");
    assert_eq!(
        hits.paths(),
        vec!["enroll/challenge", "enroll", "refresh/challenge", "refresh"],
    );
}

/// **The invariant this whole shape exists for.**
///
/// `P2pConfig` is `Clone`, and the renewal task holds one while other callers
/// hold others. If "have we enrolled" were per-value, a clone would enrol
/// again — presenting the same keypair, taking `409`, and burning a slot it
/// cannot get back.
#[tokio::test]
async fn a_cloned_config_does_not_enrol_again() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let cfg = config(url, Credential::enrollment("enr1_SECRET"));

    issue_endpoint_token(&cfg).await.expect("enrol");
    let clone = cfg.clone();
    let token = issue_endpoint_token(&clone).await.expect("renew");

    assert_eq!(token.endpoint_token, "TOKEN.FROM.REFRESH");
    assert_eq!(
        hits.paths().iter().filter(|p| *p == "enroll").count(),
        1,
        "one key registers one Endpoint; a second enrolment is an unrecoverable 409",
    );
}

/// Concurrency, which is the case a sequential test cannot see: the renewal
/// task runs beside whoever else is asking.
#[tokio::test]
async fn concurrent_callers_enrol_once_between_them() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let cfg = config(url, Credential::enrollment("enr1_SECRET"));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            issue_endpoint_token(&cfg).await.map(|t| t.endpoint_token)
        }));
    }
    let mut tokens = Vec::new();
    for task in tasks {
        tokens.push(task.await.unwrap().expect("a token"));
    }

    assert_eq!(tokens.len(), 8);
    assert_eq!(
        hits.paths().iter().filter(|p| *p == "enroll").count(),
        1,
        "the losers must fall through to a renewal, not a second enrolment",
    );
    // The winner keeps the token its enrolment produced; everyone else renewed.
    assert_eq!(
        tokens.iter().filter(|t| *t == "TOKEN.FROM.ENROL").count(),
        1,
    );
}

/// An assertion is minted for every call that verifies the binding, and for the
/// Identity audience rather than the proxy's.
///
/// Not once per job: §8.8.7 checks `binding` on every renewal, which is what
/// stops an `oidc` key working after the job that owns the workload identity
/// has ended.
#[tokio::test]
async fn every_renewal_mints_a_fresh_assertion() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let assertions = Arc::new(CountingAssertions::default());
    let credential = Enrollment::new("enr1_SECRET")
        .with_assertions(assertions.clone())
        .into();
    let cfg = config(url, credential);

    issue_endpoint_token(&cfg).await.expect("enrol");
    issue_endpoint_token(&cfg).await.expect("renew");
    issue_endpoint_token(&cfg).await.expect("renew again");

    assert_eq!(
        assertions.calls.load(Ordering::SeqCst),
        3,
        "one per call that spends the key, not one per session",
    );
    let audiences = assertions.audiences.lock().unwrap().clone();
    assert!(
        audiences.iter().all(|a| a == "isekai-identity"),
        "the proxy's audience is a different token: {audiences:?}",
    );

    let bodies = hits.bodies();
    let paths = hits.paths();
    for (path, body) in paths.iter().zip(bodies.iter()) {
        assert_eq!(body["enrollment_key"], "enr1_SECRET", "{path}");
        // The challenge legs do not verify the binding, so they do not carry
        // the evidence: asking twice only widens the window for it to expire.
        let wants_assertion = path == "enroll" || path == "refresh";
        assert_eq!(
            body["assertion"].is_null(),
            !wants_assertion,
            "{path} carried the wrong thing",
        );
    }
}

/// A response that omits `expires_in` renews on the §8.2.1 floor, not on zero.
#[tokio::test]
async fn a_silent_lifetime_falls_back_to_the_floor() {
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(|| async { challenge_response() }),
        )
        .route(
            "/v1/endpoints/enroll",
            post(|| async { Json(json!({ "endpoint_id": "ep:abc", "endpoint_token": "T" })) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let cfg = config(
        format!("http://{addr}"),
        Credential::enrollment("enr1_SECRET"),
    );
    let token = issue_endpoint_token(&cfg).await.expect("enrol");
    // 300 is what §8.2.1 clamps a `ttl` to; zero would put the renewal loop on
    // its 30-second minimum for the length of the job.
    assert_eq!(token.expires_in, 300);
}

/// An enrolment that reached the server but not the caller still leaves a
/// working session.
///
/// **The expensive shape.** `get_or_try_init` does not remember failures, so
/// without this every later call re-enrols, takes `409` again, and the renewal
/// loop retries that for the length of the job — while a plain refresh would
/// have worked all along. The response body being unreadable is a case
/// `Enrolled` explicitly anticipates; a dropped connection while reading it is
/// another.
#[tokio::test]
async fn an_enrolment_the_server_already_did_falls_through_to_renewal() {
    let hits = Hits::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "enroll/challenge", b).await;
                    challenge_response()
                },
            ),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "enroll", b).await;
                    (
                        axum::http::StatusCode::CONFLICT,
                        Json(json!({ "type": "endpoint-already-registered" })),
                    )
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh/challenge",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "refresh/challenge", b).await;
                    challenge_response()
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "refresh", b).await;
                    Json(json!({
                        "endpoint_token": "TOKEN.FROM.REFRESH",
                        "token_type": "Bearer",
                        "expires_in": 900,
                        "endpoint_id": "ep:abc",
                    }))
                },
            ),
        )
        .with_state(hits.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let cfg = config(
        format!("http://{addr}"),
        Credential::enrollment("enr1_SECRET"),
    );

    let first = issue_endpoint_token(&cfg)
        .await
        .expect("recovers via renewal");
    assert_eq!(first.endpoint_token, "TOKEN.FROM.REFRESH");

    // And it does not try to enrol again afterwards: the cell took the `409`
    // as the answer it is.
    let second = issue_endpoint_token(&cfg).await.expect("renews");
    assert_eq!(second.endpoint_token, "TOKEN.FROM.REFRESH");
    assert_eq!(
        hits.paths().iter().filter(|p| *p == "enroll").count(),
        1,
        "one attempt, then renewals",
    );
}

/// One Enrollment Key can grow several Endpoints, so the guard has to know
/// *which* one it recorded.
///
/// Sharing a credential across keypairs would otherwise let the second config
/// skip enrolment and renew an Endpoint that was never registered — a `403`
/// from §8.2.3 naming nothing. This says so where the mistake is made.
#[tokio::test]
async fn a_credential_will_not_stand_in_for_a_second_keypair() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let credential = Credential::enrollment("enr1_SECRET");

    let first = config(url.clone(), credential.clone());
    issue_endpoint_token(&first).await.expect("enrol");

    // Same credential, different keypair — `config` generates a fresh one.
    let second = config(url, credential);
    let err = issue_endpoint_token(&second)
        .await
        .expect_err("a keypair that never enrolled must not renew");
    let message = format!("{err:#}");
    assert!(message.contains("own Credential"), "{message}");
    assert_eq!(
        hits.paths().iter().filter(|p| *p == "refresh").count(),
        0,
        "and it must not have gone on to renew",
    );
}

/// A run that found the Endpoint already registered does not own the slot.
///
/// **This is what a second invocation beside a running one looks like.** The
/// CI job runs `portal-server --enroll --provisioning-key` while a
/// `portal-server` is already serving on the same keypair: the second process
/// enrols, takes `409`, and renews. If it then returned the slot on its way
/// out it would revoke the Endpoint the first one is serving on — and the next
/// redemption answers `403 provisioning-key-invalid`, because §8.13.6 counts
/// "the owner's Endpoint is revoked" among the uniform refusals.
///
/// Which is exactly what happened the first time this ran for real.
#[tokio::test]
async fn a_run_that_only_found_the_endpoint_does_not_own_its_slot() {
    let hits = Hits::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(|| async { challenge_response() }),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Hits>, _h: HeaderMap, b: Bytes| async move {
                    record(&s, "enroll", b).await;
                    (
                        axum::http::StatusCode::CONFLICT,
                        Json(json!({ "type": "endpoint-already-registered" })),
                    )
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh/challenge",
            post(|| async { challenge_response() }),
        )
        .route(
            "/v1/tokens/endpoint/refresh",
            post(|| async {
                Json(json!({
                    "endpoint_token": "T",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "endpoint_id": "ep:abc",
                }))
            }),
        )
        .with_state(hits.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let credential = Credential::enrollment("enr1_SECRET");
    let cfg = config(format!("http://{addr}"), credential.clone());
    issue_endpoint_token(&cfg).await.expect("renews via 409");

    let Credential::Enrollment(enrollment) = &credential else {
        unreachable!("built as an enrolment credential");
    };
    // It knows which Endpoint it is on …
    assert!(enrollment.endpoint_id().is_some());
    // … and that it is not the one that took the slot.
    assert!(
        !enrollment.registered_here(),
        "a 409 means somebody else registered; revoking here would take their Endpoint down",
    );
}

/// And the run that did register does own it.
#[tokio::test]
async fn a_run_that_registered_owns_its_slot() {
    let hits = Hits::default();
    let url = serve(hits).await;
    let credential = Credential::enrollment("enr1_SECRET");
    let cfg = config(url, credential.clone());
    issue_endpoint_token(&cfg).await.expect("enrol");

    let Credential::Enrollment(enrollment) = &credential else {
        unreachable!("built as an enrolment credential");
    };
    assert!(enrollment.registered_here());
}
