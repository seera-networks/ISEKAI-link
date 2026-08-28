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
use isekai_p2p::{AssertionSource, Credential};
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
    let credential = match Credential::enrollment("enr1_SECRET") {
        Credential::Enrollment(e) => Credential::Enrollment(e.with_assertions(assertions.clone())),
        other => other,
    };
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
