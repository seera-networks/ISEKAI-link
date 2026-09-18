//! `issue_endpoint_token` drives the register→challenge→register→issue flow
//! against a mock Identity API, over the default h1/h2 transport.
//!
//! The per-request assertions (paths, Auth0 bearer, PoP headers, DER
//! signatures) live in `isekai-p2p-core`'s `identity_flow` test; this one checks
//! the `isekai-p2p` config wrapper: that `register` selects register-then-issue
//! and the Endpoint Token comes back intact.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use axum::Router;
use isekai_p2p::agent::EndpointKey;
use isekai_p2p::config::{issue_endpoint_token, P2pConfig};
use isekai_p2p::Credential;
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct Hits(Arc<Mutex<Vec<String>>>);

async fn challenge(State(s): State<Hits>, _h: HeaderMap, _b: Bytes) -> Json<Value> {
    s.0.lock().unwrap().push("challenge".into());
    Json(json!({
        "challenge_id": "chl_1",
        "challenge": "CHALLENGE_VALUE",
        "expires_at": "2026-07-13T00:02:00Z",
    }))
}

async fn register(State(s): State<Hits>, _h: HeaderMap, _b: Bytes) -> Json<Value> {
    s.0.lock().unwrap().push("register".into());
    Json(json!({
        "endpoint_id": "ep:abc",
        "device_id": "dev_1",
        "user_id": "auth0|u",
        "status": "active",
        "registered_at": "2026-07-13T00:00:01Z",
    }))
}

async fn issue_token(State(s): State<Hits>, _h: HeaderMap, _b: Bytes) -> Json<Value> {
    s.0.lock().unwrap().push("token".into());
    Json(json!({
        "endpoint_token": "TOKEN.JWT.VALUE",
        "token_type": "Bearer",
        "expires_in": 900,
        "endpoint_id": "ep:abc",
        "permissions": ["peer-connect:initiate"],
        "protocols": ["isekai-validator-v1"],
    }))
}

fn config(identity_url: String, register: bool) -> P2pConfig {
    P2pConfig {
        identity_url,
        identity_http3: false,
        proxy_url: String::new(),
        credential: Credential::auth0("AUTH0_AT", None, register),
        protocol: "isekai-validator-v1".into(),
        device_name: Some("test-device".into()),
        token_ttl: Some(900),
        key: EndpointKey::generate(),
        narrowing: Default::default(),
    }
}

async fn serve(hits: Hits) -> String {
    let app = Router::new()
        .route("/v1/endpoints/register/challenge", post(challenge))
        .route("/v1/endpoints/register", post(register))
        .route("/v1/tokens/endpoint", post(issue_token))
        .with_state(hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn register_then_issue_returns_the_endpoint_token() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;

    let token = issue_endpoint_token(&config(url, true))
        .await
        .expect("flow succeeds");

    assert_eq!(token.endpoint_token, "TOKEN.JWT.VALUE");
    assert_eq!(token.expires_in, 900);
    assert_eq!(
        *hits.0.lock().unwrap(),
        vec!["challenge", "register", "token"],
        "register=true runs the full challenge→register→issue flow",
    );
}

#[tokio::test]
async fn without_register_only_issues() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;

    let token = issue_endpoint_token(&config(url, false))
        .await
        .expect("flow succeeds");

    assert_eq!(token.endpoint_token, "TOKEN.JWT.VALUE");
    assert_eq!(
        *hits.0.lock().unwrap(),
        vec!["token"],
        "register=false skips registration",
    );
}

/// **The second issue must not register again.**
///
/// `register` is a static argument and `issue()` re-reads it on every renewal,
/// so a config that registered once would present the same keypair again and
/// take `409 endpoint-already-registered`. Nothing in the Auth0 arm caught
/// that, so every renewal from the second onwards failed — and a task outliving
/// one token lost its Endpoint Token partway through. Agent mode meets this on
/// every run, because a task-scoped key is freshly generated and so must
/// register.
#[tokio::test]
async fn renewing_issues_rather_than_registering_again() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let cfg = config(url, true);

    issue_endpoint_token(&cfg).await.expect("the first token");
    issue_endpoint_token(&cfg).await.expect("the renewal");

    assert_eq!(
        *hits.0.lock().unwrap(),
        vec!["challenge", "register", "token", "token"],
        "the renewal issues against the Endpoint the first call registered",
    );
}

/// The cell is shared across clones, because the renewal task holds one.
#[tokio::test]
async fn a_cloned_config_registers_no_second_time() {
    let hits = Hits::default();
    let url = serve(hits.clone()).await;
    let cfg = config(url, true);
    let renewal = cfg.clone();

    issue_endpoint_token(&cfg).await.expect("the first token");
    issue_endpoint_token(&renewal).await.expect("the renewal");

    assert_eq!(
        *hits.0.lock().unwrap(),
        vec!["challenge", "register", "token", "token"],
    );
}

/// **A `409` on the way in is not a failure.** The registration can reach the
/// server and the answer not come back; `get_or_try_init` does not remember
/// failures, so without an arm for it every renewal would register again, take
/// `409` again, and keep doing that while a plain issue would have worked.
#[tokio::test]
async fn an_endpoint_already_registered_is_issued_against() {
    let hits = Hits::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/register/challenge",
            post(|State(s): State<Hits>| async move {
                s.0.lock().unwrap().push("challenge".into());
                (
                    axum::http::StatusCode::CONFLICT,
                    Json(json!({
                        "type": "https://identity.isekai.tools/problems/endpoint-already-registered",
                        "title": "Endpoint already registered",
                        "status": 409,
                    })),
                )
            }),
        )
        .route("/v1/tokens/endpoint", post(issue_token))
        .with_state(hits.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cfg = config(format!("http://{addr}"), true);

    issue_endpoint_token(&cfg).await.expect("the first token");
    issue_endpoint_token(&cfg).await.expect("the renewal");

    assert_eq!(
        *hits.0.lock().unwrap(),
        vec!["challenge", "token", "token"],
        "the 409 settles the cell, so the renewal does not try to register again",
    );
}
