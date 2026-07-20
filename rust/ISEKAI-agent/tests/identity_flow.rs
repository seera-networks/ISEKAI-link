//! Integration test: drive the Identity API client against a local axum mock
//! that captures each request, verifying paths, auth, PoP headers and the DER
//! challenge/PoP signatures the client sends.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use isekai_agent::endpoint::EndpointKey;
use isekai_agent::https::HttpsTransport;
use isekai_agent::identity::IdentityClient;
use p256::ecdsa::Signature;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<(String, HeaderMap, Value)>>>);

async fn record(state: &Captured, path: &str, headers: HeaderMap, body: Bytes) {
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state
        .0
        .lock()
        .unwrap()
        .push((path.to_owned(), headers, value));
}

async fn challenge(State(s): State<Captured>, h: HeaderMap, b: Bytes) -> Json<Value> {
    record(&s, "/v1/endpoints/register/challenge", h, b).await;
    Json(json!({
        "challenge_id": "chl_1",
        "challenge": "CHALLENGE_VALUE",
        "expires_at": "2026-07-13T00:02:00Z",
    }))
}

async fn register(State(s): State<Captured>, h: HeaderMap, b: Bytes) -> Json<Value> {
    record(&s, "/v1/endpoints/register", h, b).await;
    Json(json!({
        "endpoint_id": "ep:abc",
        "device_id": "dev_1",
        "user_id": "auth0|u",
        "status": "active",
        "registered_at": "2026-07-13T00:00:01Z",
    }))
}

async fn issue_token(State(s): State<Captured>, h: HeaderMap, b: Bytes) -> Json<Value> {
    record(&s, "/v1/tokens/endpoint", h, b).await;
    Json(json!({
        "endpoint_token": "TOKEN.JWT.VALUE",
        "token_type": "Bearer",
        "expires_in": 900,
        "endpoint_id": "ep:abc",
        "permissions": ["peer-connect:initiate"],
        "protocols": ["isekai-validator-v1"],
    }))
}

#[tokio::test]
async fn register_and_issue_sends_correct_requests() {
    let captured = Captured::default();
    let app = Router::new()
        .route("/v1/endpoints/register/challenge", post(challenge))
        .route("/v1/endpoints/register", post(register))
        .route("/v1/tokens/endpoint", post(issue_token))
        .with_state(captured.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let key = EndpointKey::generate();
    // The mock speaks cleartext h1; the transport is the same one that talks
    // h1/h2 over TLS to the real Identity API.
    let client = IdentityClient::new(
        HttpsTransport::connect(&format!("http://{addr}")).expect("transport builds"),
    );
    let token = client
        .register_and_issue("AUTH0_AT", &key, Some("test-device"), Some(900))
        .await
        .expect("flow succeeds");
    assert_eq!(token.endpoint_token, "TOKEN.JWT.VALUE");
    assert_eq!(token.expires_in, 900);

    let reqs = captured.0.lock().unwrap();
    assert_eq!(reqs.len(), 3, "challenge + register + token");

    // 1) challenge: Auth0 bearer, carries endpoint_id + public JWK.
    let (path, headers, body) = &reqs[0];
    assert_eq!(path, "/v1/endpoints/register/challenge");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AUTH0_AT");
    assert_eq!(body["endpoint_id"], key.endpoint_id());
    assert_eq!(body["public_key"]["kty"], "EC");

    // 2) register: signs the challenge (DER) with a timestamp.
    let (path, _h, body) = &reqs[1];
    assert_eq!(path, "/v1/endpoints/register");
    assert_eq!(body["challenge_id"], "chl_1");
    assert_eq!(body["device_name"], "test-device");
    assert!(body["timestamp"].is_string());
    let sig = URL_SAFE_NO_PAD
        .decode(body["signature"].as_str().unwrap())
        .unwrap();
    Signature::from_der(&sig).expect("challenge signature is DER");

    // 3) token: Auth0 bearer + PoP headers, endpoint_id in body.
    let (path, headers, body) = &reqs[2];
    assert_eq!(path, "/v1/tokens/endpoint");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AUTH0_AT");
    assert_eq!(headers.get("x-endpoint-id").unwrap(), &key.endpoint_id());
    assert!(headers.get("x-pop-nonce").is_some());
    assert!(headers.get("x-pop-timestamp").is_some());
    let pop_sig = URL_SAFE_NO_PAD
        .decode(headers.get("x-pop-signature").unwrap().to_str().unwrap())
        .unwrap();
    Signature::from_der(&pop_sig).expect("PoP signature is DER");
    assert_eq!(body["endpoint_id"], key.endpoint_id());
}
