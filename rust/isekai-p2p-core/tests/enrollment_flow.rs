//! Integration test: the unattended routes (§8.7 / §8.8) and token renewal
//! (§8.2.2 / §8.2.3) against a local axum mock that captures each request.
//!
//! **What is asserted here is what goes on the wire**, because that is the
//! whole of what the client contributes. The three things this exists to pin
//! down, each of which is a decision rather than a detail:
//!
//! * the enrolment routes send **no `Authorization`** and put the credential in
//!   the body (§8.8.4);
//! * `refresh/challenge` sends **no assertion** while `refresh` does (§8.8.7),
//!   so one renewal costs one minting rather than two;
//! * self-revocation sends **no assertion and no reason**, and still signs a
//!   PoP — which is what confines it to this Endpoint.
//!
//! `identity_flow.rs` covers the attended registration path and the PoP/DER
//! encodings in detail; this does not repeat those.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{
    Binding, IdentityAuth, IdentityClient, NewEnrollmentKey, RevokeAuth, RevokeReason,
};

/// The enrolment credential these tests use, with no binding evidence.
fn enrolment(key: &str) -> IdentityAuth<'_> {
    IdentityAuth::enrollment(key)
}
use p256::ecdsa::Signature;
use serde_json::{Value, json};

/// A captured request: (path, headers, body).
type Call = (String, HeaderMap, Value);

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<Call>>>);

impl Captured {
    fn take(&self) -> Vec<Call> {
        self.0.lock().unwrap().clone()
    }
}

async fn record(state: &Captured, path: &str, headers: HeaderMap, body: Bytes) {
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state
        .0
        .lock()
        .unwrap()
        .push((path.to_owned(), headers, value));
}

fn challenge_body() -> Value {
    json!({
        "challenge_id": "chl_1",
        "challenge": "CHALLENGE_VALUE",
        "expires_at": "2026-08-28T00:02:00Z",
    })
}

/// Stand the mock up and hand back a client pointed at it.
///
/// The mock speaks cleartext h1; the transport is the same one that talks
/// h1/h2 over TLS to the real Identity API.
async fn serve(app: Router) -> IdentityClient<HttpsTransport> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    IdentityClient::new(
        HttpsTransport::connect(&format!("http://{addr}")).expect("transport builds"),
    )
}

fn der_signature(value: &Value) {
    let sig = URL_SAFE_NO_PAD
        .decode(value.as_str().expect("signature is a string"))
        .unwrap();
    Signature::from_der(&sig).expect("signature is DER");
}

// ---- §8.8.4 / §8.8.5 ----

#[tokio::test]
async fn enrolling_carries_the_key_in_the_body_and_no_authorization() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll/challenge", h, b).await;
                    Json(challenge_body())
                },
            ),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll", h, b).await;
                    Json(json!({
                        "endpoint_id": "ep:abc",
                        "device_id": "dev_ci_1",
                        "tenant_id": "org_a",
                        "user_id": "auth0|owner",
                        "status": "active",
                        "registered_at": "2026-08-28T00:00:01Z",
                        "enrollment_key_id": "enk_1",
                        "ephemeral": true,
                        "expires_at": "2026-08-28T01:00:01Z",
                        "endpoint_token": "TOKEN.JWT.VALUE",
                        "token_type": "Bearer",
                        "expires_in": 900,
                        "permissions": ["peer-connect:initiate"],
                        "protocols": ["isekai-portal-v1"],
                    }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let challenge = client
        .enroll_challenge(enrolment("enr1_SECRET"), &key)
        .await
        .expect("challenge");
    let enrolled = client
        .enroll(
            enrolment("enr1_SECRET").with_assertion("OIDC.JWT"),
            &key,
            &challenge,
            Some("gha-4821"),
            Some(900),
        )
        .await
        .expect("enrol");

    assert_eq!(enrolled.endpoint_id, "ep:abc");
    assert_eq!(enrolled.token().expires_in, 900);
    assert_eq!(enrolled.protocols, vec!["isekai-portal-v1"]);

    let reqs = captured.take();
    assert_eq!(reqs.len(), 2);

    // The challenge: credential in the body, and nothing in `Authorization`.
    let (path, headers, body) = &reqs[0];
    assert_eq!(path, "/v1/endpoints/enroll/challenge");
    assert!(
        headers.get("authorization").is_none(),
        "§8.8.4 puts the credential in the body so the header keeps one meaning",
    );
    assert_eq!(body["enrollment_key"], "enr1_SECRET");
    assert_eq!(body["endpoint_id"], key.endpoint_id());
    assert_eq!(body["public_key"]["kty"], "EC");
    // Written once. A second copy would be one more place to go stale.
    assert!(
        body["assertion"].is_null(),
        "no binding evidence at challenge time"
    );

    // The enrolment: the same key, the assertion, and a challenge signature.
    let (path, headers, body) = &reqs[1];
    assert_eq!(path, "/v1/endpoints/enroll");
    assert!(headers.get("authorization").is_none());
    assert_eq!(body["enrollment_key"], "enr1_SECRET");
    assert_eq!(body["assertion"], "OIDC.JWT");
    assert_eq!(body["challenge_id"], "chl_1");
    assert_eq!(body["device_name"], "gha-4821");
    der_signature(&body["signature"]);
}

/// The private key never leaves, whatever else is in the request.
#[tokio::test]
async fn enrolling_sends_the_public_key_only() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll/challenge", h, b).await;
                    Json(challenge_body())
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    client
        .enroll_challenge(enrolment("enr1_SECRET"), &key)
        .await
        .unwrap();

    let reqs = captured.take();
    let jwk = &reqs[0].2["public_key"];
    assert!(jwk["x"].is_string() && jwk["y"].is_string());
    assert!(
        jwk["d"].is_null(),
        "a JWK with `d` in it is the private key"
    );
}

/// A response carrying only the two required fields still parses.
///
/// The expensive direction: a successful enrolment reported as a failure has
/// spent a slot and burned the keypair, and every retry is `409`.
#[tokio::test]
async fn a_minimal_enrolment_response_is_enough() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(|| async { Json(challenge_body()) }),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll", h, b).await;
                    Json(json!({ "endpoint_id": "ep:abc", "endpoint_token": "T" }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let challenge = client
        .enroll_challenge(enrolment("enr1_S"), &key)
        .await
        .unwrap();
    let enrolled = client
        .enroll(enrolment("enr1_S"), &key, &challenge, None, None)
        .await
        .expect("a minimal response is not a failure");

    assert_eq!(enrolled.endpoint_token, "T");
    assert!(enrolled.expires_in.is_none());
    // 300, the floor §8.2.1 clamps to — not 0, which would put a renewal loop
    // on its 30-second minimum for the length of the job.
    assert_eq!(enrolled.token().expires_in, 300);
}

// ---- §8.2.2 / §8.2.3 ----

#[tokio::test]
async fn renewing_mints_one_assertion_and_signs_a_pop() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/tokens/endpoint/refresh/challenge",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/tokens/endpoint/refresh/challenge", h, b).await;
                    Json(challenge_body())
                },
            ),
        )
        .route(
            "/v1/tokens/endpoint/refresh",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/tokens/endpoint/refresh", h, b).await;
                    Json(json!({
                        "endpoint_token": "TOKEN.2",
                        "token_type": "Bearer",
                        "expires_in": 900,
                        "endpoint_id": "ep:abc",
                        "permissions": ["peer-connect:initiate"],
                        "protocols": ["isekai-portal-v1"],
                    }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let auth = enrolment("enr1_SECRET").with_assertion("OIDC.JWT");
    let challenge = client
        .refresh_challenge(auth, &key.endpoint_id())
        .await
        .expect("refresh challenge");
    let token = client
        .refresh_token(auth, &key, &challenge, None)
        .await
        .expect("refresh");
    assert_eq!(token.endpoint_token, "TOKEN.2");

    let reqs = captured.take();
    assert_eq!(reqs.len(), 2);

    // The challenge takes the key and **not** the assertion: requiring the
    // evidence twice only widens the window for the OIDC token to expire
    // between the two calls (§8.8.7, settled in ISEKAI-identity#32).
    let (path, headers, body) = &reqs[0];
    assert_eq!(path, "/v1/tokens/endpoint/refresh/challenge");
    assert!(headers.get("authorization").is_none());
    assert_eq!(body["enrollment_key"], "enr1_SECRET");
    assert!(
        body["assertion"].is_null(),
        "one renewal is one minting; asking twice buys nothing",
    );

    // The refresh takes both, and a PoP: §8.8.7 substitutes for the Auth0 half
    // of §17's pair, not for the key-possession half.
    let (path, headers, body) = &reqs[1];
    assert_eq!(path, "/v1/tokens/endpoint/refresh");
    assert!(headers.get("authorization").is_none());
    assert_eq!(body["enrollment_key"], "enr1_SECRET");
    assert_eq!(body["assertion"], "OIDC.JWT");
    assert_eq!(headers.get("x-endpoint-id").unwrap(), &key.endpoint_id());
    let pop = headers.get("x-pop-signature").unwrap().to_str().unwrap();
    der_signature(&json!(pop));
    der_signature(&body["signature"]);

    // Renewal narrows monotonically; asking for the ceiling back is what
    // re-issuing is for, so nothing here requests permissions or protocols.
    assert!(body["requested_permissions"].is_null());
    assert!(body["requested_protocols"].is_null());
}

/// The Auth0 route is unchanged by all of this: header, not body.
#[tokio::test]
async fn renewing_on_auth0_still_uses_the_header() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/tokens/endpoint/refresh/challenge",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/tokens/endpoint/refresh/challenge", h, b).await;
                    Json(challenge_body())
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    client
        .refresh_challenge(IdentityAuth::Auth0("AUTH0_AT"), &key.endpoint_id())
        .await
        .unwrap();

    let reqs = captured.take();
    let (_p, headers, body) = &reqs[0];
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AUTH0_AT");
    assert!(body["enrollment_key"].is_null());
}

// ---- §8.7 ----

#[tokio::test]
async fn self_revocation_sends_no_assertion_and_no_reason() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/{endpoint_id}/revoke",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/revoke", h, b).await;
                    Json(json!({
                        "endpoint_id": "ep:abc",
                        "status": "revoked",
                        "reason": "enrollment_released",
                        "revoked_at": "2026-08-28T01:00:00Z",
                        "proxy_notification": "delivered",
                    }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let revoked = client
        .revoke_endpoint(
            RevokeAuth::Enrollment {
                key: "enr1_SECRET",
                endpoint: &key,
            },
            Some("job 4821 finished"),
        )
        .await
        .expect("self-revoke");
    // Identity names the reason, so that "the job tidied up" stays tellable
    // apart from "the sweep did".
    assert_eq!(revoked.reason.as_deref(), Some("enrollment_released"));

    let reqs = captured.take();
    let (_p, headers, body) = &reqs[0];
    assert!(headers.get("authorization").is_none());
    assert_eq!(body["enrollment_key"], "enr1_SECRET");
    assert_eq!(body["note"], "job 4821 finished");
    assert!(
        body["reason"].is_null(),
        "the key route may not name Identity's own vocabulary",
    );
    assert!(
        body["assertion"].is_null(),
        "binding says who may GET something; revoking gets nothing",
    );
    // Still a PoP: this is what stops a leaked key from stopping anything but
    // the Endpoint whose private key is in hand.
    assert_eq!(headers.get("x-endpoint-id").unwrap(), &key.endpoint_id());
    assert!(headers.get("x-pop-signature").is_some());
}

#[tokio::test]
async fn an_owner_revocation_states_a_reason() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/{endpoint_id}/revoke",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/revoke", h, b).await;
                    Json(json!({ "endpoint_id": "ep:abc", "status": "revoked" }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    client
        .revoke_endpoint(
            RevokeAuth::Auth0 {
                token: "AUTH0_AT",
                // **An id, not a key.** Revoking a lost device is exactly the
                // case where the caller does not hold its private key.
                endpoint_id: "ep:someone-elses",
                reason: RevokeReason::DeviceLost,
            },
            None,
        )
        .await
        .unwrap();

    let reqs = captured.take();
    let (_p, headers, body) = &reqs[0];
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AUTH0_AT");
    assert_eq!(body["reason"], "device_lost");
    assert!(body["enrollment_key"].is_null());
}

// ---- §8.8.2 / §8.8.9 ----

#[tokio::test]
async fn issuing_a_key_states_a_binding_and_carries_no_pop() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/enrollment-keys",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/enrollment-keys", h, b).await;
                    // **The server's names, not the spec's example.** §8.8.2
                    // prints `key`; `enrollment.rs` and `openapi.yaml` both
                    // say `key_plaintext`, and the server answers the call.
                    Json(json!({
                        "key_id": "enk_1",
                        "key_plaintext": "enr1_SECRET",
                        "permissions": ["peer-connect:initiate"],
                        "protocols": ["isekai-portal-v1"],
                        "warnings": ["binding.type is none"],
                    }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let mut request = NewEnrollmentKey::new(Binding::Oidc {
        issuer: "https://token.actions.githubusercontent.com".to_owned(),
        subject: "repo:o/r:ref:refs/heads/main".to_owned(),
    });
    request.protocols = Some(vec!["isekai-portal-v1".to_owned()]);
    request.max_live_endpoints = Some(8);
    request.label = Some("gha-main".to_owned());

    let issued = client
        .create_enrollment_key("AUTH0_AT", &request)
        .await
        .expect("issue");
    assert_eq!(issued.key, "enr1_SECRET");
    // Carried through rather than acted on: warnings are not authorization.
    assert_eq!(issued.warnings.len(), 1);

    let reqs = captured.take();
    let (_p, headers, body) = &reqs[0];
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AUTH0_AT");
    // The caller is a person, so there is no Endpoint key to prove.
    assert!(headers.get("x-pop-signature").is_none());
    assert_eq!(body["binding"]["type"], "oidc");
    assert_eq!(
        body["binding"]["issuer"],
        "https://token.actions.githubusercontent.com"
    );
    // The operator sets this, not the caller: a key naming another service's
    // audience would accept the tokens that service is holding.
    assert!(body["binding"]["audience"].is_null());
    assert_eq!(body["max_live_endpoints"], 8);
    // Untouched knobs are left to the server rather than guessed at.
    assert!(body["ttl"].is_null());
    assert!(body["ephemeral"].is_null());
}

/// `Retry-After` reaches the caller, because the server's number is better
/// than one the caller computes: §8.8.6 adds the sweep interval to it, and a
/// client that works the wait out from the expiry comes back too early.
#[tokio::test]
async fn a_full_key_hands_back_the_wait_it_was_given() {
    async fn exhausted(State(s): State<Captured>, h: HeaderMap, b: Bytes) -> Response {
        record(&s, "/v1/endpoints/enroll/challenge", h, b).await;
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "137")],
            Json(json!({ "type": "enrollment-slots-exhausted" })),
        )
            .into_response()
    }

    let captured = Captured::default();
    let app = Router::new()
        .route("/v1/endpoints/enroll/challenge", post(exhausted))
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let err = client
        .enroll_challenge(enrolment("enr1_S"), &key)
        .await
        .expect_err("a full key is refused");

    assert_eq!(err.status(), Some(429));
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(137)));
}

/// A refusal with no `Retry-After` says so, rather than inventing one.
#[tokio::test]
async fn a_refusal_without_a_wait_reports_none() {
    let app = Router::new().route(
        "/v1/endpoints/enroll/challenge",
        post(|| async {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "type": "enrollment-key-invalid" })),
            )
        }),
    );

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let err = client
        .enroll_challenge(enrolment("enr1_S"), &key)
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(403));
    assert_eq!(err.retry_after(), None);
}

/// The listing route's wrapper is `items`, not `keys`.
///
/// **A shape mismatch here has to be an error, not an empty list.** The field
/// is not defaulted for that reason: a listing that quietly answers "no keys"
/// for an owner who has four is what an operator reads right before issuing a
/// fifth and taking a `429 enrollment-key-quota-exceeded`.
#[tokio::test]
async fn listing_keys_reads_the_wrapper_the_server_sends() {
    let app = Router::new().route(
        "/v1/enrollment-keys",
        axum::routing::get(|| async {
            Json(json!({
                "tenant_id": "org_a",
                "items": [
                    { "key_id": "enk_1", "status": "active", "live_endpoints": 2 },
                    { "key_id": "enk_2", "status": "revoked" },
                ],
            }))
        }),
    );

    let client = serve(app).await;
    let keys = client
        .list_enrollment_keys("AUTH0_AT")
        .await
        .expect("listing parses");
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].key_id, "enk_1");
    assert_eq!(keys[0].live_endpoints, Some(2));
}

/// And a wrapper it does not recognise is refused rather than emptied.
#[tokio::test]
async fn an_unreadable_listing_is_an_error_not_an_empty_one() {
    let app = Router::new().route(
        "/v1/enrollment-keys",
        axum::routing::get(|| async { Json(json!({ "rows": [{ "key_id": "enk_1" }] })) }),
    );

    let client = serve(app).await;
    let err = client.list_enrollment_keys("AUTH0_AT").await.unwrap_err();
    assert!(
        err.to_string().contains("invalid response JSON"),
        "an empty list would read as \"this owner has no keys\": {err}",
    );
}

/// A `sub` or `tenant` binding needs the Auth0 token as well as the key
/// (§8.8.3), on **both** legs of the enrolment.
///
/// Those two types are the attended case — fifty devices deployed at once,
/// without walking each one through a challenge — and the server answers
/// `400 assertion-required` when the header is missing. A client that could
/// only ever send one of the two could issue keys it can never redeem.
#[tokio::test]
async fn a_sub_bound_key_carries_the_auth0_token_too() {
    let captured = Captured::default();
    let app = Router::new()
        .route(
            "/v1/endpoints/enroll/challenge",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll/challenge", h, b).await;
                    Json(challenge_body())
                },
            ),
        )
        .route(
            "/v1/endpoints/enroll",
            post(
                |State(s): State<Captured>, h: HeaderMap, b: Bytes| async move {
                    record(&s, "/v1/endpoints/enroll", h, b).await;
                    Json(json!({ "endpoint_id": "ep:abc", "endpoint_token": "T" }))
                },
            ),
        )
        .with_state(captured.clone());

    let client = serve(app).await;
    let key = EndpointKey::generate();
    let auth = enrolment("enr1_SECRET").with_auth0("AUTH0_AT");
    let challenge = client.enroll_challenge(auth, &key).await.unwrap();
    client
        .enroll(auth, &key, &challenge, None, None)
        .await
        .unwrap();

    for (path, headers, body) in captured.take() {
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer AUTH0_AT",
            "{path} must carry the principal the binding compares against",
        );
        assert_eq!(body["enrollment_key"], "enr1_SECRET", "{path}");
    }
}

/// Revoking a key says whether the cascade reached the proxy.
///
/// A key is revoked because of a leak, and the Endpoints it grew keep their
/// grants at the proxy until it hears. A `200` that does not say so would let
/// the operator believe the door is shut.
#[tokio::test]
async fn revoking_a_key_reports_whether_the_proxy_heard() {
    let app = Router::new().route(
        "/v1/enrollment-keys/{key_id}/revoke",
        post(|| async {
            Json(json!({
                "key_id": "enk_1",
                "status": "revoked",
                "revoked_at": "2026-08-28T11:00:00Z",
                "proxy_notification": "failed",
                "effects": {
                    "revoked_endpoints": ["ep:a"],
                    "remaining_endpoints": [],
                    "newly_revoked": true,
                },
            }))
        }),
    );

    let client = serve(app).await;
    let revoked = client
        .revoke_enrollment_key("AUTH0_AT", "enk_1", Some(true), None)
        .await
        .expect("revoke");
    assert_eq!(revoked.proxy_notification.as_deref(), Some("failed"));
    let effects = revoked.effects.expect("effects");
    assert_eq!(effects.revoked_endpoints, vec!["ep:a"]);
}

/// The spec's `key` spelling still parses, so a server that follows §8.8.2's
/// example rather than its own OpenAPI does not cost anyone a key.
#[tokio::test]
async fn either_spelling_of_the_minted_secret_is_accepted() {
    let app = Router::new().route(
        "/v1/enrollment-keys",
        post(|| async { Json(json!({ "key_id": "enk_1", "key": "enr1_SECRET" })) }),
    );

    let client = serve(app).await;
    let issued = client
        .create_enrollment_key("AUTH0_AT", &NewEnrollmentKey::new(Binding::None))
        .await
        .expect("a key is never worth failing over a field name");
    assert_eq!(issued.key, "enr1_SECRET");
}
