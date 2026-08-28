//! The Provisioning Key routes (spec §8.13) against a mock proxy.
//!
//! **The field names are taken from the proxy's own handlers**, not from the
//! spec's examples — phase 1 shipped two types written the other way round and
//! the mocks agreed with them, so the tests said nothing. Where the two servers
//! differ, that difference is asserted here rather than assumed away:
//!
//! | | Identity (§8.8) | proxy (§8.13) |
//! | --- | --- | --- |
//! | minted secret | `key_plaintext` | **`key`** |
//! | listing wrapper | `items` | **`keys`** |
//!
//! They are different servers with different specs, and Identity's §8.8.2 says
//! why it does not follow this one.

use std::sync::{Arc, Mutex};

use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::proxy::{
    ControlPlaneTransport, HttpResponse, ProvisioningBinding, ProxyClient, ProxyError,
};
use serde_json::{Value, json};

/// A captured request: (method, path, body).
type Call = (String, String, Value);

#[derive(Default)]
struct Inner {
    calls: Mutex<Vec<Call>>,
    response: Mutex<Option<HttpResponse>>,
}

/// Cloneable so the test can keep a handle while the client owns one; a
/// newtype rather than a bare `Arc` because the orphan rule wants a local type.
#[derive(Clone, Default)]
struct MockProxy(Arc<Inner>);

impl MockProxy {
    fn with(response: HttpResponse) -> Self {
        let mock = MockProxy::default();
        *mock.0.response.lock().unwrap() = Some(response);
        mock
    }

    fn answering(status: u16, body: Value) -> Self {
        MockProxy::with(HttpResponse {
            status,
            body: serde_json::to_vec(&body).unwrap(),
            headers: Vec::new(),
        })
    }

    fn refusing(status: u16, kind: &str, retry_after: Option<&str>) -> Self {
        MockProxy::with(HttpResponse {
            status,
            // `status` is required by `Problem` and the proxy really does send
            // it (`ProblemBody`), so a fixture without it would test the
            // parser's tolerance rather than this route.
            body: serde_json::to_vec(&json!({
                "type": format!("https://proxy.test/problems/{kind}"),
                "title": kind,
                "status": status,
            }))
            .unwrap(),
            headers: retry_after
                .map(|v| vec![("retry-after".to_owned(), v.to_owned())])
                .unwrap_or_default(),
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.0.calls.lock().unwrap().clone()
    }
}

impl ControlPlaneTransport for MockProxy {
    async fn send(
        &self,
        method: &str,
        path: &str,
        _headers: &[(String, String)],
        body: Vec<u8>,
    ) -> anyhow::Result<HttpResponse> {
        let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        self.0
            .calls
            .lock()
            .unwrap()
            .push((method.to_owned(), path.to_owned(), parsed));
        Ok(self
            .0
            .response
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(HttpResponse {
                status: 500,
                ..HttpResponse::default()
            }))
    }
}

fn client(mock: MockProxy) -> ProxyClient<MockProxy> {
    ProxyClient::new(mock, EndpointKey::generate(), "ENDPOINT.TOKEN")
}

// ---- §8.13.3 ----

#[tokio::test]
async fn issuing_a_key_sends_the_binding_and_reads_back_the_secret() {
    let mock = MockProxy::answering(
        201,
        json!({
            "key_id": "pvk_AbC12345",
            // **`key`, not `key_plaintext`** — the proxy's name for it.
            "key": "pvk1_9dQ2mR7xK0",
            "owner_endpoint": "ep:B",
            "protocol": "isekai-portal-v1",
            "grant_ttl": 1800,
            "max_live_grants": 8,
            "live_grants": 0,
            "redemption_count": 0,
            "binding": {
                "type": "oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:o/r:ref:refs/heads/main",
                "audience": "isekai-proxy",
            },
            "label": "gha-main",
            "created_at": "2026-08-28T08:30:00Z",
            "expires_at": "2026-09-27T08:30:00Z",
        }),
    );
    let issued = client(mock.clone())
        .create_provisioning_key(
            "isekai-portal-v1",
            None,
            Some(1800),
            Some(8),
            Some(&ProvisioningBinding::Oidc {
                issuer: "https://token.actions.githubusercontent.com".to_owned(),
                subject: "repo:o/r:ref:refs/heads/main".to_owned(),
            }),
            Some("gha-main"),
        )
        .await
        .expect("issue");

    assert_eq!(issued.key, "pvk1_9dQ2mR7xK0");
    assert_eq!(issued.key_id.as_deref(), Some("pvk_AbC12345"));
    // The audience the operator configured, echoed so CI knows what to mint.
    assert_eq!(issued.binding.as_ref().unwrap()["audience"], "isekai-proxy");

    let (method, path, body) = &mock.calls()[0];
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("POST", "/v1/peer/provisioning-keys")
    );
    assert_eq!(body["protocol"], "isekai-portal-v1");
    assert_eq!(body["binding"]["type"], "oidc");
    assert_eq!(body["grant_ttl"], 1800);
    assert_eq!(body["max_live_grants"], 8);
    // Untouched knobs are left to the server rather than guessed at.
    assert!(body["ttl"].is_null());
    // Never the caller's to name.
    assert!(body["binding"]["audience"].is_null());
}

/// A response that lost everything but the secret still hands it back.
///
/// There is no second chance at it: the key is minted, counted against a quota
/// of four, and never shown again.
#[tokio::test]
async fn a_minimal_issue_response_still_yields_the_key() {
    let mock = MockProxy::answering(201, json!({ "key": "pvk1_SECRET" }));
    let issued = client(mock)
        .create_provisioning_key("isekai-portal-v1", None, None, None, None, None)
        .await
        .expect("a lost field is not worth losing a key over");
    assert_eq!(issued.key, "pvk1_SECRET");
    assert_eq!(issued.key_id, None);
}

// ---- §8.13.7 ----

#[tokio::test]
async fn listing_keys_reads_the_wrapper_the_proxy_sends() {
    let mock = MockProxy::answering(
        200,
        json!({
            // `keys` here; Identity calls the same idea `items`.
            "keys": [
                { "key_id": "pvk_1", "live_grants": 3, "max_live_grants": 8 },
                { "key_id": "pvk_2", "live_grants": 0, "max_live_grants": 4 },
            ]
        }),
    );
    let keys = client(mock)
        .list_provisioning_keys()
        .await
        .expect("listing");
    assert_eq!(keys.len(), 2);
    // The pair that says whether a key is turning jobs away.
    assert_eq!(keys[0].live_grants, Some(3));
    assert_eq!(keys[0].max_live_grants, Some(8));
}

/// A wrapper this cannot read is an error, never an empty list.
///
/// An empty one reads as "this Endpoint has no keys", which is what somebody
/// sees just before issuing past the quota of four.
#[tokio::test]
async fn an_unreadable_key_listing_is_refused() {
    let mock = MockProxy::answering(200, json!({ "items": [{ "key_id": "pvk_1" }] }));
    let err = client(mock).list_provisioning_keys().await.unwrap_err();
    assert!(matches!(err, ProxyError::Decode(_)), "{err}");
}

#[tokio::test]
async fn redemptions_count_visits_rather_than_rows() {
    let mock = MockProxy::answering(
        200,
        json!({
            "redemptions": [{
                "endpoint_id": "ep:A",
                "grant_id": "gr_AbC12345",
                "binding_subject": "repo:o/r:ref:refs/heads/main",
                "first_redeemed_at": "2026-08-28T08:32:00Z",
                "redeemed_at": "2026-08-28T14:05:00Z",
                "redeem_count": 37,
            }]
        }),
    );
    let rows = client(mock.clone())
        .provisioning_redemptions("pvk_AbC12345")
        .await
        .expect("redemptions");

    assert_eq!(rows.len(), 1);
    // One row, thirty-seven visits: the row is unique per (key, endpoint) and
    // re-redemption updates it, so counting rows would answer a different
    // question.
    assert_eq!(rows[0].redeem_count, Some(37));
    assert_eq!(
        rows[0].binding_subject.as_deref(),
        Some("repo:o/r:ref:refs/heads/main"),
    );

    let (method, path, _) = &mock.calls()[0];
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("GET", "/v1/peer/provisioning-keys/pvk_AbC12345/redemptions"),
    );
}

#[tokio::test]
async fn revoking_a_key_is_a_delete() {
    let mock = MockProxy::with(HttpResponse {
        status: 204,
        ..HttpResponse::default()
    });
    client(mock.clone())
        .revoke_provisioning_key("pvk_AbC12345")
        .await
        .expect("revoke");
    let (method, path, _) = &mock.calls()[0];
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("DELETE", "/v1/peer/provisioning-keys/pvk_AbC12345"),
    );
}

// ---- §8.13.5 ----

#[tokio::test]
async fn redeeming_answers_in_a_ticket_redemption_shape() {
    let mock = MockProxy::answering(
        201,
        json!({
            "grant": {
                "grant_id": "gr_AbC12345",
                "owner_endpoint": "ep:B",
                "allowed_endpoint": "ep:A",
                "protocol": "isekai-portal-v1",
                "origin": "provisioning",
                "provisioning_key_id": "pvk_AbC12345",
                "label": "gha-run-4821",
                "created_at": "2026-08-28T08:32:00Z",
                "expires_at": "2026-08-28T09:02:00Z",
            },
            "listeners": [{
                "listener_id": "pl_1",
                "protocol": "isekai-portal-v1",
                "owner_endpoint": "ep:B",
            }],
        }),
    );
    let redeemed = client(mock.clone())
        .redeem_provisioning_key("pvk1_SECRET", Some("OIDC.JWT"), Some("gha-run-4821"))
        .await
        .expect("redeem");

    assert_eq!(redeemed.grant.owner_endpoint, "ep:B");
    assert_eq!(redeemed.grant.origin.as_deref(), Some("provisioning"));
    // Which key opened this door — needed for §8.13.7's cascade, and the answer
    // to "which key let this in" when reading a grant list.
    assert_eq!(
        redeemed.grant.provisioning_key_id.as_deref(),
        Some("pvk_AbC12345"),
    );
    assert_eq!(redeemed.listeners.len(), 1);

    let (method, path, body) = &mock.calls()[0];
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("POST", "/v1/peer/provisioning-keys/redeem"),
    );
    assert_eq!(body["key"], "pvk1_SECRET");
    assert_eq!(body["assertion"], "OIDC.JWT");
    assert_eq!(body["label"], "gha-run-4821");
}

/// Re-redemption answers `200` rather than `201`, and both are successes.
///
/// This is the reverse of a Ticket, and `grant_ttl`'s narrow ceiling assumes
/// it: a job longer than half an hour keeps its authorization by coming back.
#[tokio::test]
async fn a_second_redemption_is_not_a_failure() {
    let mock = MockProxy::answering(
        200,
        json!({
            "grant": {
                "grant_id": "gr_AbC12345",
                "owner_endpoint": "ep:B",
                "origin": "provisioning",
                "expires_at": "2026-08-28T10:02:00Z",
            },
            "listeners": [],
        }),
    );
    let redeemed = client(mock)
        .redeem_provisioning_key("pvk1_SECRET", None, None)
        .await
        .expect("200 is a success");
    assert_eq!(redeemed.grant.grant_id, "gr_AbC12345");
    // Empty is not a failure either: the authorization exists, the far side
    // just has nothing listening yet.
    assert!(redeemed.listeners.is_empty());
}

// ---- §8.13.6 ----

/// **`provisioning-binding-invalid` must not be folded into the uniform
/// refusal.** Presenting a 256-bit secret is not guesswork, so this answer says
/// the key is real and the CI is misconfigured — a wrong branch, a wrong
/// repository, a missing audience. Collapsing it would leave an operator unable
/// to tell a leak from a typo.
#[tokio::test]
async fn a_misconfigured_binding_is_distinguishable_from_a_bad_key() {
    let mock = MockProxy::refusing(403, "provisioning-binding-invalid", None);
    let err = client(mock)
        .redeem_provisioning_key("pvk1_SECRET", Some("OIDC.JWT"), None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), Some("provisioning-binding-invalid"));

    let mock = MockProxy::refusing(403, "provisioning-key-invalid", None);
    let err = client(mock)
        .redeem_provisioning_key("pvk1_SECRET", None, None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), Some("provisioning-key-invalid"));
}

/// A full key and an unreachable issuer both hand back the wait they were
/// given — neither is derivable from anything the caller holds.
#[tokio::test]
async fn a_wait_the_proxy_asked_for_reaches_the_caller() {
    for (status, kind) in [
        (429, "provisioning-slots-exhausted"),
        (503, "provisioning-unavailable"),
    ] {
        let mock = MockProxy::refusing(status, kind, Some("42"));
        let err = client(mock)
            .redeem_provisioning_key("pvk1_SECRET", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(kind));
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(42)));
    }
}

#[tokio::test]
async fn a_refusal_without_a_wait_reports_none() {
    let mock = MockProxy::refusing(403, "provisioning-key-invalid", None);
    let err = client(mock)
        .redeem_provisioning_key("pvk1_SECRET", None, None)
        .await
        .unwrap_err();
    assert_eq!(err.retry_after(), None);
}
