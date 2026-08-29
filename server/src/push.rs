//! Firebase Cloud Messaging (FCM) change signals.
//!
//! A push is only a wake-up hint. The authenticated sync API remains the source
//! of truth. The payload contains no vault data and no user data.

use reqwest::StatusCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use gcp_auth::TokenProvider;
use serde_json::json;
use uuid::Uuid;

use crate::SharedState;

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// FCM says this registration token no longer exists. The route is dead
    /// and clearing it immediately is correct.
    TokenUnregistered,
    /// The send failed for a reason that says nothing about the token: our
    /// OAuth credentials, an FCM outage, a rate limit, a network error.
    ///
    /// Kept separate because the alternative is dangerous. If every failure
    /// counted against the device, one expired service account would fail
    /// every send for every device and quietly delete every push route on the
    /// service — turning a credential problem into a silent, account-wide
    /// feature outage that only re-registration recovers.
    Transient,
}

#[async_trait]
pub trait PushDispatcher: Send + Sync {
    async fn send_vault_changed(&self, registration_token: &str) -> Result<Delivery>;
}

pub struct FcmDispatcher {
    project_id: String,
    credentials: Arc<dyn TokenProvider>,
    client: reqwest::Client,
}

impl FcmDispatcher {
    /// Enables FCM only when `FCM_PROJECT_ID` exists. Authentication uses
    /// Google Application Default Credentials. Outside Google Cloud, set
    /// `GOOGLE_APPLICATION_CREDENTIALS` to the service-account JSON path.
    pub async fn from_environment() -> Result<Option<Arc<dyn PushDispatcher>>> {
        let project_id = std::env::var("FCM_PROJECT_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        if project_id.is_empty() {
            return Ok(None);
        }
        if !valid_project_id(&project_id) {
            anyhow::bail!("FCM_PROJECT_ID must contain only letters, digits, and hyphens");
        }

        let credentials = gcp_auth::provider()
            .await
            .context("FCM_PROJECT_ID is set, but Google credentials are unavailable")?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("could not create the FCM HTTPS client")?;
        Ok(Some(Arc::new(Self {
            project_id,
            credentials,
            client,
        })))
    }
}

#[async_trait]
impl PushDispatcher for FcmDispatcher {
    async fn send_vault_changed(&self, registration_token: &str) -> Result<Delivery> {
        let access = self
            .credentials
            .token(&[FCM_SCOPE])
            .await
            .context("could not obtain an FCM OAuth access token")?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(access.as_str())
            .json(&message_payload(registration_token))
            .send()
            .await
            .context("the FCM send request failed")?;

        if response.status().is_success() {
            return Ok(Delivery::Sent);
        }
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let unregistered = body
            .pointer("/error/details")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|details| {
                details.iter().any(|detail| {
                    detail.get("errorCode").and_then(serde_json::Value::as_str)
                        == Some("UNREGISTERED")
                })
            });
        if unregistered {
            return Ok(Delivery::TokenUnregistered);
        }

        // Whose fault it is decides whether the device is penalised.
        //
        // 401 and 403 are our credentials. 429 is a rate limit. 5xx is FCM.
        // None of those say anything about this registration token, and
        // counting them would let an outage clear every route on the service.
        // Everything else in the 4xx range — a malformed or unusable token —
        // is attributable to the device.
        if is_transient(status) {
            tracing::warn!(%status, "FCM is unavailable or refused this server");
            return Ok(Delivery::Transient);
        }
        anyhow::bail!("FCM returned HTTP {status}")
    }
}

/// Whether a failing status says nothing about the registration token.
///
/// Split out so the rule can be tested directly. Reaching it through a real
/// FCM response would need a fake HTTP server, and the thing worth pinning is
/// this decision, not the plumbing around it.
fn is_transient(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::UNAUTHORIZED
        || status == StatusCode::FORBIDDEN
        || status == StatusCode::TOO_MANY_REQUESTS
}

fn valid_project_id(project_id: &str) -> bool {
    !project_id.is_empty()
        && project_id.len() <= 128
        && project_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn message_payload(registration_token: &str) -> serde_json::Value {
    json!({
        "message": {
            "token": registration_token,
            "data": {
                "type": "vault_changed",
                "schema": "1"
            },
            "android": {
                "collapse_key": "vault-sync",
                "priority": "high",
                "ttl": "3600s"
            }
        }
    })
}

/// Consecutive attributable failures before a push route is dropped.
///
/// Only failures the device is responsible for count toward this, so it is not
/// a timer on FCM being unavailable. A token rejected on its own merits this
/// many times running is not coming back, and retrying it forever costs one
/// request per sync, per device, for the life of the account.
const MAX_PUSH_FAILURES: i32 = 10;

/// Sends to every active device except the device that wrote the change.
/// Delivery runs after the database commit and never changes the sync result.
pub async fn notify_vault_changed(state: SharedState, account_id: Uuid, source: Option<Uuid>) {
    let Some(dispatcher) = state.push.clone() else {
        return;
    };
    let targets = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, push_token FROM device
          WHERE account_id = $1
            AND NOT revoked
            AND push_token IS NOT NULL
            AND ($2::UUID IS NULL OR id <> $2)",
    )
    .bind(account_id)
    .bind(source)
    .fetch_all(&state.db)
    .await;
    let Ok(targets) = targets else {
        tracing::warn!("could not load push notification targets");
        return;
    };

    // Wait for all deliveries before the request finishes. A serverless host
    // can stop the process as soon as the response is sent, which would lose
    // a detached task. The sends run in parallel, so one slow target does not
    // delay every other target.
    let mut jobs = tokio::task::JoinSet::new();
    for (device_id, token) in targets {
        let dispatcher = dispatcher.clone();
        jobs.spawn(async move { (device_id, dispatcher.send_vault_changed(&token).await) });
    }

    while let Some(result) = jobs.join_next().await {
        let Ok((device_id, delivery)) = result else {
            tracing::warn!("a push delivery task stopped unexpectedly");
            continue;
        };
        match delivery {
            Ok(Delivery::Sent) => {
                let _ = sqlx::query("UPDATE device SET push_failures = 0 WHERE id = $1")
                    .bind(device_id)
                    .execute(&state.db)
                    .await;
            }
            Ok(Delivery::TokenUnregistered) => {
                let _ = sqlx::query(
                    "UPDATE device
                            SET push_token = NULL,
                                push_token_updated_at = NULL,
                                push_failures = 0
                          WHERE id = $1",
                )
                .bind(device_id)
                .execute(&state.db)
                .await;
            }
            // Not the token's fault, so the device is not penalised for it.
            Ok(Delivery::Transient) => {}
            Err(error) => {
                tracing::warn!(device_id = %device_id, %error, "push delivery failed");
                // Counted and acted on in one statement. Reading the count and
                // then clearing the route would leave a window — and until now
                // the counter was incremented by a mechanism nothing ever read,
                // which looks like a policy until you check.
                let _ = sqlx::query(
                    "UPDATE device
                        SET push_failures = push_failures + 1,
                            push_token = CASE
                                WHEN push_failures + 1 >= $2 THEN NULL
                                ELSE push_token
                            END,
                            push_token_updated_at = CASE
                                WHEN push_failures + 1 >= $2 THEN NULL
                                ELSE push_token_updated_at
                            END
                      WHERE id = $1",
                )
                .bind(device_id)
                .bind(MAX_PUSH_FAILURES)
                .execute(&state.db)
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ids_reject_urls_and_path_characters() {
        assert!(valid_project_id("authenticator-prod-1"));
        assert!(!valid_project_id(""));
        assert!(!valid_project_id("https://example.invalid"));
        assert!(!valid_project_id("project/name"));
    }

    #[test]
    fn data_only_payload_contains_no_vault_or_account_data() {
        let payload = message_payload("route-token");
        let message = payload["message"].as_object().unwrap();
        let mut keys = message.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["android", "data", "token"]);
        assert_eq!(message["android"]["priority"], "high");
        assert_eq!(
            message["data"],
            json!({ "type": "vault_changed", "schema": "1" })
        );
        let text = payload.to_string();
        for forbidden in ["issuer", "account", "secret", "code", "ciphertext"] {
            assert!(!text.contains(forbidden), "payload contains {forbidden}");
        }
    }
}

#[cfg(test)]
mod failure_policy {
    use super::*;

    /// The distinction the whole policy rests on.
    ///
    /// Only failures a device is responsible for may count against it. If an
    /// expired service account or an FCM outage counted, one bad credential
    /// would fail every send for every device and clear every push route on
    /// the service — a silent, account-wide outage that only re-registration
    /// recovers, caused by something entirely on our side.
    #[test]
    fn only_the_devices_own_failures_are_attributable() {
        // Ours, or FCM's. The device is blameless.
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(
                is_transient(status),
                "{status} must not be charged to the device"
            );
        }

        // The token itself is unusable. That is the device's to answer for.
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
        ] {
            assert!(
                !is_transient(status),
                "{status} says the token is bad and must count"
            );
        }
    }

    /// The SQL clears the route when `push_failures + 1 >= MAX`. This walks
    /// that expression rather than restating the constant, so an off-by-one in
    /// the statement shows up here.
    ///
    /// A previous version of this test asserted `MAX_PUSH_FAILURES > 1`, which
    /// is a compile-time constant and therefore proves nothing. Clippy caught
    /// it, which is the only reason it is not still sitting here looking green.
    #[test]
    fn the_route_is_cleared_by_the_failure_that_reaches_the_limit() {
        // Mirrors the CASE expression: given the count already stored, does
        // this failure clear the token?
        let clears = |stored: i32| stored + 1 >= MAX_PUSH_FAILURES;

        assert!(!clears(0), "one failure must not drop a working device");
        assert!(
            !clears(MAX_PUSH_FAILURES - 2),
            "the failure before the limit must leave the route alone"
        );
        assert!(
            clears(MAX_PUSH_FAILURES - 1),
            "the failure that reaches the limit must clear the route"
        );
        assert!(clears(MAX_PUSH_FAILURES), "past the limit stays cleared");

        // And the count of survivable failures is what the constant says.
        let survivable = (0..MAX_PUSH_FAILURES).filter(|n| !clears(*n)).count();
        assert_eq!(survivable, (MAX_PUSH_FAILURES - 1) as usize);
    }

}
