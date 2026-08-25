//! Firebase Cloud Messaging (FCM) change signals.
//!
//! A push is only a wake-up hint. The authenticated sync API remains the source
//! of truth. The payload contains no vault data and no user data.

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
    TokenUnregistered,
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
        anyhow::bail!("FCM returned HTTP {status}")
    }
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
            "notification": {
                "title": "Authenticator update available",
                "body": "Open Authenticator to synchronize your encrypted vault."
            },
            "android": {
                "collapse_key": "vault-sync",
                "priority": "normal",
                "ttl": "3600s"
            }
        }
    })
}

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
            Err(error) => {
                tracing::warn!(device_id = %device_id, %error, "push delivery failed");
                let _ = sqlx::query(
                    "UPDATE device
                            SET push_failures = push_failures + 1
                          WHERE id = $1",
                )
                .bind(device_id)
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
    fn notification_payload_contains_no_vault_or_account_data() {
        let payload = message_payload("route-token");
        let message = payload["message"].as_object().unwrap();
        let mut keys = message.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["android", "data", "notification", "token"]);
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
