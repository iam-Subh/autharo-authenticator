//! Security events that an account owner can inspect.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::SharedState;
use crate::auth;
use crate::error::{ApiError, ApiResult};

pub const MAX_EVENTS: i64 = 100;
const MAX_STORED_EVENTS: i64 = 1_000;

#[derive(Debug, Serialize)]
pub struct SecurityEventView {
    pub id: i64,
    pub event_type: String,
    pub created_at: DateTime<Utc>,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub detail: Value,
}

#[derive(Debug, Serialize)]
pub struct SecurityActivityResponse {
    pub events: Vec<SecurityEventView>,
}

pub async fn record_in_transaction(
    transaction: &mut PgConnection,
    account_id: Uuid,
    device_id: Option<Uuid>,
    event_type: &str,
    detail: Value,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO security_event (account_id, device_id, event_type, detail)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(device_id)
    .bind(event_type)
    .bind(detail)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM security_event
          WHERE account_id = $1
            AND id IN (
                SELECT id FROM security_event
                 WHERE account_id = $1
                 ORDER BY created_at DESC, id DESC
                 OFFSET $2
            )",
    )
    .bind(account_id)
    .bind(MAX_STORED_EVENTS)
    .execute(&mut *transaction)
    .await?;
    Ok(())
}

pub async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<SecurityActivityResponse>> {
    let token = bearer(&headers)?;
    let session =
        auth::session_for_token_with_scope(&state.db, token, auth::SCOPE_SECURITY_READ).await?;

    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            DateTime<Utc>,
            Option<Uuid>,
            Option<String>,
            Value,
        ),
    >(
        "SELECT e.id, e.event_type, e.created_at, e.device_id, d.name, e.detail
           FROM security_event e
           LEFT JOIN device d ON d.id = e.device_id
          WHERE e.account_id = $1
          ORDER BY e.created_at DESC, e.id DESC
          LIMIT $2",
    )
    .bind(session.account_id)
    .bind(MAX_EVENTS)
    .fetch_all(&state.db)
    .await?;

    let events = rows
        .into_iter()
        .map(
            |(id, event_type, created_at, device_id, device_name, detail)| SecurityEventView {
                id,
                event_type,
                created_at,
                device_id,
                device_name,
                detail,
            },
        )
        .collect();

    Ok(Json(SecurityActivityResponse { events }))
}

fn bearer(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)
}
