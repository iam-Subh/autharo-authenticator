//! Temporary storage for end-to-end encrypted account shares.
//!
//! Creation needs an authenticated account. Retrieval uses the random share
//! identifier as a capability. The decryption key is never part of a request.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SharedState;
use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;

const MIN_TTL_SECONDS: i64 = 5 * 60;
const MAX_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024;
const MAX_ACTIVE_SHARES: i64 = 20;
/// Retrievals per address per hour. High enough that a family passing a link
/// around never notices, low enough that the endpoint is not free to hammer.
const RETRIEVALS_PER_ADDRESS_PER_HOUR: i64 = 60;

#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub payload: String,
    pub expires_in_seconds: i64,
    #[serde(default = "default_one_time")]
    pub one_time: bool,
}

fn default_one_time() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct ShareResponse {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

pub async fn create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<CreateShareRequest>,
) -> ApiResult<Json<ShareResponse>> {
    let account_id = authenticate(&state, &headers).await?;
    if request.payload.is_empty() || request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::BadRequest {
            message: format!("A shared payload must be 1 to {MAX_PAYLOAD_BYTES} bytes."),
        });
    }
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.expires_in_seconds) {
        return Err(ApiError::BadRequest {
            message: "A share must expire after 5 minutes to 24 hours.".to_string(),
        });
    }

    let mut transaction = state.db.begin().await?;
    sqlx::query("SELECT id FROM account WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM temporary_share WHERE expires_at <= now()")
        .execute(&mut *transaction)
        .await?;
    let (active,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM temporary_share WHERE account_id = $1 AND expires_at > now()",
    )
    .bind(account_id)
    .fetch_one(&mut *transaction)
    .await?;
    if active >= MAX_ACTIVE_SHARES {
        return Err(ApiError::QuotaExceeded {
            message: format!("An account can have at most {MAX_ACTIVE_SHARES} active shares."),
        });
    }

    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::seconds(request.expires_in_seconds);
    sqlx::query(
        "INSERT INTO temporary_share (id, account_id, payload, one_time, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(account_id)
    .bind(request.payload.as_bytes())
    .bind(request.one_time)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Json(ShareResponse {
        id,
        expires_at,
        payload: None,
    }))
}

/// The only unauthenticated endpoint that returns stored bytes.
///
/// Unauthenticated on purpose: the recipient of a share has no account, which
/// is the whole point. Guessing an identifier is not the concern — they are
/// version-4 UUIDs, so there are 122 random bits to find.
///
/// The concern is that every other endpoint is rate limited and this one was
/// not, which left an unauthenticated, database-touching, transaction-opening
/// call anyone could run as fast as they liked. The limit is per address and
/// generous: a real recipient opens a link once, occasionally twice.
pub async fn retrieve(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ShareResponse>> {
    let address = ratelimit::client_address(&headers, socket);
    ratelimit::record_address_endpoint(
        &state.db,
        "share-retrieve",
        address,
        RETRIEVALS_PER_ADDRESS_PER_HOUR,
    )
    .await?;

    let mut transaction = state.db.begin().await?;
    let row: Option<(Vec<u8>, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT payload, expires_at, one_time
         FROM temporary_share WHERE id = $1 AND expires_at > now() FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((payload, expires_at, one_time)) = row else {
        return Err(ApiError::NotFound {
            message: "This share does not exist or has expired.".to_string(),
        });
    };
    if one_time {
        sqlx::query("DELETE FROM temporary_share WHERE id = $1")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    let payload = String::from_utf8(payload)
        .map_err(|_| ApiError::Other(anyhow::anyhow!("stored share payload is not valid UTF-8")))?;
    Ok(Json(ShareResponse {
        id,
        expires_at,
        payload: Some(payload),
    }))
}

pub async fn revoke(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<axum::http::StatusCode> {
    let account_id = authenticate(&state, &headers).await?;
    let deleted = sqlx::query("DELETE FROM temporary_share WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(&state.db)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound {
            message: "This share does not exist or has expired.".to_string(),
        });
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn authenticate(state: &SharedState, headers: &HeaderMap) -> ApiResult<Uuid> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    auth::account_for_token(&state.db, token).await
}
