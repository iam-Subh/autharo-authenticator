//! Devices, sign-out, and account deletion (PRD section 9.5).
//!
//! # The question this module exists to answer
//!
//! "I lost my phone."
//!
//! Until now the honest answer was that nothing could be done. The vault on
//! that phone is encrypted, and the key is in a hardware keystore behind a
//! screen lock, so it is not an emergency — but the device still holds a
//! refresh token good for thirty days, and every change made anywhere else
//! keeps syncing to it. A user who cannot cut that off is being asked to trust
//! a lock they cannot change.
//!
//! # Revoking has to bite immediately
//!
//! A revoked device that keeps working for fifteen minutes is a revoke that
//! does not work, because the fifteen minutes are exactly when it matters. So
//! revoking marks the device *and* kills its sessions in one statement, and
//! [`crate::auth::session_for_token_with_scope`] joins to the device so a session that
//! somehow survived still cannot be used.
//!
//! # Deletion is real deletion
//!
//! Not a flag, not a grace period, not a queue. `ON DELETE CASCADE` runs from
//! `account` through key slots, records, sync state, devices, and sessions, and
//! what comes back is a row count the caller can check.
//!
//! There is no soft delete because there is nothing to restore *to*. The server
//! cannot decrypt a record, so a "recoverable" account would be an encrypted
//! blob whose key the user has already been told to destroy — kept only to be
//! stolen later. Section 16.4 is explicit that the server cannot help recover a
//! vault, and keeping the ciphertext around after someone asked for it to go
//! would be the worst of both positions.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::SharedState;
use crate::activity;
use crate::auth;
use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;

const APPROVAL_TTL_MINUTES: i64 = 10;

/// One device on the account, as the "your devices" screen shows it.
///
/// Deliberately thin. This is a list a user reads to decide what to remove, and
/// every field beyond that is one more thing the server is keeping about them.
#[derive(Debug, Serialize)]
pub struct DeviceView {
    pub id: Uuid,
    pub name: String,
    pub platform: String,
    pub last_seen: Option<DateTime<Utc>>,
    /// True for the device making the request, so the screen can say "this
    /// device" rather than letting someone revoke the phone in their hand and
    /// wonder why they were signed out.
    pub current: bool,
    pub revoked: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceView>,
}

const MAX_PUSH_TOKEN_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct PushTokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct PushTokenResponse {
    pub registered: bool,
}

/// Associates an FCM routing token with only the current authenticated device.
/// The token is never returned by any API.
pub async fn set_push_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<PushTokenRequest>,
) -> ApiResult<Json<PushTokenResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SESSION_SELF).await?;
    let device_id = session.device_id.ok_or(ApiError::Unauthorized)?;
    let token = request.token.trim();
    if token.is_empty()
        || token.len() > MAX_PUSH_TOKEN_BYTES
        || token.chars().any(char::is_whitespace)
    {
        return Err(ApiError::BadRequest {
            message: "The push registration token is invalid.".to_string(),
        });
    }

    let mut transaction = state.db.begin().await?;
    // FCM can reuse an installation token after an account is replaced on the
    // same application installation. Keep one owner and do not deliver a
    // signal for the old account to the new session.
    sqlx::query(
        "UPDATE device
            SET push_token = NULL,
                push_token_updated_at = NULL,
                push_failures = 0
          WHERE push_token = $1 AND id <> $2",
    )
    .bind(token)
    .bind(device_id)
    .execute(&mut *transaction)
    .await?;
    let changed = sqlx::query(
        "UPDATE device
            SET push_token = $1,
                push_token_updated_at = now(),
                push_failures = 0
          WHERE id = $2 AND account_id = $3 AND NOT revoked",
    )
    .bind(token)
    .bind(device_id)
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Unauthorized);
    }
    transaction.commit().await?;
    Ok(Json(PushTokenResponse { registered: true }))
}

pub async fn clear_push_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<PushTokenResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SESSION_SELF).await?;
    let device_id = session.device_id.ok_or(ApiError::Unauthorized)?;
    sqlx::query(
        "UPDATE device
            SET push_token = NULL,
                push_token_updated_at = NULL,
                push_failures = 0
          WHERE id = $1 AND account_id = $2",
    )
    .bind(device_id)
    .bind(session.account_id)
    .execute(&state.db)
    .await?;
    Ok(Json(PushTokenResponse { registered: false }))
}

/// Section 9.5: every device that has signed in to this account.
///
/// Revoked devices are included rather than hidden. A user checking whether the
/// phone they lost is really cut off needs to see it listed as cut off; a list
/// that simply no longer mentions it is indistinguishable from a list that
/// forgot.
pub async fn list_devices(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<DeviceListResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;

    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<DateTime<Utc>>, bool)>(
        "SELECT id, name, platform, last_seen, revoked
           FROM device
          WHERE account_id = $1
          ORDER BY revoked ASC, last_seen DESC NULLS LAST",
    )
    .bind(session.account_id)
    .fetch_all(&state.db)
    .await?;

    let devices = rows
        .into_iter()
        .map(|(id, name, platform, last_seen, revoked)| DeviceView {
            current: Some(id) == session.device_id,
            id,
            name,
            platform,
            last_seen,
            revoked,
        })
        .collect();

    Ok(Json(DeviceListResponse { devices }))
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    /// Sessions killed. Zero is a normal answer — a device that had already
    /// been signed out has none — so this is reported rather than treated as a
    /// failure.
    pub sessions_ended: u64,
}

/// Section 9.5: cuts one device off.
///
/// The device row is kept, marked revoked. Deleting it would take the row that
/// `session.device_id` points at, and more importantly it would remove the
/// evidence — a user wants to see that the lost phone is dealt with, not to
/// find it gone from a list where its absence proves nothing.
///
/// Revoking the device you are using is permitted. It is a strange thing to do
/// by accident and a reasonable thing to do on purpose (a phone about to be
/// sold), and refusing would mean guessing at the user's intent from the one
/// piece of information least likely to be a mistake.
pub async fn revoke_device(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
    request: Option<Json<StepUpRequest>>,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    let Json(request) = request.ok_or_else(|| ApiError::BadRequest {
        message: "The account password is required.".to_string(),
    })?;
    auth::verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;
    let mut transaction = state.db.begin().await?;

    // Scoped to the account in the statement itself, not checked first and
    // acted on second. A separate check leaves a window, and worse, it makes
    // "not yours" and "does not exist" distinguishable — which turns this into
    // an oracle for whether a device id is real.
    let marked = sqlx::query(
        "UPDATE device
            SET revoked = TRUE,
                push_token = NULL,
                push_token_updated_at = NULL,
                push_failures = 0
          WHERE id = $1 AND account_id = $2",
    )
    .bind(device_id)
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    if marked == 0 {
        return Err(ApiError::NotFound {
            message: "That device is not on this account.".to_string(),
        });
    }

    // In the same request, not on a schedule. A revoked device whose access
    // token keeps working for another fifteen minutes has not been revoked —
    // and those fifteen minutes are the whole reason someone pressed the
    // button.
    let sessions_ended = sqlx::query(
        "UPDATE session SET revoked = TRUE
          WHERE device_id = $1 AND account_id = $2 AND NOT revoked",
    )
    .bind(device_id)
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    activity::record_in_transaction(
        &mut transaction,
        session.account_id,
        session.device_id,
        "device_revoked",
        serde_json::json!({ "revoked_device_id": device_id }),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(RevokeResponse { sessions_ended }))
}

/// Section 9.5: signs every device out, including this one.
///
/// The blunt instrument, for the case where a user does not know which device
/// is the problem. Devices are also revoked. A later sign-in needs an approval
/// code or the recovery phrase, so the password alone cannot restore access.
pub async fn sign_out_everywhere(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Option<Json<StepUpRequest>>,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    let Json(request) = request.ok_or_else(|| ApiError::BadRequest {
        message: "The account password is required.".to_string(),
    })?;
    auth::verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;
    let mut transaction = state.db.begin().await?;

    let sessions_ended =
        sqlx::query("UPDATE session SET revoked = TRUE WHERE account_id = $1 AND NOT revoked")
            .bind(session.account_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();

    sqlx::query(
        "UPDATE device
            SET revoked = TRUE,
                push_token = NULL,
                push_token_updated_at = NULL,
                push_failures = 0
          WHERE account_id = $1 AND NOT revoked",
    )
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?;
    activity::record_in_transaction(
        &mut transaction,
        session.account_id,
        session.device_id,
        "signed_out_everywhere",
        serde_json::json!({ "sessions_ended": sessions_ended }),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(RevokeResponse { sessions_ended }))
}

/// Ends the calling session only. The ordinary "sign out" button.
pub async fn sign_out(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SESSION_SELF).await?;
    let mut transaction = state.db.begin().await?;

    let sessions_ended = sqlx::query("UPDATE session SET revoked = TRUE WHERE id = $1")
        .bind(session.session_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();

    if let Some(device_id) = session.device_id {
        sqlx::query(
            "UPDATE device
                SET revoked = TRUE,
                    push_token = NULL,
                    push_token_updated_at = NULL,
                    push_failures = 0
              WHERE id = $1 AND account_id = $2",
        )
        .bind(device_id)
        .bind(session.account_id)
        .execute(&mut *transaction)
        .await?;
    }
    activity::record_in_transaction(
        &mut transaction,
        session.account_id,
        session.device_id,
        "signed_out",
        serde_json::json!({}),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(RevokeResponse { sessions_ended }))
}

#[derive(Debug, Deserialize)]
pub struct StepUpRequest {
    /// The authentication key, derived from the password exactly as at login.
    ///
    /// Re-authentication rather than a confirmation dialog, because a stolen
    /// access token is precisely the situation where the other endpoints here
    /// matter — and an attacker holding one must not be able to destroy the
    /// account the user is trying to save.
    pub auth_key: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountResponse {
    /// Encrypted records destroyed. Reported so a client can show the user what
    /// went, rather than a bare success on the most irreversible action the
    /// product has.
    pub records_deleted: i64,
}

/// Section 9.5: deletes the account and everything under it.
///
/// Irreversible, immediate, and complete. See the module documentation for why
/// there is no soft delete.
pub async fn delete_account(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<StepUpRequest>,
) -> ApiResult<Json<DeleteAccountResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    auth::verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;

    // Counted before the delete, because afterwards there is nothing to count.
    let (records_deleted,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM record WHERE account_id = $1")
            .bind(session.account_id)
            .fetch_one(&state.db)
            .await?;

    // One statement. Key slots, records, sync state, devices and sessions all
    // cascade from here, so there is no order to get wrong and no partial
    // state to be left in if the connection drops.
    let removed = sqlx::query("DELETE FROM account WHERE id = $1")
        .bind(session.account_id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if removed == 0 {
        // Two requests raced and the other won. The user's intent was carried
        // out either way, so this is not an error to report to them.
        return Ok(Json(DeleteAccountResponse { records_deleted: 0 }));
    }

    Ok(Json(DeleteAccountResponse { records_deleted }))
}

/// The caller's session, not just their account.
///
/// Every endpoint here acts on sessions and devices, so knowing *which* session
/// is asking is the whole job — "sign out" and "sign out everywhere" differ by
/// exactly this.
pub async fn create_device_approval(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<StepUpRequest>,
) -> ApiResult<Json<DeviceApprovalResponse>> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    auth::verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;
    let creator = session.device_id.ok_or(ApiError::Unauthorized)?;
    let token = crypto::random_token();
    let expires_at = Utc::now() + chrono::Duration::minutes(APPROVAL_TTL_MINUTES);
    let mut transaction = state.db.begin().await?;

    sqlx::query(
        "DELETE FROM device_approval
          WHERE account_id = $1",
    )
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO device_approval
           (id, account_id, created_by_device_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(session.account_id)
    .bind(creator)
    .bind(auth::token_hash(&token))
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    activity::record_in_transaction(
        &mut transaction,
        session.account_id,
        Some(creator),
        "device_approval_created",
        serde_json::json!({ "expires_at": expires_at }),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(DeviceApprovalResponse { token, expires_at }))
}

#[derive(Debug, Serialize)]
pub struct DeviceApprovalResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EnrollRecoveryRequest {
    pub auth_key: String,
    pub recovery_auth_key: String,
    pub recovery_slot: auth::WrappedSlot,
}

pub async fn enroll_recovery_access(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<EnrollRecoveryRequest>,
) -> ApiResult<StatusCode> {
    let session = authenticate(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    auth::verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;
    let recovery_auth_key =
        crypto::b64_decode(&request.recovery_auth_key).map_err(|_| ApiError::BadRequest {
            message: "recovery_auth_key is not valid base64url.".to_string(),
        })?;
    if recovery_auth_key.len() != 32 {
        return Err(ApiError::BadRequest {
            message: "The recovery authentication key must be 256 bits.".to_string(),
        });
    }
    let recovery_slot = auth::decode_slot(&request.recovery_slot, "recovery_slot")?;
    auth::validate_slot(&recovery_slot, "recovery_slot")?;
    let recovery_hash = auth::hash_auth_key_limited(recovery_auth_key).await?;
    let mut transaction = state.db.begin().await?;
    let changed = sqlx::query(
        "UPDATE key_slot
            SET auth_hash = $1, wrapped_key = $2, wrap_nonce = $3, last_used = now()
          WHERE account_id = $4 AND type = 'recovery'",
    )
    .bind(recovery_hash)
    .bind(&recovery_slot.0)
    .bind(&recovery_slot.1)
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::BadRequest {
            message: "This account has no recovery slot.".to_string(),
        });
    }
    activity::record_in_transaction(
        &mut transaction,
        session.account_id,
        session.device_id,
        "recovery_access_enrolled",
        serde_json::json!({}),
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate(
    state: &SharedState,
    headers: &HeaderMap,
    scope: &str,
) -> ApiResult<auth::Session> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    auth::session_for_token_with_scope(&state.db, token, scope).await
}
