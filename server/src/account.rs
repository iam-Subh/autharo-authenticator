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
//! [`crate::auth::account_for_token`] joins to the device so a session that
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
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SharedState;
use crate::auth;
use crate::crypto;
use crate::error::{ApiError, ApiResult};

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
    let session = authenticate(&state, &headers).await?;

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
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers).await?;

    // Scoped to the account in the statement itself, not checked first and
    // acted on second. A separate check leaves a window, and worse, it makes
    // "not yours" and "does not exist" distinguishable — which turns this into
    // an oracle for whether a device id is real.
    let marked = sqlx::query("UPDATE device SET revoked = TRUE WHERE id = $1 AND account_id = $2")
        .bind(device_id)
        .bind(session.account_id)
        .execute(&state.db)
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
    .execute(&state.db)
    .await?
    .rows_affected();

    Ok(Json(RevokeResponse { sessions_ended }))
}

/// Section 9.5: signs every device out, including this one.
///
/// The blunt instrument, for the case where a user does not know which device
/// is the problem. Devices are left unrevoked — they can sign in again with the
/// password, which is the point: this is for "I think someone has a token",
/// where the answer is to invalidate every token and let the legitimate devices
/// come back.
pub async fn sign_out_everywhere(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers).await?;

    let sessions_ended =
        sqlx::query("UPDATE session SET revoked = TRUE WHERE account_id = $1 AND NOT revoked")
            .bind(session.account_id)
            .execute(&state.db)
            .await?
            .rows_affected();

    Ok(Json(RevokeResponse { sessions_ended }))
}

/// Ends the calling session only. The ordinary "sign out" button.
pub async fn sign_out(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<RevokeResponse>> {
    let session = authenticate(&state, &headers).await?;

    let sessions_ended = sqlx::query("UPDATE session SET revoked = TRUE WHERE id = $1")
        .bind(session.session_id)
        .execute(&state.db)
        .await?
        .rows_affected();

    Ok(Json(RevokeResponse { sessions_ended }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
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
    headers: HeaderMap,
    Json(request): Json<DeleteAccountRequest>,
) -> ApiResult<Json<DeleteAccountResponse>> {
    let session = authenticate(&state, &headers).await?;

    let auth_key = crypto::b64_decode(&request.auth_key).map_err(|_| ApiError::BadRequest {
        message: "auth_key is not valid base64url.".to_string(),
    })?;
    if auth_key.len() != 32 {
        return Err(ApiError::InvalidCredentials);
    }

    let stored = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT auth_hash FROM key_slot WHERE account_id = $1 AND type = 'password'",
    )
    .bind(session.account_id)
    .fetch_optional(&state.db)
    .await?;

    // An account with no password slot — a passkey-only account, once S7
    // exists — cannot be deleted through this route. Refused explicitly rather
    // than falling through to a comparison against nothing, which would delete
    // on any input.
    let Some((Some(auth_hash),)) = stored else {
        return Err(ApiError::BadRequest {
            message: "This account has no password set, so it cannot be deleted this way."
                .to_string(),
        });
    };

    if !auth::verify_auth_key_limited(auth_key, auth_hash).await? {
        return Err(ApiError::InvalidCredentials);
    }

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
async fn authenticate(state: &SharedState, headers: &HeaderMap) -> ApiResult<auth::Session> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    auth::session_for_token(&state.db, token).await
}
