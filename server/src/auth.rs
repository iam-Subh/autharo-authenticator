//! Sign-up and password sign-in (PRD sections 9.2.1, 9.5, 13).

use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::quota;
use crate::{AppState, SharedState};

/// Section 13: an access token lasts 15 minutes, a refresh token 30 days.
const ACCESS_TTL_MINUTES: i64 = 15;
const REFRESH_TTL_DAYS: i64 = 30;

/// The floor every `prelogin` response is padded to.
///
/// Section 9.5: "Match the response time of the real path." The real path does
/// a lookup and returns stored values; the fake path does the same lookup,
/// finds nothing, and computes an HMAC. Those are not the same cost, and the
/// difference is measurable over enough requests.
///
/// Padding to a fixed floor removes the difference rather than trying to
/// balance it. The floor is above the slowest of the two branches, so the
/// observable time is the floor in both cases and carries no information.
/// Chosen well above a local database round trip; raise it if a deployment's
/// database is slower.
const PRELOGIN_FLOOR: Duration = Duration::from_millis(120);

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// One wrapped copy of the vault key. Ciphertext to the server, always.
#[derive(Debug, Deserialize, Serialize)]
pub struct WrappedSlot {
    /// Base64url, no padding.
    pub wrapped_key: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// The client's authentication key. Hashed on arrival and never stored as
    /// it is (section 9.2.1 step 5).
    pub auth_key: String,
    /// The Argon2id parameters the client used, returned later by `prelogin`
    /// so any device can reproduce the derivation.
    pub kdf_params: serde_json::Value,
    /// The client-generated 128-bit salt. Public, and never derived from the
    /// email address (section 9.2.1 step 2).
    pub client_salt: String,
    pub password_slot: WrappedSlot,
    /// Mandatory. Section 9.2: a synced account holds exactly one recovery
    /// slot, and 9.2.3 makes it mandatory for passkey accounts too.
    pub recovery_slot: WrappedSlot,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub account_id: Uuid,
}

pub async fn register(
    State(state): State<SharedState>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    let email = crypto::normalise_email(&request.email);
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::BadRequest {
            message: "An email address is required.".to_string(),
        });
    }

    let auth_key = decode(&request.auth_key, "auth_key")?;
    let client_salt = decode(&request.client_salt, "client_salt")?;
    if client_salt.len() != 16 {
        return Err(ApiError::BadRequest {
            message: "The salt must be 128 bits.".to_string(),
        });
    }

    let password = decode_slot(&request.password_slot, "password_slot")?;
    let recovery = decode_slot(&request.recovery_slot, "recovery_slot")?;

    // Section 9.2.1 step 5. Done before the transaction so the Argon2id cost
    // is not held across a database lock.
    let auth_hash = crypto::hash_auth_key(&auth_key)
        .map_err(|error| ApiError::Other(anyhow::anyhow!("hashing failed: {error}")))?;

    let mut transaction = state.db.begin().await?;

    let account_id = Uuid::new_v4();
    let inserted = sqlx::query("INSERT INTO account (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING")
        .bind(account_id)
        .bind(&email)
        .execute(&mut *transaction)
        .await?;

    if inserted.rows_affected() == 0 {
        // An address that already exists. This is a deliberate difference from
        // `prelogin`: registration cannot hide it — the caller finds out
        // either way when the account does not work — and refusing without
        // saying why would be unusable.
        return Err(ApiError::Conflict {
            message: "An account already exists for that address.".to_string(),
        });
    }

    sqlx::query(
        "INSERT INTO key_slot
           (id, account_id, type, wrapped_key, wrap_nonce, kdf_params, client_salt, auth_hash)
         VALUES ($1, $2, 'password', $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(&password.0)
    .bind(&password.1)
    .bind(&request.kdf_params)
    .bind(&client_salt)
    .bind(&auth_hash)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO key_slot (id, account_id, type, wrapped_key, wrap_nonce)
         VALUES ($1, $2, 'recovery', $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(&recovery.0)
    .bind(&recovery.1)
    .execute(&mut *transaction)
    .await?;

    sqlx::query("INSERT INTO sync_state (account_id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok((StatusCode::CREATED, Json(RegisterResponse { account_id })))
}

// ---------------------------------------------------------------------------
// Prelogin
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub client_salt: String,
    pub kdf_params: serde_json::Value,
    /// Which slot types the account holds. For an address with no account this
    /// is what a password-only account would look like, because that is the
    /// common case and an unusual answer would itself be a signal.
    pub slot_types: Vec<String>,
}

/// Section 9.5, and the requirement is easy to half-build.
///
/// Two things have to match, not one:
///
/// - **The body.** A fabricated salt that is stable per address, derived by
///   HMAC with a server-held key, and the current default parameters.
/// - **The time.** A matching body with a distinguishable response time still
///   answers the attacker's question. Both paths are padded to a fixed floor.
///
/// The lookup runs the same way in both cases; only the source of the values
/// differs afterwards.
pub async fn prelogin(
    State(state): State<SharedState>,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let started = Instant::now();
    let email = crypto::normalise_email(&request.email);

    let found = sqlx::query_as::<_, (Option<Vec<u8>>, Option<serde_json::Value>)>(
        "SELECT k.client_salt, k.kdf_params
           FROM account a
           JOIN key_slot k ON k.account_id = a.id AND k.type = 'password'
          WHERE a.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    let response = match found {
        Some((Some(salt), Some(params))) => PreloginResponse {
            client_salt: crypto::b64_encode(&salt),
            kdf_params: params,
            slot_types: vec!["password".to_string(), "recovery".to_string()],
        },
        // No account, or an account with no password slot. Both get the same
        // fabricated answer: an account that exists but has only a passkey
        // must not be distinguishable from one that does not exist.
        _ => PreloginResponse {
            client_salt: crypto::b64_encode(&crypto::fake_client_salt(&state.server_key, &email)),
            kdf_params: default_kdf_params(),
            slot_types: vec!["password".to_string(), "recovery".to_string()],
        },
    };

    pad_to_floor(started, PRELOGIN_FLOOR).await;
    Ok(Json(response))
}

/// The parameters a current client would use (section 9.2.1 step 3, mobile).
///
/// Returned for an unknown address, so a fabricated answer names a cost that a
/// real account would plausibly have been created with.
fn default_kdf_params() -> serde_json::Value {
    serde_json::json!({ "memory_kib": 65536, "iterations": 3, "lanes": 4 })
}

/// Sleeps until `floor` has elapsed since `started`.
///
/// If the work already took longer, this returns immediately — the floor is a
/// minimum, not a fixed cost, and a request slow enough to exceed it was slow
/// for a reason unrelated to whether the account exists.
async fn pad_to_floor(started: Instant, floor: Duration) {
    if let Some(remaining) = floor.checked_sub(started.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
    pub device_name: Option<String>,
    pub device_platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    /// The wrapped vault key for the password slot. Still ciphertext: the
    /// client unwraps it with a KEK the server has never seen.
    pub password_slot: WrappedSlot,
    pub recovery_slot: WrappedSlot,
}

pub async fn login(
    State(state): State<SharedState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = crypto::normalise_email(&request.email);
    let auth_key = decode(&request.auth_key, "auth_key")?;

    let row = sqlx::query_as::<_, (Uuid, Option<String>, Vec<u8>, Vec<u8>)>(
        "SELECT a.id, k.auth_hash, k.wrapped_key, k.wrap_nonce
           FROM account a
           JOIN key_slot k ON k.account_id = a.id AND k.type = 'password'
          WHERE a.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    // One error for a wrong address and a wrong key. Section 9.5 again: a
    // different message here would undo what `prelogin` is protecting.
    let Some((account_id, Some(auth_hash), wrapped_key, wrap_nonce)) = row else {
        return Err(ApiError::InvalidCredentials);
    };

    if !crypto::verify_auth_key(&auth_key, &auth_hash) {
        return Err(ApiError::InvalidCredentials);
    }

    let recovery = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT wrapped_key, wrap_nonce FROM key_slot
          WHERE account_id = $1 AND type = 'recovery'",
    )
    .bind(account_id)
    .fetch_one(&state.db)
    .await?;

    let device_id = register_device(&state, account_id, &request).await?;
    let tokens = issue_session(&state, account_id, device_id).await?;

    sqlx::query("UPDATE key_slot SET last_used = now() WHERE account_id = $1 AND type = 'password'")
        .bind(account_id)
        .execute(&state.db)
        .await?;

    Ok(Json(LoginResponse {
        access_token: tokens.access,
        refresh_token: tokens.refresh,
        access_expires_at: tokens.access_expires_at,
        password_slot: WrappedSlot {
            wrapped_key: crypto::b64_encode(&wrapped_key),
            nonce: crypto::b64_encode(&wrap_nonce),
        },
        recovery_slot: WrappedSlot {
            wrapped_key: crypto::b64_encode(&recovery.0),
            nonce: crypto::b64_encode(&recovery.1),
        },
    }))
}

async fn register_device(
    state: &AppState,
    account_id: Uuid,
    request: &LoginRequest,
) -> ApiResult<Uuid> {
    quota::check_device_limit(&state.db, account_id).await?;

    let device_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO device (id, account_id, name, platform, last_seen)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(request.device_name.as_deref().unwrap_or("Unnamed device"))
    .bind(request.device_platform.as_deref().unwrap_or("unknown"))
    .execute(&state.db)
    .await?;

    Ok(device_id)
}

struct Tokens {
    access: String,
    refresh: String,
    access_expires_at: DateTime<Utc>,
}

/// Issues a session, storing only hashes of the tokens.
async fn issue_session(state: &AppState, account_id: Uuid, device_id: Uuid) -> ApiResult<Tokens> {
    let access = crypto::random_token();
    let refresh = crypto::random_token();

    let access_expires_at = Utc::now() + chrono::Duration::minutes(ACCESS_TTL_MINUTES);
    let refresh_expires_at = Utc::now() + chrono::Duration::days(REFRESH_TTL_DAYS);

    sqlx::query(
        "INSERT INTO session
           (id, account_id, device_id, access_hash, refresh_hash,
            access_expires_at, refresh_expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(device_id)
    .bind(token_hash(&access))
    .bind(token_hash(&refresh))
    .bind(access_expires_at)
    .bind(refresh_expires_at)
    .execute(&state.db)
    .await?;

    Ok(Tokens {
        access,
        refresh,
        access_expires_at,
    })
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Resolves a bearer token to an account, or refuses.
pub async fn account_for_token(db: &sqlx::PgPool, token: &str) -> ApiResult<Uuid> {
    let row = sqlx::query_as::<_, (Uuid,)>(
        "SELECT account_id FROM session
          WHERE access_hash = $1 AND NOT revoked AND access_expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await?;

    row.map(|(id,)| id).ok_or(ApiError::Unauthorized)
}

fn decode(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    crypto::b64_decode(value).map_err(|_| ApiError::BadRequest {
        message: format!("{field} is not valid base64url."),
    })
}

fn decode_slot(slot: &WrappedSlot, field: &str) -> ApiResult<(Vec<u8>, Vec<u8>)> {
    Ok((
        decode(&slot.wrapped_key, field)?,
        decode(&slot.nonce, field)?,
    ))
}
