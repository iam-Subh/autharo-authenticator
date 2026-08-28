//! Sign-up and password sign-in (PRD sections 9.2.1, 9.5, 13).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::activity;
use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::quota;
use crate::ratelimit;
use crate::{AppState, SharedState};

/// Section 13: an access token lasts 15 minutes, a refresh token 30 days.
const ACCESS_TTL_MINUTES: i64 = 15;
const REFRESH_TTL_DAYS: i64 = 30;
const CAPABILITY_TTL_MINUTES: i64 = 5;
const RECOVERY_RESET_TTL_MINUTES: i64 = 10;

/// Bound all Argon2 work. Each permit can use about 19 MiB. Login and account
/// deletion need the same bound as registration.
static ARGON2_SLOTS: Semaphore = Semaphore::const_new(4);

const AUTH_KEY_BYTES: usize = 32;
const SLOT_NONCE_BYTES: usize = 24;
const WRAPPED_VAULT_KEY_BYTES: usize = 48;
const KDF_MEMORY_MIN_KIB: u64 = 8 * 1024;
const KDF_MEMORY_MAX_KIB: u64 = 256 * 1024;
const KDF_ITERATIONS_MAX: u64 = 10;
const KDF_LANES_MAX: u64 = 8;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_DEVICE_NAME_BYTES: usize = 100;
const MAX_PLATFORM_BYTES: usize = 40;
const MAX_TOKEN_BYTES: usize = 128;

pub const SCOPE_VAULT_SYNC: &str = "vault:sync";
pub const SCOPE_SECURITY_READ: &str = "security:read";
pub const SCOPE_SHARE_WRITE: &str = "share:write";
pub const SCOPE_SESSION_SELF: &str = "session:self";
pub(crate) const DEFAULT_SCOPES: [&str; 2] = [SCOPE_VAULT_SYNC, SCOPE_SESSION_SELF];

const ELEVATED_SCOPES: [&str; 2] = [SCOPE_SECURITY_READ, SCOPE_SHARE_WRITE];

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
    /// A fresh Firebase ID token. A release server verifies its signature,
    /// project, expiry, subject, and email ownership before it creates an
    /// account. Development builds can omit it when Firebase is not set.
    pub identity_token: Option<String>,
    /// The client's authentication key. Hashed on arrival and never stored as
    /// it is (section 9.2.1 step 5).
    pub auth_key: String,
    /// A separate proof derived from the recovery phrase. The phrase itself
    /// never reaches the server.
    pub recovery_auth_key: String,
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
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    let email = crypto::normalise_email(&request.email);
    if !valid_email_input(&email) {
        return Err(ApiError::BadRequest {
            message: "An email address is required.".to_string(),
        });
    }

    let address = ratelimit::client_address(&headers, socket);
    ratelimit::record_address_endpoint(
        &state.db,
        "register",
        address,
        ratelimit::REGISTRATIONS_PER_ADDRESS_PER_HOUR,
    )
    .await?;

    // Apply the address limit before token verification. Token verification
    // can fetch public keys and use CPU for signature verification.
    let verified_identity = if let Some(verifier) = &state.identity {
        let token = request
            .identity_token
            .as_deref()
            .ok_or(ApiError::EmailVerificationRequired)?;
        match verifier.verify(token).await {
            Ok(identity) if crypto::normalise_email(&identity.email) == email => Some(identity),
            Ok(_) => return Err(ApiError::InvalidIdentity),
            Err(crate::identity::IdentityError::EmailNotVerified) => {
                return Err(ApiError::EmailVerificationRequired);
            }
            Err(_) => return Err(ApiError::InvalidIdentity),
        }
    } else {
        None
    };

    let auth_key = decode(&request.auth_key, "auth_key")?;
    if auth_key.len() != AUTH_KEY_BYTES {
        return Err(ApiError::BadRequest {
            message: "The authentication key must be 256 bits.".to_string(),
        });
    }
    let recovery_auth_key = decode(&request.recovery_auth_key, "recovery_auth_key")?;
    if recovery_auth_key.len() != AUTH_KEY_BYTES {
        return Err(ApiError::BadRequest {
            message: "The recovery authentication key must be 256 bits.".to_string(),
        });
    }
    let client_salt = decode(&request.client_salt, "client_salt")?;
    if client_salt.len() != 16 {
        return Err(ApiError::BadRequest {
            message: "The salt must be 128 bits.".to_string(),
        });
    }

    let password = decode_slot(&request.password_slot, "password_slot")?;
    let recovery = decode_slot(&request.recovery_slot, "recovery_slot")?;
    validate_slot(&password, "password_slot")?;
    validate_slot(&recovery, "recovery_slot")?;
    validate_kdf_params(&request.kdf_params)?;

    // Section 9.2.1 step 5. Done before the transaction so the Argon2id cost
    // is not held across a database lock.
    let auth_hash = hash_auth_key_limited(auth_key).await?;
    let recovery_auth_hash = hash_auth_key_limited(recovery_auth_key).await?;

    let mut transaction = state.db.begin().await?;

    let account_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO account (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
    )
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

    if let Some(identity) = verified_identity {
        let inserted_identity = sqlx::query(
            "INSERT INTO account_identity
               (account_id, provider, subject, verified_email)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (subject) DO NOTHING",
        )
        .bind(account_id)
        .bind(identity.provider)
        .bind(identity.subject)
        .bind(email.clone())
        .execute(&mut *transaction)
        .await?;
        if inserted_identity.rows_affected() == 0 {
            return Err(ApiError::Conflict {
                message: "This verified identity is linked to another account.".to_string(),
            });
        }
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
        "INSERT INTO key_slot (id, account_id, type, wrapped_key, wrap_nonce, auth_hash)
         VALUES ($1, $2, 'recovery', $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(&recovery.0)
    .bind(&recovery.1)
    .bind(&recovery_auth_hash)
    .execute(&mut *transaction)
    .await?;

    sqlx::query("INSERT INTO sync_state (account_id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;

    activity::record_in_transaction(
        &mut transaction,
        account_id,
        None,
        "account_registered",
        serde_json::json!({}),
    )
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
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let started = Instant::now();
    let email = crypto::normalise_email(&request.email);
    if !valid_email_input(&email) {
        pad_to_floor(started, PRELOGIN_FLOOR).await;
        return Err(ApiError::BadRequest {
            message: "A valid email address is required.".to_string(),
        });
    }

    // Limited by address only. This endpoint is unauthenticated and takes an
    // address as input, so an account-keyed limit here would let anyone lock
    // out anyone else's sign-in by hammering `prelogin` with their address —
    // a denial of service handed out for free.
    //
    // The refusal is padded like every other answer, or the 429 would arrive
    // faster than a real response and become its own timing signal.
    let address = ratelimit::client_address(&headers, socket);
    if let Err(error) = ratelimit::record_address_endpoint(
        &state.db,
        "prelogin",
        address,
        ratelimit::PER_ADDRESS_PER_HOUR,
    )
    .await
    {
        pad_to_floor(started, PRELOGIN_FLOOR).await;
        return Err(error);
    }

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
    serde_json::json!({ "m": 65536, "t": 3, "p": 4 })
}

// ---------------------------------------------------------------------------
// Forgotten-password recovery
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartRecoveryRequest {
    pub email: String,
    pub recovery_auth_key: String,
}

#[derive(Debug, Serialize)]
pub struct StartRecoveryResponse {
    pub reset_token: String,
    pub recovery_slot: WrappedSlot,
    pub expires_at: DateTime<Utc>,
}

/// Verifies the recovery phrase proof and creates one short-lived reset token.
pub async fn start_recovery(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<StartRecoveryRequest>,
) -> ApiResult<Json<StartRecoveryResponse>> {
    let email = crypto::normalise_email(&request.email);
    if !valid_email_input(&email) {
        return Err(ApiError::InvalidCredentials);
    }
    let address = ratelimit::client_address(&headers, socket);
    ratelimit::record_and_check(&state.db, &format!("recovery:{email}"), Some(address)).await?;
    let candidate = decode(&request.recovery_auth_key, "recovery_auth_key")?;
    if candidate.len() != AUTH_KEY_BYTES {
        return Err(ApiError::InvalidCredentials);
    }

    let row = sqlx::query_as::<_, (Uuid, Option<String>, Vec<u8>, Vec<u8>)>(
        "SELECT a.id, k.auth_hash, k.wrapped_key, k.wrap_nonce
           FROM account a
           JOIN key_slot k ON k.account_id = a.id AND k.type = 'recovery'
          WHERE a.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let verification_hash = row
        .as_ref()
        .and_then(|(_, hash, _, _)| hash.clone())
        .unwrap_or_else(|| state.fake_auth_hash.clone());
    let verified = verify_auth_key_limited(candidate, verification_hash).await?;
    let Some((account_id, Some(_), wrapped_key, nonce)) = row else {
        return Err(ApiError::InvalidCredentials);
    };
    if !verified {
        return Err(ApiError::InvalidCredentials);
    }

    let reset_token = crypto::random_token();
    let expires_at = Utc::now() + chrono::Duration::minutes(RECOVERY_RESET_TTL_MINUTES);
    let mut transaction = state.db.begin().await?;
    sqlx::query("DELETE FROM recovery_reset WHERE account_id = $1 OR expires_at <= now()")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO recovery_reset (id, account_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(token_hash(&reset_token))
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    activity::record_in_transaction(
        &mut transaction,
        account_id,
        None,
        "password_recovery_started",
        serde_json::json!({ "expires_at": expires_at }),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(StartRecoveryResponse {
        reset_token,
        recovery_slot: WrappedSlot {
            wrapped_key: crypto::b64_encode(&wrapped_key),
            nonce: crypto::b64_encode(&nonce),
        },
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishRecoveryRequest {
    pub reset_token: String,
    pub new_auth_key: String,
    pub kdf_params: serde_json::Value,
    pub client_salt: String,
    pub password_slot: WrappedSlot,
    pub device_name: Option<String>,
    pub device_platform: Option<String>,
}

/// Replaces the password after a successful recovery proof.
pub async fn finish_recovery(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<FinishRecoveryRequest>,
) -> ApiResult<Json<LoginResponse>> {
    ratelimit::record_address_endpoint(
        &state.db,
        "recovery_finish",
        ratelimit::client_address(&headers, socket),
        ratelimit::PER_ADDRESS_PER_HOUR,
    )
    .await?;
    if request.reset_token.is_empty() || request.reset_token.len() > MAX_TOKEN_BYTES {
        return Err(ApiError::InvalidCredentials);
    }
    if request
        .device_name
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_DEVICE_NAME_BYTES)
        || request
            .device_platform
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_PLATFORM_BYTES)
    {
        return Err(ApiError::BadRequest {
            message: "The device description is invalid.".to_string(),
        });
    }
    let new_auth_key = decode(&request.new_auth_key, "new_auth_key")?;
    if new_auth_key.len() != AUTH_KEY_BYTES {
        return Err(ApiError::BadRequest {
            message: "The new authentication key must be 256 bits.".to_string(),
        });
    }
    let client_salt = decode(&request.client_salt, "client_salt")?;
    if client_salt.len() != 16 {
        return Err(ApiError::BadRequest {
            message: "The new salt must be 128 bits.".to_string(),
        });
    }
    validate_kdf_params(&request.kdf_params)?;
    let password_slot = decode_slot(&request.password_slot, "password_slot")?;
    validate_slot(&password_slot, "password_slot")?;
    let new_auth_hash = hash_auth_key_limited(new_auth_key).await?;

    let mut transaction = state.db.begin().await?;
    let row = sqlx::query_as::<_, (Uuid,)>(
        "DELETE FROM recovery_reset
          WHERE token_hash = $1 AND expires_at > now()
          RETURNING account_id",
    )
    .bind(token_hash(&request.reset_token))
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((account_id,)) = row else {
        return Err(ApiError::InvalidCredentials);
    };
    sqlx::query("SELECT id FROM account WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
    let changed = sqlx::query(
        "UPDATE key_slot
            SET auth_hash = $1, kdf_params = $2, client_salt = $3,
                wrapped_key = $4, wrap_nonce = $5, last_used = now()
          WHERE account_id = $6 AND type = 'password'",
    )
    .bind(new_auth_hash)
    .bind(&request.kdf_params)
    .bind(&client_salt)
    .bind(&password_slot.0)
    .bind(&password_slot.1)
    .bind(account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::InvalidCredentials);
    }
    sqlx::query("UPDATE session SET revoked = TRUE WHERE account_id = $1 AND NOT revoked")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE device SET revoked = TRUE, push_token = NULL
          WHERE account_id = $1 AND NOT revoked",
    )
    .bind(account_id)
    .execute(&mut *transaction)
    .await?;

    let device_id = Uuid::new_v4();
    let device_name = request.device_name.as_deref().unwrap_or("Android device");
    let device_platform = request.device_platform.as_deref().unwrap_or("android");
    sqlx::query(
        "INSERT INTO device (id, account_id, name, platform, last_seen)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(device_name)
    .bind(device_platform)
    .execute(&mut *transaction)
    .await?;
    let tokens = Tokens::new();
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO session
           (id, family_id, account_id, device_id, access_hash, refresh_hash,
            access_expires_at, refresh_expires_at, scopes)
         VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(session_id)
    .bind(account_id)
    .bind(device_id)
    .bind(token_hash(&tokens.access))
    .bind(token_hash(&tokens.refresh))
    .bind(tokens.access_expires_at)
    .bind(tokens.refresh_expires_at)
    .bind(DEFAULT_SCOPES.to_vec())
    .execute(&mut *transaction)
    .await?;
    let recovery = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT wrapped_key, wrap_nonce FROM key_slot
          WHERE account_id = $1 AND type = 'recovery'",
    )
    .bind(account_id)
    .fetch_one(&mut *transaction)
    .await?;
    activity::record_in_transaction(
        &mut transaction,
        account_id,
        Some(device_id),
        "password_recovered",
        serde_json::json!({ "other_devices_revoked": true }),
    )
    .await?;
    transaction.commit().await?;

    Ok(Json(LoginResponse {
        access_token: tokens.access,
        refresh_token: tokens.refresh,
        access_expires_at: tokens.access_expires_at,
        password_slot: WrappedSlot {
            wrapped_key: crypto::b64_encode(&password_slot.0),
            nonce: crypto::b64_encode(&password_slot.1),
        },
        recovery_slot: WrappedSlot {
            wrapped_key: crypto::b64_encode(&recovery.0),
            nonce: crypto::b64_encode(&recovery.1),
        },
    }))
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
    /// A single-use token created by an existing device. The first active
    /// device does not need one.
    pub device_approval_token: Option<String>,
    /// Optional emergency approval derived from the recovery phrase.
    pub recovery_auth_key: Option<String>,
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
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = crypto::normalise_email(&request.email);
    if !valid_email_input(&email) {
        return Err(ApiError::InvalidCredentials);
    }

    // Section 9.5, before anything expensive happens. Counted against the
    // submitted address whether or not it names an account: a limit that
    // applied only to real accounts would make 429-versus-401 answer the
    // question the fake salt and the timing floor exist to refuse.
    let address = ratelimit::client_address(&headers, socket);
    ratelimit::record_and_check(&state.db, &email, Some(address)).await?;

    let auth_key = decode(&request.auth_key, "auth_key")?;
    if auth_key.len() != AUTH_KEY_BYTES {
        return Err(ApiError::InvalidCredentials);
    }

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
    let verification_hash = row
        .as_ref()
        .and_then(|(_, hash, _, _)| hash.clone())
        .unwrap_or_else(|| state.fake_auth_hash.clone());
    let verified = verify_auth_key_limited(auth_key, verification_hash).await?;
    let Some((account_id, Some(_), wrapped_key, wrap_nonce)) = row else {
        return Err(ApiError::InvalidCredentials);
    };

    if !verified {
        return Err(ApiError::InvalidCredentials);
    }

    let recovery_approved = if let Some(encoded) = request.recovery_auth_key.as_deref() {
        let candidate = decode(encoded, "recovery_auth_key")?;
        if candidate.len() != AUTH_KEY_BYTES {
            false
        } else {
            let stored = sqlx::query_as::<_, (Option<String>,)>(
                "SELECT auth_hash FROM key_slot WHERE account_id = $1 AND type = 'recovery'",
            )
            .bind(account_id)
            .fetch_optional(&state.db)
            .await?;
            match stored {
                Some((Some(hash),)) => verify_auth_key_limited(candidate, hash).await?,
                _ => false,
            }
        }
    } else {
        false
    };

    let recovery = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT wrapped_key, wrap_nonce FROM key_slot
          WHERE account_id = $1 AND type = 'recovery'",
    )
    .bind(account_id)
    .fetch_one(&state.db)
    .await?;

    let (_device_id, tokens) =
        register_device_and_issue_session(&state, account_id, &request, recovery_approved).await?;

    sqlx::query(
        "UPDATE key_slot SET last_used = now() WHERE account_id = $1 AND type = 'password'",
    )
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

pub(crate) async fn register_device_and_issue_session(
    state: &AppState,
    account_id: Uuid,
    request: &LoginRequest,
    recovery_approved: bool,
) -> ApiResult<(Uuid, Tokens)> {
    if request
        .device_name
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_DEVICE_NAME_BYTES)
        || request
            .device_platform
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_PLATFORM_BYTES)
    {
        return Err(ApiError::BadRequest {
            message: "The device description is invalid.".to_string(),
        });
    }
    let mut transaction = state.db.begin().await?;
    sqlx::query("SELECT id FROM account WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    let (device_count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM device WHERE account_id = $1 AND NOT revoked")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
    let (device_history,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM device WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
    if device_count >= quota::MAX_DEVICES {
        return Err(ApiError::QuotaExceeded {
            message: format!(
                "This account already has {} devices. Revoke one before adding another.",
                quota::MAX_DEVICES
            ),
        });
    }

    let approval_method = if device_history == 0 {
        "initial"
    } else if recovery_approved {
        "recovery"
    } else {
        let token = request
            .device_approval_token
            .as_deref()
            .filter(|value| !value.is_empty() && value.len() <= MAX_TOKEN_BYTES)
            .ok_or(ApiError::DeviceApprovalRequired)?;
        let consumed = sqlx::query_as::<_, (Uuid,)>(
            "UPDATE device_approval
                SET used_at = now()
              WHERE account_id = $1
                AND token_hash = $2
                AND used_at IS NULL
                AND expires_at > now()
              RETURNING id",
        )
        .bind(account_id)
        .bind(token_hash(token))
        .fetch_optional(&mut *transaction)
        .await?;
        if consumed.is_none() {
            return Err(ApiError::DeviceApprovalRequired);
        }
        "device"
    };

    let device_id = Uuid::new_v4();
    let device_name = request.device_name.as_deref().unwrap_or("Unnamed device");
    let device_platform = request.device_platform.as_deref().unwrap_or("unknown");
    sqlx::query(
        "INSERT INTO device (id, account_id, name, platform, last_seen)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(device_name)
    .bind(device_platform)
    .execute(&mut *transaction)
    .await?;

    let tokens = Tokens::new();
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO session
           (id, family_id, account_id, device_id, access_hash, refresh_hash,
            access_expires_at, refresh_expires_at, scopes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(session_id)
    .bind(session_id)
    .bind(account_id)
    .bind(device_id)
    .bind(token_hash(&tokens.access))
    .bind(token_hash(&tokens.refresh))
    .bind(tokens.access_expires_at)
    .bind(tokens.refresh_expires_at)
    .bind(DEFAULT_SCOPES.to_vec())
    .execute(&mut *transaction)
    .await?;

    activity::record_in_transaction(
        &mut transaction,
        account_id,
        Some(device_id),
        "device_added",
        serde_json::json!({
            "name": device_name,
            "platform": device_platform,
            "approval_method": approval_method,
        }),
    )
    .await?;

    transaction.commit().await?;

    Ok((device_id, tokens))
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ElevateRequest {
    pub auth_key: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ElevateResponse {
    pub access_token: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

/// Issues a short-lived permission for an interactive action.
///
/// The persistent session can synchronize in the background. It cannot read
/// security data or create a share. Those permissions require the account
/// password and are never refreshable or written to disk by the client.
pub async fn elevate(
    State(state): State<SharedState>,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ElevateRequest>,
) -> ApiResult<Json<ElevateResponse>> {
    let token = bearer(&headers)?;
    let session = session_for_token_with_scope(&state.db, token, SCOPE_SESSION_SELF).await?;
    let mut scopes = request.scopes;
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty()
        || scopes.len() > ELEVATED_SCOPES.len()
        || scopes
            .iter()
            .any(|scope| !ELEVATED_SCOPES.contains(&scope.as_str()))
    {
        return Err(ApiError::InvalidScope);
    }
    verify_step_up(
        &state,
        session.account_id,
        &request.auth_key,
        ratelimit::client_address(&headers, socket),
    )
    .await?;

    let access_token = crypto::random_token();
    let expires_at = Utc::now() + chrono::Duration::minutes(CAPABILITY_TTL_MINUTES);
    sqlx::query(
        "INSERT INTO capability_session
           (id, parent_session_id, token_hash, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(session.session_id)
    .bind(token_hash(&access_token))
    .bind(&scopes)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(ElevateResponse {
        access_token,
        scopes,
        expires_at,
    }))
}

/// Exchanges a refresh token for a new pair (section 13).
///
/// # Why this is not optional
///
/// An access token lasts fifteen minutes. Without this endpoint a device syncs
/// for fifteen minutes after signing in and then never again: every cycle gets
/// a 401, the client reports "signed out", and the only way back is the account
/// password. On a device that syncs in the background the user never even sees
/// the moment it stopped — they find out when a code they added on their phone
/// is missing on their laptop a week later.
///
/// It shipped that way, and no test caught it, because every test signs in
/// fresh and finishes in under a second.
///
/// # The old refresh token is invalidated
///
/// Refresh tokens rotate: each use issues a new pair and revokes the row it
/// came from. A refresh token is a thirty-day credential sitting in a file, and
/// one that stayed valid after use would let a copied file keep minting
/// sessions for a month after the device that owned it had moved on.
///
/// Reuse of an already-spent token is therefore a signal, not an accident. It
/// is refused — see the note below on why it is not treated as more than that
/// yet.
pub async fn refresh(
    State(state): State<SharedState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<Json<RefreshResponse>> {
    if request.refresh_token.is_empty() || request.refresh_token.len() > MAX_TOKEN_BYTES {
        return Err(ApiError::Unauthorized);
    }
    let hash = token_hash(&request.refresh_token);

    let mut transaction = state.db.begin().await?;
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            Option<Uuid>,
            Uuid,
            bool,
            DateTime<Utc>,
            Option<bool>,
            Vec<String>,
        ),
    >(
        "SELECT s.account_id, s.device_id, s.family_id, s.revoked,
                s.refresh_expires_at, d.revoked, s.scopes
           FROM session s
           LEFT JOIN device d ON d.id = s.device_id
          WHERE s.refresh_hash = $1
          FOR UPDATE OF s",
    )
    .bind(&hash)
    .fetch_optional(&mut *transaction)
    .await?;

    let Some((account_id, device_id, family_id, revoked, expires_at, device_revoked, scopes)) = row
    else {
        return Err(ApiError::Unauthorized);
    };

    // Reuse of a rotated token means that two parties hold the same token
    // family. Revoke the full family, including descendants that remain live.
    if revoked || expires_at <= Utc::now() || device_id.is_none() || device_revoked.unwrap_or(true)
    {
        if revoked {
            activity::record_in_transaction(
                &mut transaction,
                account_id,
                device_id,
                "refresh_replay_detected",
                serde_json::json!({ "session_family_id": family_id }),
            )
            .await?;
        }
        sqlx::query("UPDATE session SET revoked = TRUE WHERE family_id = $1")
            .bind(family_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Err(ApiError::Unauthorized);
    }
    let device_id = device_id.expect("checked above");

    sqlx::query("UPDATE session SET revoked = TRUE WHERE refresh_hash = $1")
        .bind(&hash)
        .execute(&mut *transaction)
        .await?;

    let tokens = Tokens::new();
    sqlx::query(
        "INSERT INTO session
           (id, family_id, account_id, device_id, access_hash, refresh_hash,
             access_expires_at, refresh_expires_at, scopes)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(Uuid::new_v4())
    .bind(family_id)
    .bind(account_id)
    .bind(device_id)
    .bind(token_hash(&tokens.access))
    .bind(token_hash(&tokens.refresh))
    .bind(tokens.access_expires_at)
    .bind(tokens.refresh_expires_at)
    .bind(scopes)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE device SET last_seen = now() WHERE id = $1")
        .bind(device_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    Ok(Json(RefreshResponse {
        access_token: tokens.access,
        refresh_token: tokens.refresh,
        access_expires_at: tokens.access_expires_at,
    }))
}

pub(crate) struct Tokens {
    pub(crate) access: String,
    pub(crate) refresh: String,
    pub(crate) access_expires_at: DateTime<Utc>,
    pub(crate) refresh_expires_at: DateTime<Utc>,
}

impl Tokens {
    pub(crate) fn new() -> Self {
        Self {
            access: crypto::random_token(),
            refresh: crypto::random_token(),
            access_expires_at: Utc::now() + chrono::Duration::minutes(ACCESS_TTL_MINUTES),
            refresh_expires_at: Utc::now() + chrono::Duration::days(REFRESH_TTL_DAYS),
        }
    }
}

pub(crate) async fn hash_auth_key_limited(auth_key: Vec<u8>) -> ApiResult<String> {
    let _permit = ARGON2_SLOTS
        .acquire()
        .await
        .map_err(|error| ApiError::Other(anyhow::anyhow!("Argon2 work limiter closed: {error}")))?;
    tokio::task::spawn_blocking(move || {
        let auth_key = Zeroizing::new(auth_key);
        crypto::hash_auth_key(&auth_key)
            .map_err(|error| ApiError::Other(anyhow::anyhow!("hashing failed: {error}")))
    })
    .await
    .map_err(|error| ApiError::Other(anyhow::anyhow!("hashing task failed: {error}")))?
}

pub(crate) async fn verify_auth_key_limited(
    auth_key: Vec<u8>,
    auth_hash: String,
) -> ApiResult<bool> {
    let _permit = ARGON2_SLOTS
        .acquire()
        .await
        .map_err(|error| ApiError::Other(anyhow::anyhow!("Argon2 work limiter closed: {error}")))?;
    tokio::task::spawn_blocking(move || {
        let auth_key = Zeroizing::new(auth_key);
        crypto::verify_auth_key(&auth_key, &auth_hash)
    })
    .await
    .map_err(|error| ApiError::Other(anyhow::anyhow!("verification task failed: {error}")))
}

pub(crate) async fn verify_step_up(
    state: &SharedState,
    account_id: Uuid,
    encoded_auth_key: &str,
    address: std::net::IpAddr,
) -> ApiResult<()> {
    ratelimit::record_and_check(&state.db, &format!("stepup:{account_id}"), Some(address)).await?;
    let auth_key =
        crypto::b64_decode(encoded_auth_key).map_err(|_| ApiError::InvalidCredentials)?;
    if auth_key.len() != AUTH_KEY_BYTES {
        return Err(ApiError::InvalidCredentials);
    }
    let stored = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT auth_hash FROM key_slot WHERE account_id = $1 AND type = 'password'",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((Some(auth_hash),)) = stored else {
        return Err(ApiError::InvalidCredentials);
    };
    if !verify_auth_key_limited(auth_key, auth_hash).await? {
        return Err(ApiError::InvalidCredentials);
    }
    Ok(())
}

pub(crate) async fn verify_recovery_approval(
    state: &SharedState,
    account_id: Uuid,
    encoded_recovery_key: Option<&str>,
) -> ApiResult<bool> {
    let Some(encoded) = encoded_recovery_key else {
        return Ok(false);
    };
    let candidate = decode(encoded, "recovery_auth_key")?;
    if candidate.len() != AUTH_KEY_BYTES {
        return Ok(false);
    }
    let stored = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT auth_hash FROM key_slot WHERE account_id = $1 AND type = 'recovery'",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    match stored {
        Some((Some(hash),)) => verify_auth_key_limited(candidate, hash).await,
        _ => Ok(false),
    }
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Who is calling: the session, its account, and the device it belongs to.
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: Uuid,
    pub account_id: Uuid,
    /// `NULL` where the device row was removed. Sessions outlive nothing else,
    /// so this is rare, but section 9.5's endpoints act on devices and must
    /// cope with not having one.
    pub device_id: Option<Uuid>,
    pub scopes: Vec<String>,
}

pub async fn account_for_token_with_scope(
    db: &sqlx::PgPool,
    token: &str,
    scope: &str,
) -> ApiResult<Uuid> {
    Ok(session_for_token_with_scope(db, token, scope)
        .await?
        .account_id)
}

/// The same check, keeping the session and device it resolved.
///
/// # The device join is not decoration
///
/// Revoking a device marks the device row and kills its sessions in the same
/// request, so this join should never be what stops a revoked device. It is
/// here because "should never" is doing a lot of work in that sentence: a
/// session created between the two statements, a future code path that issues
/// one without re-reading the device, or a restore of the session table from a
/// backup taken before the revoke would each hand a live token to a device the
/// user believes they cut off.
///
/// The cost is one join on a request that already hits the database. The
/// failure it prevents is a lost phone that keeps syncing after its owner was
/// told it would not.
pub(crate) async fn session_for_token(db: &sqlx::PgPool, token: &str) -> ApiResult<Session> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>, Vec<String>)>(
        "SELECT s.id, s.account_id, s.device_id, s.scopes
           FROM session s
           LEFT JOIN device d ON d.id = s.device_id
          WHERE s.access_hash = $1
            AND NOT s.revoked
            AND s.access_expires_at > now()
            AND (d.id IS NULL OR NOT d.revoked)",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await?;

    row.map(|(session_id, account_id, device_id, scopes)| Session {
        session_id,
        account_id,
        device_id,
        scopes,
    })
    .ok_or(ApiError::Unauthorized)
}

pub async fn session_for_token_with_scope(
    db: &sqlx::PgPool,
    token: &str,
    scope: &str,
) -> ApiResult<Session> {
    match session_for_token(db, token).await {
        Ok(session) => {
            if session.scopes.iter().any(|value| value == scope) {
                return Ok(session);
            }
            if ELEVATED_SCOPES.contains(&scope) {
                return Err(ApiError::ElevationRequired);
            }
            return Err(ApiError::InsufficientScope);
        }
        Err(ApiError::Unauthorized) => {}
        Err(error) => return Err(error),
    }

    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>, Vec<String>, DateTime<Utc>, bool)>(
        "SELECT s.id, s.account_id, s.device_id, c.scopes, c.expires_at, c.revoked
           FROM capability_session c
           JOIN session s ON s.id = c.parent_session_id
           LEFT JOIN device d ON d.id = s.device_id
          WHERE c.token_hash = $1
            AND NOT s.revoked
            AND s.access_expires_at > now()
            AND (d.id IS NULL OR NOT d.revoked)",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await?;

    let Some((session_id, account_id, device_id, scopes, expires_at, revoked)) = row else {
        return Err(ApiError::Unauthorized);
    };
    if revoked || expires_at <= Utc::now() {
        return Err(ApiError::CapabilityExpired);
    }
    if !scopes.iter().any(|value| value == scope) {
        return Err(ApiError::InsufficientScope);
    }
    Ok(Session {
        session_id,
        account_id,
        device_id,
        scopes,
    })
}

fn bearer(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)
}

fn decode(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    crypto::b64_decode(value).map_err(|_| ApiError::BadRequest {
        message: format!("{field} is not valid base64url."),
    })
}

pub(crate) fn decode_slot(slot: &WrappedSlot, field: &str) -> ApiResult<(Vec<u8>, Vec<u8>)> {
    Ok((
        decode(&slot.wrapped_key, field)?,
        decode(&slot.nonce, field)?,
    ))
}

pub(crate) fn validate_slot(slot: &(Vec<u8>, Vec<u8>), field: &str) -> ApiResult<()> {
    if slot.0.len() != WRAPPED_VAULT_KEY_BYTES || slot.1.len() != SLOT_NONCE_BYTES {
        return Err(ApiError::BadRequest {
            message: format!("{field} has an invalid length."),
        });
    }
    Ok(())
}

pub(crate) fn validate_kdf_params(value: &serde_json::Value) -> ApiResult<()> {
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_u64);
    let valid = matches!(field("m"), Some(KDF_MEMORY_MIN_KIB..=KDF_MEMORY_MAX_KIB))
        && matches!(field("t"), Some(1..=KDF_ITERATIONS_MAX))
        && matches!(field("p"), Some(1..=KDF_LANES_MAX));
    if !valid {
        return Err(ApiError::BadRequest {
            message: "The KDF parameters are outside the supported range.".to_string(),
        });
    }
    Ok(())
}

fn valid_email_input(email: &str) -> bool {
    !email.is_empty() && email.len() <= MAX_EMAIL_BYTES && email.contains('@')
}
