//! WebAuthn passkey registration and authentication.
//!
//! The feature is disabled unless all relying-party environment values exist.
//! A ceremony row is removed before its response is verified, so one challenge
//! can produce at most one accepted response.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::SharedState;
use crate::auth;
use crate::crypto;
use crate::error::{ApiError, ApiResult};

const CEREMONY_TTL_MINUTES: i64 = 5;
const PRF_SALT_BYTES: usize = 32;
const WRAPPED_KEY_BYTES: usize = 48;
const WRAP_NONCE_BYTES: usize = 24;

type OptionalWrappedSlot = (Option<Vec<u8>>, Option<Vec<u8>>);

#[derive(Clone)]
pub struct PasskeyService {
    webauthn: Arc<Webauthn>,
}

impl PasskeyService {
    pub fn from_environment() -> anyhow::Result<Option<Self>> {
        let rp_id = std::env::var("WEBAUTHN_RP_ID").ok();
        let origin = std::env::var("WEBAUTHN_RP_ORIGIN").ok();
        let name = std::env::var("WEBAUTHN_RP_NAME").ok();
        if rp_id.is_none() && origin.is_none() && name.is_none() {
            return Ok(None);
        }
        let (rp_id, origin, name) = match (rp_id, origin, name) {
            (Some(rp_id), Some(origin), Some(name)) => (rp_id, origin, name),
            _ => anyhow::bail!(
                "WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN, and WEBAUTHN_RP_NAME must be set together"
            ),
        };
        let origin = Url::parse(&origin)?;
        if origin.scheme() != "https" || origin.host_str().is_none() {
            anyhow::bail!("WEBAUTHN_RP_ORIGIN must be one HTTPS origin");
        }
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)?
            .rp_name(&name)
            .build()?;
        Ok(Some(Self {
            webauthn: Arc::new(webauthn),
        }))
    }
}

#[derive(Debug, Serialize)]
pub struct CeremonyResponse {
    pub ceremony_id: Uuid,
    pub public_key: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistrationState {
    webauthn: PasskeyRegistration,
    prf_salt: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationState {
    webauthn: PasskeyAuthentication,
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistrationRequest {
    pub ceremony_id: Uuid,
    pub credential: Value,
    pub prf_supported: bool,
    pub wrapped_key: Option<String>,
    pub wrap_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FinishRegistrationResponse {
    pub credential_id: String,
    pub prf_supported: bool,
}

pub async fn start_registration(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<CeremonyResponse>> {
    let service = configured(&state)?;
    let session = authenticated(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    let (email,): (String,) = sqlx::query_as("SELECT email FROM account WHERE id = $1")
        .bind(session.account_id)
        .fetch_one(&state.db)
        .await?;
    let existing = load_passkeys(&state, session.account_id).await?;
    let excluded = (!existing.is_empty()).then(|| {
        existing
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect()
    });
    let (options, registration) = service
        .webauthn
        .start_google_passkey_in_google_password_manager_only_registration(
            session.account_id,
            &email,
            &email,
            excluded,
        )
        .map_err(webauthn_error)?;
    let prf_salt = random_bytes(PRF_SALT_BYTES)?;
    let mut options = serde_json::to_value(options).map_err(internal_json)?;
    add_registration_prf(&mut options, &prf_salt)?;
    let ceremony_id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::minutes(CEREMONY_TTL_MINUTES);
    let ceremony = RegistrationState {
        webauthn: registration,
        prf_salt,
    };
    sqlx::query(
        "INSERT INTO passkey_ceremony (id, account_id, kind, state, expires_at)
         VALUES ($1, $2, 'register', $3, $4)",
    )
    .bind(ceremony_id)
    .bind(session.account_id)
    .bind(serde_json::to_value(ceremony).map_err(internal_json)?)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(Json(CeremonyResponse {
        ceremony_id,
        public_key: options,
        expires_at,
    }))
}

pub async fn finish_registration(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<FinishRegistrationRequest>,
) -> ApiResult<Json<FinishRegistrationResponse>> {
    let service = configured(&state)?;
    let session = authenticated(&state, &headers, auth::SCOPE_SECURITY_READ).await?;
    let state_json =
        consume_ceremony(&state, request.ceremony_id, session.account_id, "register").await?;
    let ceremony: RegistrationState = serde_json::from_value(state_json).map_err(internal_json)?;
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(request.credential.clone()).map_err(|_| ApiError::BadRequest {
            message: "The passkey registration response is malformed.".to_string(),
        })?;
    let passkey = service
        .webauthn
        .finish_passkey_registration(&credential, &ceremony.webauthn)
        .map_err(webauthn_error)?;

    if request.prf_supported != registration_prf_supported(&request.credential) {
        return Err(ApiError::BadRequest {
            message: "The passkey PRF support result is inconsistent.".to_string(),
        });
    }

    let (wrapped_key, wrap_nonce) = decode_optional_slot(
        request.prf_supported,
        request.wrapped_key.as_deref(),
        request.wrap_nonce.as_deref(),
    )?;
    let credential_id = passkey.cred_id().as_ref().to_vec();
    let public_key = serde_json::to_value(passkey.get_public_key()).map_err(internal_json)?;
    let credential_json = serde_json::to_value(&passkey).map_err(internal_json)?;
    let transports = registration_transports(&request.credential);
    sqlx::query(
        "INSERT INTO passkey_credential
           (id, account_id, credential_id, user_handle, public_key, credential,
            transports, prf_salt, prf_supported, wrapped_key, wrap_nonce)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::new_v4())
    .bind(session.account_id)
    .bind(&credential_id)
    .bind(session.account_id.as_bytes().to_vec())
    .bind(public_key)
    .bind(credential_json)
    .bind(transports)
    .bind(ceremony.prf_salt)
    .bind(request.prf_supported)
    .bind(wrapped_key)
    .bind(wrap_nonce)
    .execute(&state.db)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|inner| inner.is_unique_violation())
        {
            ApiError::Conflict {
                message: "This passkey is already registered.".to_string(),
            }
        } else {
            ApiError::Database(error)
        }
    })?;

    Ok(Json(FinishRegistrationResponse {
        credential_id: B64.encode(credential_id),
        prf_supported: request.prf_supported,
    }))
}

#[derive(Debug, Deserialize)]
pub struct StartAuthenticationRequest {
    pub email: String,
}

pub async fn start_authentication(
    State(state): State<SharedState>,
    Json(request): Json<StartAuthenticationRequest>,
) -> ApiResult<Json<CeremonyResponse>> {
    let service = configured(&state)?;
    let email = crypto::normalise_email(&request.email);
    let account = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM account WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.db)
        .await?;
    let Some((account_id,)) = account else {
        return Err(ApiError::InvalidCredentials);
    };
    let rows = load_passkey_rows(&state, account_id).await?;
    if rows.is_empty() {
        return Err(ApiError::InvalidCredentials);
    }
    let passkeys = rows
        .iter()
        .map(|row| row.passkey.clone())
        .collect::<Vec<_>>();
    let (options, authentication) = service
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(webauthn_error)?;
    let mut options = serde_json::to_value(options).map_err(internal_json)?;
    add_authentication_prf(&mut options, &rows)?;
    let ceremony_id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::minutes(CEREMONY_TTL_MINUTES);
    sqlx::query(
        "INSERT INTO passkey_ceremony (id, account_id, kind, state, expires_at)
         VALUES ($1, $2, 'authenticate', $3, $4)",
    )
    .bind(ceremony_id)
    .bind(account_id)
    .bind(
        serde_json::to_value(AuthenticationState {
            webauthn: authentication,
        })
        .map_err(internal_json)?,
    )
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(Json(CeremonyResponse {
        ceremony_id,
        public_key: options,
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FinishAuthenticationRequest {
    pub ceremony_id: Uuid,
    pub credential: Value,
    pub prf_result_present: bool,
    pub device_name: Option<String>,
    pub device_platform: Option<String>,
    pub device_approval_token: Option<String>,
    pub recovery_auth_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FinishAuthenticationResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub slot_kind: String,
    pub wrapped_key: String,
    pub nonce: String,
    pub prf_salt: Option<String>,
}

pub async fn finish_authentication(
    State(state): State<SharedState>,
    Json(request): Json<FinishAuthenticationRequest>,
) -> ApiResult<Json<FinishAuthenticationResponse>> {
    let service = configured(&state)?;
    let row = sqlx::query_as::<_, (Uuid, Value, DateTime<Utc>)>(
        "DELETE FROM passkey_ceremony
          WHERE id = $1 AND kind = 'authenticate'
          RETURNING account_id, state, expires_at",
    )
    .bind(request.ceremony_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((account_id, state_json, expires_at)) = row else {
        return Err(ApiError::BadRequest {
            message: "The passkey request is missing or was already used.".to_string(),
        });
    };
    if expires_at <= Utc::now() {
        return Err(ApiError::BadRequest {
            message: "The passkey request expired.".to_string(),
        });
    }
    let ceremony: AuthenticationState =
        serde_json::from_value(state_json).map_err(internal_json)?;
    reject_prf_secret(&request.credential)?;
    let credential: PublicKeyCredential =
        serde_json::from_value(request.credential).map_err(|_| ApiError::BadRequest {
            message: "The passkey authentication response is malformed.".to_string(),
        })?;
    let result = service
        .webauthn
        .finish_passkey_authentication(&credential, &ceremony.webauthn)
        .map_err(webauthn_error)?;
    let credential_id = result.cred_id().as_ref().to_vec();
    let row = sqlx::query_as::<_, (Uuid, Value, bool, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>)>(
        "SELECT id, credential, prf_supported, wrapped_key, wrap_nonce, prf_salt
           FROM passkey_credential
          WHERE account_id = $1 AND credential_id = $2",
    )
    .bind(account_id)
    .bind(&credential_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((stored_id, stored_json, prf_supported, passkey_wrapped, passkey_nonce, prf_salt)) =
        row
    else {
        return Err(ApiError::InvalidCredentials);
    };
    let mut stored: Passkey = serde_json::from_value(stored_json).map_err(internal_json)?;
    stored.update_credential(&result);
    sqlx::query(
        "UPDATE passkey_credential
            SET credential = $1, sign_count = $2, last_used = now()
          WHERE id = $3",
    )
    .bind(serde_json::to_value(&stored).map_err(internal_json)?)
    .bind(i64::from(result.counter()))
    .bind(stored_id)
    .execute(&state.db)
    .await?;

    let recovery_approved =
        auth::verify_recovery_approval(&state, account_id, request.recovery_auth_key.as_deref())
            .await?;
    let (slot_kind, wrapped_key, nonce, response_prf_salt) = if prf_supported
        && request.prf_result_present
    {
        (
            "passkey".to_string(),
            passkey_wrapped.ok_or_else(slot_missing)?,
            passkey_nonce.ok_or_else(slot_missing)?,
            Some(B64.encode(prf_salt)),
        )
    } else if recovery_approved {
        let recovery = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT wrapped_key, wrap_nonce FROM key_slot
              WHERE account_id = $1 AND type = 'recovery'",
        )
        .bind(account_id)
        .fetch_one(&state.db)
        .await?;
        ("recovery".to_string(), recovery.0, recovery.1, None)
    } else {
        return Err(ApiError::BadRequest {
            message: "This passkey provider did not return PRF key material. Use the account password or recovery phrase.".to_string(),
        });
    };

    let login = auth::LoginRequest {
        email: String::new(),
        auth_key: String::new(),
        device_name: request.device_name,
        device_platform: request.device_platform,
        device_approval_token: request.device_approval_token,
        recovery_auth_key: request.recovery_auth_key,
    };
    let (_, tokens) =
        auth::register_device_and_issue_session(&state, account_id, &login, recovery_approved)
            .await?;
    Ok(Json(FinishAuthenticationResponse {
        access_token: tokens.access,
        refresh_token: tokens.refresh,
        access_expires_at: tokens.access_expires_at,
        slot_kind,
        wrapped_key: B64.encode(wrapped_key),
        nonce: B64.encode(nonce),
        prf_salt: response_prf_salt,
    }))
}

#[derive(Clone)]
struct StoredPasskey {
    passkey: Passkey,
    credential_id: Vec<u8>,
    prf_salt: Vec<u8>,
}

async fn load_passkeys(state: &SharedState, account_id: Uuid) -> ApiResult<Vec<Passkey>> {
    Ok(load_passkey_rows(state, account_id)
        .await?
        .into_iter()
        .map(|row| row.passkey)
        .collect())
}

async fn load_passkey_rows(state: &SharedState, account_id: Uuid) -> ApiResult<Vec<StoredPasskey>> {
    let rows = sqlx::query_as::<_, (Value, Vec<u8>, Vec<u8>)>(
        "SELECT credential, credential_id, prf_salt
           FROM passkey_credential WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_all(&state.db)
    .await?;
    rows.into_iter()
        .map(|(value, credential_id, prf_salt)| {
            Ok(StoredPasskey {
                passkey: serde_json::from_value(value).map_err(internal_json)?,
                credential_id,
                prf_salt,
            })
        })
        .collect()
}

async fn consume_ceremony(
    state: &SharedState,
    ceremony_id: Uuid,
    account_id: Uuid,
    kind: &str,
) -> ApiResult<Value> {
    let row = sqlx::query_as::<_, (Value, DateTime<Utc>)>(
        "DELETE FROM passkey_ceremony
          WHERE id = $1 AND account_id = $2 AND kind = $3
          RETURNING state, expires_at",
    )
    .bind(ceremony_id)
    .bind(account_id)
    .bind(kind)
    .fetch_optional(&state.db)
    .await?;
    let Some((state, expires_at)) = row else {
        return Err(ApiError::BadRequest {
            message: "The passkey request is missing or was already used.".to_string(),
        });
    };
    if expires_at <= Utc::now() {
        return Err(ApiError::BadRequest {
            message: "The passkey request expired.".to_string(),
        });
    }
    Ok(state)
}

fn add_registration_prf(options: &mut Value, salt: &[u8]) -> ApiResult<()> {
    let public_key = options
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ApiError::Other(anyhow::anyhow!("WebAuthn options have no publicKey")))?;
    let extensions = public_key.entry("extensions").or_insert_with(|| json!({}));
    extensions["prf"] = json!({ "eval": { "first": B64.encode(salt) } });
    Ok(())
}

fn add_authentication_prf(options: &mut Value, rows: &[StoredPasskey]) -> ApiResult<()> {
    let by_credential = rows
        .iter()
        .map(|row| {
            (
                B64.encode(&row.credential_id),
                json!({ "first": B64.encode(&row.prf_salt) }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let public_key = options
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ApiError::Other(anyhow::anyhow!("WebAuthn options have no publicKey")))?;
    let extensions = public_key.entry("extensions").or_insert_with(|| json!({}));
    extensions["prf"] = json!({ "evalByCredential": by_credential });
    Ok(())
}

fn configured(state: &SharedState) -> ApiResult<&PasskeyService> {
    state
        .passkeys
        .as_ref()
        .ok_or_else(|| ApiError::FeatureUnavailable {
            message: "Passkeys are disabled until the production domain is configured.".to_string(),
        })
}

async fn authenticated(
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

fn decode_optional_slot(
    prf_supported: bool,
    wrapped_key: Option<&str>,
    nonce: Option<&str>,
) -> ApiResult<OptionalWrappedSlot> {
    if !prf_supported {
        if wrapped_key.is_some() || nonce.is_some() {
            return Err(ApiError::BadRequest {
                message: "A passkey without PRF support cannot include a passkey key slot."
                    .to_string(),
            });
        }
        return Ok((None, None));
    }
    let wrapped = B64
        .decode(wrapped_key.unwrap_or_default())
        .map_err(|_| invalid_slot())?;
    let nonce = B64
        .decode(nonce.unwrap_or_default())
        .map_err(|_| invalid_slot())?;
    if wrapped.len() != WRAPPED_KEY_BYTES || nonce.len() != WRAP_NONCE_BYTES {
        return Err(invalid_slot());
    }
    Ok((Some(wrapped), Some(nonce)))
}

fn registration_transports(credential: &Value) -> Vec<String> {
    credential
        .pointer("/response/transports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn registration_prf_supported(credential: &Value) -> bool {
    credential
        .pointer("/clientExtensionResults/prf/enabled")
        .or_else(|| credential.pointer("/extensions/prf/enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn reject_prf_secret(credential: &Value) -> ApiResult<()> {
    let contains_secret = [
        "/clientExtensionResults/prf/results/first",
        "/clientExtensionResults/prf/results/second",
        "/extensions/prf/results/first",
        "/extensions/prf/results/second",
    ]
    .iter()
    .any(|pointer| credential.pointer(pointer).is_some());
    if contains_secret {
        return Err(ApiError::BadRequest {
            message:
                "Remove the PRF result from the WebAuthn response before sending it to the server."
                    .to_string(),
        });
    }
    Ok(())
}

fn random_bytes(length: usize) -> ApiResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes)
        .map_err(|error| ApiError::Other(anyhow::anyhow!("random generation failed: {error}")))?;
    Ok(bytes)
}

fn webauthn_error(error: WebauthnError) -> ApiError {
    tracing::warn!(%error, "WebAuthn ceremony rejected");
    ApiError::BadRequest {
        message: "The passkey response could not be verified.".to_string(),
    }
}

fn internal_json(error: serde_json::Error) -> ApiError {
    ApiError::Other(anyhow::anyhow!("passkey state encoding failed: {error}"))
}

fn invalid_slot() -> ApiError {
    ApiError::BadRequest {
        message: "The passkey key slot has an invalid length or encoding.".to_string(),
    }
}

fn slot_missing() -> ApiError {
    ApiError::Other(anyhow::anyhow!("a PRF passkey has no stored key slot"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_rejects_a_prf_secret() {
        let credential = json!({
            "clientExtensionResults": {
                "prf": {"results": {"first": "secret"}}
            }
        });
        assert!(reject_prf_secret(&credential).is_err());
    }

    #[test]
    fn a_stripped_assertion_is_accepted_by_the_prf_guard() {
        let credential = json!({"clientExtensionResults": {"prf": {}}});
        assert!(reject_prf_secret(&credential).is_ok());
    }

    #[test]
    fn registration_reads_the_prf_support_result() {
        let credential = json!({
            "clientExtensionResults": {"prf": {"enabled": true}}
        });
        assert!(registration_prf_supported(&credential));
        assert!(!registration_prf_supported(&json!({})));
    }

    #[test]
    fn a_passkey_slot_has_exact_lengths() {
        let wrapped = B64.encode([0; WRAPPED_KEY_BYTES]);
        let nonce = B64.encode([0; WRAP_NONCE_BYTES]);
        assert!(decode_optional_slot(true, Some(&wrapped), Some(&nonce)).is_ok());
        assert!(decode_optional_slot(true, Some("short"), Some(&nonce)).is_err());
    }
}
