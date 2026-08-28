//! Firebase identity verification for account registration.
//!
//! Firebase proves control of an email address. It does not receive or unwrap
//! the vault key. The server stores the stable Firebase subject, not the email
//! address, as the external identity identifier.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;

const FIREBASE_JWKS: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const DEFAULT_CACHE_SECONDS: u64 = 300;

#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub subject: String,
    pub email: String,
    pub provider: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity verification is not configured")]
    NotConfigured,
    #[error("the identity token is invalid or expired")]
    Invalid,
    #[error("the email address is not verified")]
    EmailNotVerified,
    #[error("the identity provider keys could not be obtained")]
    KeysUnavailable,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    iat: u64,
    auth_time: u64,
    firebase: Option<FirebaseClaim>,
}

#[derive(Debug, Deserialize)]
struct FirebaseClaim {
    sign_in_provider: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    n: String,
    e: String,
}

struct CachedKeys {
    keys: Vec<Jwk>,
    expires_at: Instant,
}

pub struct FirebaseIdentityVerifier {
    project_id: String,
    client: reqwest::Client,
    cache: RwLock<Option<CachedKeys>>,
}

impl FirebaseIdentityVerifier {
    pub fn from_environment() -> anyhow::Result<Option<Self>> {
        let Ok(project_id) = std::env::var("FIREBASE_AUTH_PROJECT_ID") else {
            return Ok(None);
        };
        let project_id = project_id.trim().to_string();
        if project_id.is_empty()
            || project_id.len() > 128
            || !project_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            anyhow::bail!("FIREBASE_AUTH_PROJECT_ID is invalid");
        }
        Ok(Some(Self {
            project_id,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            cache: RwLock::new(None),
        }))
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedIdentity, IdentityError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(IdentityError::Invalid);
        }
        let header = decode_header(token).map_err(|_| IdentityError::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(IdentityError::Invalid);
        }
        let kid = header.kid.ok_or(IdentityError::Invalid)?;
        let key = self.key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.project_id]);
        validation.set_issuer(&[format!(
            "https://securetoken.google.com/{}",
            self.project_id
        )]);
        validation.leeway = 30;
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| IdentityError::Invalid)?
            .claims;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityError::Invalid)?
            .as_secs();
        if claims.sub.is_empty()
            || claims.sub.len() > 128
            || claims.iat > now.saturating_add(30)
            || claims.auth_time > now.saturating_add(30)
        {
            return Err(IdentityError::Invalid);
        }
        if claims.email_verified != Some(true) {
            return Err(IdentityError::EmailNotVerified);
        }
        let email = claims.email.ok_or(IdentityError::Invalid)?;
        let provider = claims
            .firebase
            .and_then(|value| value.sign_in_provider)
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .unwrap_or_else(|| "firebase".to_string());
        Ok(VerifiedIdentity {
            subject: claims.sub,
            email,
            provider,
        })
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, IdentityError> {
        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache.as_ref()
                && cache.expires_at > Instant::now()
            {
                return cache
                    .keys
                    .iter()
                    .find(|key| key.kid == kid)
                    .ok_or(IdentityError::Invalid)
                    .and_then(decoding_key);
            }
        }

        let response = self
            .client
            .get(FIREBASE_JWKS)
            .send()
            .await
            .map_err(|_| IdentityError::KeysUnavailable)?;
        if !response.status().is_success() {
            return Err(IdentityError::KeysUnavailable);
        }
        let max_age = response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .and_then(cache_max_age)
            .unwrap_or(DEFAULT_CACHE_SECONDS);
        let set: JwkSet = response
            .json()
            .await
            .map_err(|_| IdentityError::KeysUnavailable)?;
        let selected = set
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .map(decoding_key)
            .transpose()?;
        *self.cache.write().await = Some(CachedKeys {
            keys: set.keys,
            expires_at: Instant::now() + Duration::from_secs(max_age.min(86_400)),
        });
        selected.ok_or(IdentityError::Invalid)
    }
}

fn decoding_key(jwk: &Jwk) -> Result<DecodingKey, IdentityError> {
    if jwk.kty != "RSA" || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256") {
        return Err(IdentityError::Invalid);
    }
    DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| IdentityError::Invalid)
}

fn cache_max_age(value: &str) -> Option<u64> {
    value.split(',').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.eq_ignore_ascii_case("max-age")).then(|| value.parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use super::cache_max_age;

    #[test]
    fn cache_control_max_age_is_read() {
        assert_eq!(
            cache_max_age("public, max-age=123, must-revalidate"),
            Some(123)
        );
        assert_eq!(cache_max_age("no-cache"), None);
    }
}
