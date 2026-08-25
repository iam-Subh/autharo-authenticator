//! The error shape from section 13.
//!
//! Every failure leaves through here, which is what keeps the enumeration
//! rules in section 9.5 honest: a handler cannot accidentally return a
//! different status or a more specific message for an address that exists.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{message}")]
    BadRequest { message: String },

    /// Deliberately vague, and always the same for a wrong address and a wrong
    /// key. Saying which was wrong would answer the question that section 9.5
    /// exists to refuse.
    #[error("the email address or password is not correct")]
    InvalidCredentials,

    #[error("authentication is required")]
    Unauthorized,

    #[error("an existing device must approve this sign-in")]
    DeviceApprovalRequired,

    #[error("this session does not permit that action")]
    InsufficientScope,
    #[error("enter the account password to authorize this action")]
    ElevationRequired,
    #[error("the requested permission is not available")]
    InvalidScope,
    #[error("the temporary authorization has expired")]
    CapabilityExpired,

    #[error("{message}")]
    FeatureUnavailable { message: String },

    #[error("{message}")]
    Conflict { message: String },

    /// Section 10.6: the cursor points into a range of changes that no longer
    /// exists, so only a full re-sync is correct.
    ///
    /// Its own status, not a `Conflict`. The client has to act on this and on
    /// nothing else that way, and the two are not distinguishable by a status
    /// of 409 — which "this email is already registered" also returns, under
    /// the same `conflict` code. A client left to tell them apart by the
    /// message string either re-syncs when it should not, or loops forever on
    /// a cursor it can never advance.
    #[error("{message}")]
    CursorTooOld { message: String },

    /// Section 9.5's sign-in rate limit. Carries when another attempt could
    /// succeed, which section 13 requires as a `Retry-After` header.
    #[error("too many sign-in attempts. Try again in {retry_after} seconds.")]
    RateLimited { retry_after: i64 },

    /// NFR-11. The message names the limit, because a user who has hit one
    /// needs to know which.
    #[error("{message}")]
    QuotaExceeded { message: String },

    #[error("the request was too large")]
    TooLarge,

    /// A resource that is not on the caller's account.
    ///
    /// Deliberately the same answer for "no such device" and "someone else's
    /// device". Distinguishing them would turn every endpoint that takes an
    /// identifier into a way of asking whether that identifier exists.
    #[error("{message}")]
    NotFound { message: String },

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest { .. } => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::DeviceApprovalRequired => (StatusCode::FORBIDDEN, "device_approval_required"),
            Self::InsufficientScope => (StatusCode::FORBIDDEN, "insufficient_scope"),
            Self::ElevationRequired => (StatusCode::FORBIDDEN, "elevation_required"),
            Self::InvalidScope => (StatusCode::BAD_REQUEST, "invalid_scope"),
            Self::CapabilityExpired => (StatusCode::UNAUTHORIZED, "capability_expired"),
            Self::FeatureUnavailable { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "feature_unavailable")
            }
            Self::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),
            Self::CursorTooOld { .. } => (StatusCode::GONE, "cursor_too_old"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::QuotaExceeded { .. } => (StatusCode::FORBIDDEN, "quota_exceeded"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found"),
            Self::Database(_) | Self::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();

        // An internal error's detail is logged, never returned. A database
        // message can name a table, a column, or a constraint, and a
        // constraint name here would say whether an account exists.
        let message = match &self {
            Self::Database(inner) => {
                tracing::error!(error = %inner, "database error");
                "something went wrong".to_string()
            }
            Self::Other(inner) => {
                tracing::error!(error = %inner, "internal error");
                "something went wrong".to_string()
            }
            other => other.to_string(),
        };

        let mut response =
            (status, Json(json!({ "error": code, "message": message }))).into_response();

        // Section 13. Without it a client has to guess, and a client that
        // guesses short comes straight back to be refused again — which is the
        // traffic the limit exists to stop.
        if let Self::RateLimited { retry_after } = &self
            && let Ok(value) = retry_after.to_string().parse()
        {
            response.headers_mut().insert("retry-after", value);
        }

        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
