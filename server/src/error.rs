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

    #[error("{message}")]
    Conflict { message: String },

    /// NFR-11. The message names the limit, because a user who has hit one
    /// needs to know which.
    #[error("{message}")]
    QuotaExceeded { message: String },

    #[error("the request was too large")]
    TooLarge,

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
            Self::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),
            Self::QuotaExceeded { .. } => (StatusCode::FORBIDDEN, "quota_exceeded"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::Database(_) | Self::Other(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
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

        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
