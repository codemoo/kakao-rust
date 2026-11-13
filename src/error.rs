use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("state conflict: {0}")]
    Conflict(String),
    #[error("authentication required or credential invalid")]
    Unauthorized,
    #[error("scope or room access denied")]
    Forbidden,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("resource not found")]
    NotFound,
    #[error("private storage: {0}")]
    Storage(String),
    #[error("database failure")]
    Database(#[from] rusqlite::Error),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    QrAuth(#[from] crate::qr_auth::AuthError),
    #[error("API capacity reached")]
    Busy,
    #[error("content unavailable: {0}")]
    Unavailable(&'static str),
    #[error("service unavailable: {0}")]
    ServiceUnavailable(&'static str),
    #[error("internal worker failure")]
    Worker,
}
pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Invalid(_) | Self::Json(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid request or cursor",
            ),
            Self::Conflict(_) => (StatusCode::CONFLICT, "state_conflict", "Conflicting state"),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required or credential invalid",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Scope or room access denied",
            ),
            Self::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
                "API capacity reached; retry later",
            ),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "Method not allowed",
            ),
            Self::Database(rusqlite::Error::SqliteFailure(ref error, _))
                if error.code == rusqlite::ErrorCode::OperationInterrupted =>
            {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "query_timeout",
                    "Search exceeded its time budget; narrow the query",
                )
            }
            Self::Unavailable(code) => (StatusCode::BAD_GATEWAY, code, "Attachment unavailable"),
            Self::ServiceUnavailable(code) => {
                (StatusCode::SERVICE_UNAVAILABLE, code, "Service unavailable")
            }
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "Resource not found"),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal storage error",
            ),
        };
        let mut response = (
            status,
            Json(json!({"error":{"code":code,"message":message}})),
        )
            .into_response();
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

pub(crate) fn valid_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "{label} must be 1..256 UTF-8 bytes without control characters"
        )));
    }
    Ok(())
}
