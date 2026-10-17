use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cjs_proto::{ErrorCode, ProtoError};

/// API error with a stable machine code (same codes as the wire protocol).
#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, m: impl Into<String>) -> Self {
        Self {
            code,
            message: m.into(),
        }
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, m)
    }
    pub fn bad(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, m)
    }
    pub fn unauth(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, m)
    }
    pub fn audit() -> Self {
        Self::new(
            ErrorCode::AuditFailure,
            "audit log unavailable; operation refused",
        )
    }
    pub fn proto(&self) -> ProtoError {
        ProtoError::new(self.code, self.message.clone())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(f, _) = &e {
            if f.code == rusqlite::ErrorCode::ConstraintViolation {
                return ApiError::new(ErrorCode::Conflict, format!("conflict: {e}"));
            }
        }
        ApiError::internal(e.to_string())
    }
}

impl From<ProtoError> for ApiError {
    fn from(e: ProtoError) -> Self {
        ApiError::new(e.code, e.message)
    }
}

impl From<cjs_audit::AuditError> for ApiError {
    fn from(e: cjs_audit::AuditError) -> Self {
        tracing::error!(err = %e, "audit append failed");
        ApiError::audit()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code {
            ErrorCode::Unauthenticated | ErrorCode::Expired => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden | ErrorCode::Disabled => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::BadRequest | ErrorCode::Protocol => StatusCode::BAD_REQUEST,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::LimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::AuditFailure | ErrorCode::DeviceOffline => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            axum::Json(serde_json::json!({"error": {"code": self.code.as_str(), "message": self.message}})),
        )
            .into_response()
    }
}
