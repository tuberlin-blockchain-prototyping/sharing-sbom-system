use actix_web::{HttpResponse, ResponseError};
use std::fmt;

#[derive(Debug)]
pub enum Error {
    InvalidProof(String),
    VerificationFailed(String),
    DeserializationFailed(String),
    InvalidImageId(String),
    InternalError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            Error::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Error::DeserializationFailed(msg) => write!(f, "Deserialization failed: {}", msg),
            Error::InvalidImageId(msg) => write!(f, "Invalid image ID: {}", msg),
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            Error::InvalidProof(_) | Error::VerificationFailed(_) | Error::DeserializationFailed(_) | Error::InvalidImageId(_) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            Error::InternalError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        HttpResponse::build(status).json(serde_json::json!({
            "error": self.to_string()
        }))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

