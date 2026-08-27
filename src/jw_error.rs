use std::string;
use thiserror::Error;

/// Low-level decoding errors (Base64, UTF-8, JSON).
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Base64 error, {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("UTF8 error, {0}")]
    InvalidUtf8(#[from] string::FromUtf8Error),
    #[error("JSON error, {0}")]
    InvalidJson(#[from] serde_json::error::Error),
}

/// Errors that can occur while handling a JWE token.
#[derive(Debug, Error)]
pub enum JweError {
    #[error("{0}")]
    Parse(#[from] JwtParseError),
    #[error("not serialized error")]
    Json(#[from] serde_json::Error),
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(#[from] string::FromUtf8Error),
    #[error("{0}")]
    Crypto(#[from] JweCryptoError),
}

/// Errors related to JWE decryption and the underlying crypto operations.
#[derive(Debug, Error)]
pub enum JweCryptoError {
    #[error("CEK length mismatch: expected {expected} bytes, got {actual}")]
    CekLengthMismatch { expected: usize, actual: usize },
    #[error("IV length invalid: expected 12 bytes")]
    InvalidIvLength,
    #[error("Unsupported key length: {0}")]
    UnsupportedKeyLength(usize),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid RSA key: {0}")]
    InvalidRsaKey(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// High-level token parsing errors, indicating which part failed.
#[derive(Debug, Error)]
pub enum JwtParseError {
    #[error("Invalid Header: {0}")]
    InvalidHeader(#[source] ParseError),
    #[error("Invalid Body: {0}")]
    InvalidBody(#[source] ParseError),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(#[source] ParseError),
    #[error("Invalid token: expected 3 parts (JWS) or 5 parts (JWE) but found {found}")]
    WrongPartCount { found: usize },
    #[error("Invalid base64url segment")]
    InvalidSegment,
}
