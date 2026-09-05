use std::string;
use thiserror::Error;

/// Low-level decoding errors (Base64, UTF-8, JSON).
///
/// Base64url decoding is delegated to biscuit, so the base64 cause is
/// carried as a pre-formatted message (e.g. `"invalid length at 16"`)
/// rather than a typed error.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Base64 error, {0}")]
    InvalidBase64(String),
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
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(#[from] string::FromUtf8Error),
    #[error("No key provided: use the --key flag to decrypt this JWE")]
    MissingKey,
    #[error("{0}")]
    Crypto(#[from] JweCryptoError),
}

/// Errors related to JWE decryption and the underlying crypto operations.
#[derive(Debug, Error)]
pub enum JweCryptoError {
    #[error("Unsupported JWE header parameter: {0}")]
    UnsupportedHeaderParameter(String),
    #[error("{alg} key length mismatch: expected {expected} bytes, got {actual}")]
    KekLengthMismatch {
        alg: String,
        expected: usize,
        actual: usize,
    },
    #[error("Wrapped CEK length mismatch: expected {expected} bytes, got {actual}")]
    WrappedCekLengthMismatch { expected: usize, actual: usize },
    #[error("CEK length mismatch: expected {expected} bytes, got {actual}")]
    CekLengthMismatch { expected: usize, actual: usize },
    #[error("IV length invalid: expected 12 bytes")]
    InvalidIvLength,
    #[error("Authentication tag length invalid: expected 16 bytes, got {0}")]
    InvalidTagLength(usize),
    #[error("The dir algorithm requires an empty encrypted-key segment")]
    NonEmptyDirectKey,
    #[error("Unsupported key length: {0}")]
    UnsupportedKeyLength(usize),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
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
    #[error("Expected a JWE token (5 parts), but the input is a JWS (3 parts)")]
    NotAJwe,
}
