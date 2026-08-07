use std::{str, string};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    /// Indicates that a given section was not correctly Base64-encoded
    #[error("Base64 error, {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    /// Indicates that a section did not contain a valid utf8 string
    #[error("UTF8 error, {0}")]
    InvalidStrUtf8(#[from] str::Utf8Error),
    #[error("UTF8 error, {0}")]
    InvalidStringUtf8(#[from] string::FromUtf8Error),
}

/// Represents an error while parsing a JWT
#[derive(Debug, Error)]
pub enum JWTParseError {
    /// Indicates that an expected section (Header, Body or Signature) was not found
    #[error("Missing token section")]
    MissingSection,
    #[error("{0}")]
    InvalidFormat(#[from] ParseError),
    /// Indicates that a given section did not contain a valid JSON string
    #[error("JSON error, {0}")]
    InvalidJSON(#[from] serde_json::error::Error),
}

impl From<base64::DecodeError> for JWTParseError {
    fn from(err: base64::DecodeError) -> JWTParseError {
        JWTParseError::InvalidFormat(ParseError::InvalidBase64(err))
    }
}

/// Represents an error while parsing a given part of a JWT
#[derive(Debug, Error)]
pub enum JWTParsePartError {
    /// Error while parsing the Header part
    #[error("Invalid Header: {0}")]
    Header(JWTParseError),
    /// Error while parsing the Body part
    #[error("Invalid Body: {0}")]
    Body(JWTParseError),
    /// Error while parsing the Signature part
    #[error("Invalid Signature: {0}")]
    Signature(JWTParseError),
    /// Error because an additional part was found after the Signature part
    #[error("Error: Unexpected fragment after signature")]
    UnexpectedPart(),
}

#[derive(Debug, Error)]
pub enum JweParseError {
    #[error("Missing JWE section")]
    MissingParts,
    #[error("Unexpected section")]
    TooManyParts,
    #[error("{0}")]
    InvalidFormat(#[from] ParseError),
}

impl From<base64::DecodeError> for JweParseError {
    fn from(err: base64::DecodeError) -> JweParseError {
        JweParseError::InvalidFormat(ParseError::InvalidBase64(err))
    }
}

#[derive(Debug, Error)]
pub enum JweError {
    #[error("{0}")]
    ParseError(#[from] JweParseError),
    #[error("not serialized error")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8Error(#[from] string::FromUtf8Error),
    #[error("{0}")]
    Crypto(#[from] JweCryptoError),
}

impl From<ParseError> for JweError {
    fn from(e: ParseError) -> Self {
        JweError::ParseError(JweParseError::InvalidFormat(e))
    }
}

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
