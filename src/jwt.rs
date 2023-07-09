//! # JWT
//!
//! `jwt` is a collection of utilities to parse JWTs (Json Web Tokens)
//!
//! ## Examples
//!
//! To parse a given JWT as a string:
//!
//! ```rust
//! use jwtinfo::{jwt};
//!
//! let token_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//! match jwt::parse(token_str) {
//!   Ok(token) => {
//!     // do something with token
//!     assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
//!     assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
//!   }
//!   Err(e) => panic!(e)
//! }
//! ```
//!
//! Since `jwt::Token` implements `str::FromStr`, you can also do the following:
//!
//! ```rust
//! use jwtinfo::{jwt};
//!
//! let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".parse::<jwt::Token>().unwrap();
//! assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
//! assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
//! ```

use std::error::Error;
use std::fmt;
use std::str;
use std::sync::OnceLock;

use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

static BASE64_ENGINE: OnceLock<engine::GeneralPurpose> = OnceLock::new();

#[inline]
fn get_base64() -> &'static engine::GeneralPurpose {
    BASE64_ENGINE
        .get_or_init(|| engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD))
}

/// Represents a JWT, composed by a header, a body and a signature
#[derive(Debug)]
pub struct Token {
    /// the header part of the token
    pub header: serde_json::Value,
    /// the body (or payload) of the token
    pub body: serde_json::Value,
    /// the signature data of the token
    pub signature: Vec<u8>,
}

impl Token {
    /// Creates a new token from scratch
    fn new(header: serde_json::Value, body: serde_json::Value, signature: Vec<u8>) -> Self {
        Self {
            header,
            body,
            signature,
        }
    }
}

impl str::FromStr for Token {
    type Err = JWTParsePartError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Represents an error while parsing a JWT
#[derive(Debug)]
pub enum JWTParseError {
    /// Indicates that an expected section (Header, Body or Signature) was not found
    MissingSection(),
    /// Indicates that a section did not contain a valid utf8 string
    InvalidUtf8(str::Utf8Error),
    /// Indicates that a given section was not correctly Base64-encoded
    InvalidBase64(base64::DecodeError),
    /// Indicates that a given section did not contain a valid JSON string
    InvalidJSON(serde_json::error::Error),
}

impl fmt::Display for JWTParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JWTParseError::MissingSection() => "Missing token section".to_string(),
            JWTParseError::InvalidUtf8(e) => format!("UTF8 error, {}", e),
            JWTParseError::InvalidBase64(e) => format!("Base64 error, {}", e),
            JWTParseError::InvalidJSON(e) => format!("JSON error, {}", e),
        };
        write!(f, "{}", message)
    }
}

impl From<str::Utf8Error> for JWTParseError {
    fn from(err: str::Utf8Error) -> JWTParseError {
        JWTParseError::InvalidUtf8(err)
    }
}

impl From<base64::DecodeError> for JWTParseError {
    fn from(err: base64::DecodeError) -> JWTParseError {
        JWTParseError::InvalidBase64(err)
    }
}

impl From<serde_json::error::Error> for JWTParseError {
    fn from(err: serde_json::error::Error) -> JWTParseError {
        JWTParseError::InvalidJSON(err)
    }
}

/// Represents an error while parsing a given part of a JWT
#[derive(Debug)]
pub enum JWTParsePartError {
    /// Error while parsing the Header part
    Header(JWTParseError),
    /// Error while parsing the Body part
    Body(JWTParseError),
    /// Error while parsing the Signature part
    Signature(JWTParseError),
    /// Error because an additional part was found after the Signature part
    UnexpectedPart(),
}

impl fmt::Display for JWTParsePartError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JWTParsePartError::Header(e) => format!("Invalid Header: {}", e),
            JWTParsePartError::Body(e) => format!("Invalid Body: {}", e),
            JWTParsePartError::Signature(e) => format!("Invalid Signature: {}", e),
            JWTParsePartError::UnexpectedPart() => {
                "Error: Unexpected fragment after signature".to_string()
            }
        };
        write!(f, "{}", message)
    }
}

impl Error for JWTParsePartError {}

#[doc(hidden)]
fn parse_base64_string(s: &str) -> Result<String, JWTParseError> {
    let s = get_base64().decode(s)?;
    let s = str::from_utf8(&s)?;
    Ok(s.to_string())
}

#[doc(hidden)]
fn parse_header(raw_header: Option<&str>) -> Result<serde_json::Value, JWTParseError> {
    match raw_header {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => {
            let header_str = parse_base64_string(s)?;
            Ok(serde_json::from_str(&header_str)?)
        }
    }
}

#[doc(hidden)]
fn parse_body(raw_body: Option<&str>) -> Result<serde_json::Value, JWTParseError> {
    match raw_body {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => {
            let body_str = parse_base64_string(s)?;
            Ok(serde_json::from_str(&body_str)?)
        }
    }
}

#[doc(hidden)]
fn parse_signature(raw_signature: Option<&str>) -> Result<Vec<u8>, JWTParseError> {
    match raw_signature {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => Ok(get_base64().decode(s)?),
    }
}

/// Parses a token from a string
///
/// # Errors
///
/// This function will return a `JWTParsePartError` if the token cannot be successfully parsed
pub fn parse<T: AsRef<str>>(token: T) -> Result<Token, JWTParsePartError> {
    let mut parts = token.as_ref().split('.');
    let header = parse_header(parts.next()).map_err(JWTParsePartError::Header)?;
    let body = parse_body(parts.next()).map_err(JWTParsePartError::Body)?;
    let signature = parse_signature(parts.next()).map_err(JWTParsePartError::Signature)?;

    if parts.next().is_some() {
        return Err(JWTParsePartError::UnexpectedPart());
    }

    Ok(Token::new(header, body, signature))
}

#[cfg(test)]
mod test;
