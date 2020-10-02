//! # JWT
//!
//! `jwt` is a collection of utilities to parse JWT tokens
//!
//! ## Examples
//!
//! To parse a given JWT token:
//!
//! ```rust
//! use jwtinfo::{jwt};
//!
//! let token_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//! match jwt::parse(token_str) {
//!   Ok(token) => {
//!     // do something with token
//!     assert_eq!(token.header.alg, "HS256");
//!     assert_eq!(token.body, "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
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
//! assert_eq!(token.header.alg, "HS256");
//! assert_eq!(token.body, "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
//! ```

use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::str;

lazy_static! {
    static ref BASE64_CONFIG: base64::Config =
        base64::Config::new(base64::CharacterSet::UrlSafe, false);
}

/// Represents the header part of a JWT token
#[derive(Deserialize, Debug)]
pub struct Header {
    /// the type of token, must be "JWT"
    typ: String,
    /// the signature algorithm used for this token
    pub alg: String,
}

/// Represents a JWT token, composed by a header, a body and a signature
#[derive(Debug)]
pub struct Token {
    /// the header part of the token
    pub header: Header,
    /// the body (or payload) of the token
    pub body: String,
    /// the signature data of the token
    pub signature: Vec<u8>,
}

impl Token {
    /// Creates a new token from scratch
    fn new(header: Header, body: String, signature: Vec<u8>) -> Self {
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

/// Represents an error while parsing a JWT token
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
        match self {
            JWTParseError::MissingSection() => write!(f, "{}", "Missing token section".to_string()),
            JWTParseError::InvalidUtf8(e) => write!(f, "UTF8 error, {}", e),
            JWTParseError::InvalidBase64(e) => write!(f, "Base64 error, {}", e),
            JWTParseError::InvalidJSON(e) => write!(f, "JSON error, {}", e),
        }
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

/// Represents an error while parsing a given part of a JWT token
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
        match self {
            JWTParsePartError::Header(e) => write!(f, "{}", format!("Invalid Header: {}", e)),
            JWTParsePartError::Body(e) => write!(f, "{}", format!("Invalid Body: {}", e)),
            JWTParsePartError::Signature(e) => write!(f, "{}", format!("Invalid Signature: {}", e)),
            JWTParsePartError::UnexpectedPart() => write!(
                f,
                "{}",
                "Error: Unexpected fragment after signature".to_string()
            ),
        }
    }
}

impl Error for JWTParsePartError {}

#[doc(hidden)]
fn parse_base64_string(s: &str) -> Result<String, JWTParseError> {
    let s = base64::decode_config(s, *BASE64_CONFIG)?;
    let s = str::from_utf8(&s)?;
    Ok(s.to_string())
}

#[doc(hidden)]
fn parse_header(raw_header: Option<&str>) -> Result<Header, JWTParseError> {
    match raw_header {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => {
            let header_str = parse_base64_string(s)?;
            Ok(serde_json::from_str::<Header>(&header_str)?)
        }
    }
}

#[doc(hidden)]
fn parse_body(raw_body: Option<&str>) -> Result<String, JWTParseError> {
    match raw_body {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => Ok(parse_base64_string(s)?),
    }
}

#[doc(hidden)]
fn parse_signature(raw_signature: Option<&str>) -> Result<Vec<u8>, JWTParseError> {
    match raw_signature {
        None => Err(JWTParseError::MissingSection()),
        Some(s) => Ok(base64::decode_config(s, *BASE64_CONFIG)?),
    }
}

/// Parses a token from a string
///
/// # Errors
///
/// This function will return a `JWTParsePartError` if the token cannot be successfully parsed
pub fn parse(token: &str) -> Result<Token, JWTParsePartError> {
    let mut parts = token.split('.');
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
