//! # JWT
//!
//! `jwt` is a collection of utilities to parse JWTs (Json Web Tokens)
//!
//! ## Examples
//!
//! To parse a given JWT as a string:
//!
//! ```rust
//! use jwtinfo::{jws};
//!
//! let token_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//! match jws::parse(token_str) {
//!   Ok(token) => {
//!     // do something with token
//!     assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
//!     assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
//!   }
//!   Err(e) => panic!("{}", e)
//! }
//! ```
//!
//! Since `jws::JwsToken` implements `str::FromStr`, you can also do the following:
//!
//! ```rust
//! use jwtinfo::{jws};
//!
//! let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".parse::<jws::JwsToken>().unwrap();
//! assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
//! assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
//! ```

use serde_json::to_string_pretty;
use std::{error::Error, str};

use base64::Engine as _;

use crate::jw_error::{JWTParseError, JWTParsePartError, ParseError};
use crate::jw_parser::get_base64;

/// Represents a JWT, composed by a header, a body and a signature
#[derive(Debug, PartialEq, Eq)]
pub struct JwsToken {
    /// the header part of the token
    pub header: serde_json::Value,
    /// the body (or payload) of the token
    pub body: serde_json::Value,
    /// the signature data of the token
    #[allow(unused)]
    pub signature: Vec<u8>,
}

impl JwsToken {
    /// Creates a new token from scratch
    fn new(header: serde_json::Value, body: serde_json::Value, signature: Vec<u8>) -> Self {
        Self {
            header,
            body,
            signature,
        }
    }
}

impl str::FromStr for JwsToken {
    type Err = JWTParsePartError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

#[doc(hidden)]
fn parse_base64_string(s: &str) -> Result<String, ParseError> {
    let s = get_base64().decode(s)?;
    let s = str::from_utf8(&s)?;
    Ok(s.to_string())
}

#[doc(hidden)]
fn parse_header_or_body(raw: Option<&str>) -> Result<serde_json::Value, JWTParseError> {
    match raw {
        None => Err(JWTParseError::MissingSection),
        Some(s) => {
            let str = parse_base64_string(s)?;
            Ok(serde_json::from_str(&str)?)
        }
    }
}

#[doc(hidden)]
fn parse_signature(raw_signature: Option<&str>) -> Result<Vec<u8>, JWTParseError> {
    match raw_signature {
        None => Err(JWTParseError::MissingSection),
        Some(s) => Ok(get_base64().decode(s)?),
    }
}

/// Parses a token from a string
///
/// # Errors
///
/// This function will return a `JWTParsePartError` if the token cannot be successfully parsed
pub fn parse<T: AsRef<str>>(token: T) -> Result<JwsToken, JWTParsePartError> {
    let mut parts = token.as_ref().split('.');
    let header = parse_header_or_body(parts.next()).map_err(JWTParsePartError::Header)?; // Check if this is an encrypted JWE token
    if header.get("enc").is_some() {
        // For encrypted tokens (JWE), we cannot read the body without decryption.
        // Return a token with the header and a placeholder message for the body.
        // JWE tokens have 5 parts instead of 3, so we skip validation of the remaining parts.
        Ok(JwsToken::new(
            header,
            serde_json::Value::String(
                "Detected a JWE token but no private key was provided. Please use the -K/--key flag to decrypt it.".to_string(),
            ),
            Vec::new(),
        ))
    } else {
        // Standard JWT token with 3 parts: header.body.signature
        let body = parse_header_or_body(parts.next()).map_err(JWTParsePartError::Body)?;
        let signature = parse_signature(parts.next()).map_err(JWTParsePartError::Signature)?;

        if parts.next().is_some() {
            return Err(JWTParsePartError::UnexpectedPart());
        }

        Ok(JwsToken::new(header, body, signature))
    }
}

pub fn stringify_token(
    jwt_token: JwsToken,
    full_flag: bool,
    should_pretty_print: bool,
    header_flag: bool,
) -> Result<String, Box<dyn Error>> {
    let stringified = if full_flag {
        // Show both header and claims
        let full_output = serde_json::json!({
            "header": jwt_token.header,
            "claims": jwt_token.body
        });
        if should_pretty_print {
            to_string_pretty(&full_output)?
        } else {
            full_output.to_string()
        }
    } else {
        // Show either header or body
        let part = if header_flag {
            jwt_token.header
        } else {
            jwt_token.body
        };
        if should_pretty_print {
            to_string_pretty(&part)?
        } else {
            part.to_string()
        }
    };
    Ok(stringified)
}

#[cfg(test)]
mod test;
