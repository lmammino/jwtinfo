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
use serde_json::Value;
use std::{error::Error, str};

use crate::jw_error::JwtParseError;
use crate::jw_error::ParseError;
use crate::jw_parser::parse_token;
use crate::jw_parser::JWToken;

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
    type Err = JwtParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Parses a token from a string
///
/// # Errors
///
/// This function will return a `JwtParseError` if the token cannot be successfully parsed
const JWE_PLACEHOLDER: &str = "Detected a JWE token but no private key was provided. Please use the -K/--key flag to decrypt it.";

pub fn parse<T: AsRef<str>>(token: T) -> Result<JwsToken, JwtParseError> {
    let token = token.as_ref();
    match parse_token(token)? {
        JWToken::Jws(t) => Ok(t),
        JWToken::Jwe(jwe) => {
            let header: Value = serde_json::from_str(&jwe.header)
                .map_err(|e| JwtParseError::InvalidHeader(ParseError::InvalidJson(e)))?;
            Ok(JwsToken::new(
                header,
                Value::String(JWE_PLACEHOLDER.to_string()),
                Vec::new(),
            ))
        }
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
