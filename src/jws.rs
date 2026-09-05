//! # JWS
//!
//! `jws` is a collection of utilities to parse JWSs (Json Web Signatures),
//! the three-part signed JWTs (header.payload.signature)
//!
//! > **Deprecation notice (0.7.0):** jwtinfo is being repositioned as a CLI
//! > tool and this parsing API is deprecated and in maintenance mode. It
//! > remains functional, but it will not gain new features and may be
//! > removed in a future release. For library JWT parsing, use
//! > [`biscuit`](https://crates.io/crates/biscuit) or some other JWT
//! > library ([check jwt.io for
//! > suggestions](https://jwt.io/libraries)).
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
//!     assert_eq!(token.body.to_string(), "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
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
//! assert_eq!(token.body.to_string(), "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
//! ```

use std::str;

use crate::jw_error::JwtParseError;
// The CLI-oriented internals below consume the deprecated parsing API.
#[allow(deprecated)]
use crate::jw_parser::parse_token;
use crate::jw_parser::JWToken;

/// Represents a JWS, composed by a header, a body and a signature
#[derive(Debug, PartialEq, Eq)]
pub struct JwsToken {
    /// the header part of the token
    pub header: serde_json::Value,
    /// the body (or payload) of the token
    pub body: serde_json::Value,
    /// the signature data of the token
    pub signature: Vec<u8>,
}

impl str::FromStr for JwsToken {
    type Err = JwtParseError;

    // Delegates to the deprecated `parse` to keep the trait working for
    // existing callers; the trait impl itself cannot carry a deprecation.
    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Parses a token from a string.
///
/// For a JWS token, the header and body are decoded and the signature is kept
/// as bytes. JWE inputs are rejected with [`JwtParseError::NotAJws`]; use
/// [`crate::jw_parser::parse_token`] to inspect either token type.
///
/// # Errors
///
/// This function will return a `JwtParseError` if the token cannot be successfully parsed.
#[deprecated(
    since = "0.7.0",
    note = "jwtinfo is being repositioned as a CLI tool and its parsing API is in maintenance mode; \
            for library JWT parsing, use biscuit or some other JWT library (check https://jwt.io for suggestions)"
)]
#[allow(deprecated)] // delegates to the deprecated parse_token
pub fn parse<T: AsRef<str>>(token: T) -> Result<JwsToken, JwtParseError> {
    let token = token.as_ref();
    match parse_token(token)? {
        JWToken::Jws(t) => Ok(t),
        JWToken::Jwe(_) => Err(JwtParseError::NotAJws),
    }
}

#[cfg(test)]
#[allow(deprecated)] // the tests exercise the deprecated library API deliberately
mod test;
