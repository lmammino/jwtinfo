use biscuit::Compact;
use serde_json::Value;
use winnow::{
    combinator::{alt, eof, terminated},
    token::take_while,
    Parser,
};

use crate::jw_error::{JwtParseError, ParseError};
use crate::jwe::jwe_handler::JweToken;
use crate::jws::JwsToken;

/// The result of parsing a token: either a JWS (3 parts) or a JWE (5 parts).
#[derive(Debug, PartialEq, Eq)]
pub enum JWToken {
    /// A signed JWS token (header.payload.signature).
    Jws(JwsToken),
    /// An encrypted JWE token (header.key.iv.ciphertext.tag).
    Jwe(JweToken),
}

/// Returns `true` for characters allowed in a Base64url segment (RFC 7515).
fn is_base64url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// A non-empty Base64url segment (RFC 7515 §2).
fn b64url<'s>(input: &mut &'s str) -> winnow::Result<&'s str> {
    take_while(1.., is_base64url_char).parse_next(input)
}

/// A Base64url segment that may be empty. Required for the unsecured-JWT
/// signature (`alg: none`, RFC 7518 §3.6) and the `dir` encrypted key
/// (RFC 7518 §4.5); also used for the JWE iv/ciphertext/tag segments, which
/// are validated by the content-encryption layer rather than the grammar.
fn b64url_or_empty<'s>(input: &mut &'s str) -> winnow::Result<&'s str> {
    take_while(0.., is_base64url_char).parse_next(input)
}

/// Compact token classification. The caller already owns the input; the
/// grammar only needs to tell the decoder which shape it validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A 3-segment JWS (header.payload.signature).
    Jws,
    /// A 5-segment JWE (header.encrypted-key.iv.ciphertext.tag).
    Jwe,
}

/// `JWS-Compact = BASE64URL(header) '.' BASE64URL(payload) '.' BASE64URL(signature)`
/// where the signature segment is empty for unsecured JWTs (RFC 7518 §3.6).
fn jws_shape(input: &mut &str) -> winnow::Result<Shape> {
    (b64url, ".", b64url_or_empty, ".", b64url_or_empty)
        .value(Shape::Jws)
        .parse_next(input)
}

/// `JWE-Compact = BASE64URL(header) '.' BASE64URL(encrypted key) '.' ...`
/// where the encrypted-key segment is empty for `dir` (RFC 7518 §4.5).
fn jwe_shape(input: &mut &str) -> winnow::Result<Shape> {
    (
        b64url,
        ".",
        b64url_or_empty, // encrypted key: empty for `dir`
        ".",
        b64url_or_empty, // initialization vector
        ".",
        b64url_or_empty, // ciphertext
        ".",
        b64url_or_empty, // authentication tag
    )
        .value(Shape::Jwe)
        .parse_next(input)
}

/// Both alternatives failed: classify the failure by re-scanning the raw
/// input, since backtracking discards how many parts were found.
fn classify(raw: &str) -> JwtParseError {
    if raw.chars().all(|c| c == '.' || is_base64url_char(c)) {
        let parts = raw.split('.').count();
        if parts == 3 || parts == 5 {
            // The shape was right, but a required segment was empty.
            JwtParseError::InvalidSegment
        } else {
            JwtParseError::WrongPartCount { found: parts }
        }
    } else {
        JwtParseError::InvalidSegment
    }
}

/// Decodes one part of a grammar-validated compact token into a JSON value:
/// biscuit base64url-decodes the segment, we handle UTF-8 and JSON.
fn decode_json_part(compact: &Compact, index: usize) -> Result<Value, ParseError> {
    let bytes = compact
        .part::<Vec<u8>>(index)
        .map_err(|e| ParseError::InvalidBase64(e.to_string()))?;
    let s = String::from_utf8(bytes)?;
    Ok(serde_json::from_str(&s)?)
}

/// Decodes a grammar-validated JWS into a [`JwsToken`], using biscuit to
/// split the compact form and base64url-decode its parts.
fn decode_jws(raw: &str) -> Result<JWToken, JwtParseError> {
    let compact = Compact::decode(raw);
    let header = decode_json_part(&compact, 0).map_err(JwtParseError::InvalidHeader)?;
    let body = decode_json_part(&compact, 1).map_err(JwtParseError::InvalidBody)?;
    let signature = compact
        .part::<Vec<u8>>(2)
        .map_err(|e| JwtParseError::InvalidSignature(ParseError::InvalidBase64(e.to_string())))?;
    Ok(JWToken::Jws(JwsToken {
        header,
        body,
        signature,
    }))
}

/// Decodes a grammar-validated JWE into a [`JweToken`]: `JweToken::new`
/// derives every part from the raw string, with biscuit doing the split.
fn decode_jwe(raw: &str) -> Result<JWToken, JwtParseError> {
    Ok(JWToken::Jwe(JweToken::new(raw)?))
}

/// Parses a JWS or JWE token from a string.
///
/// The grammar checks the compact token's alphabet and 3/5-segment shape;
/// biscuit decodes the segments. Algorithm-specific JWE validation happens
/// during decryption. This parser does not verify JWS signatures or claims.
#[deprecated(
    since = "0.7.0",
    note = "jwtinfo is being repositioned as a CLI tool and its parsing API is in maintenance mode; \
            for library JWT parsing, use biscuit or some other JWT library (check https://jwt.io for suggestions)"
)]
pub fn parse_token(token_str: &str) -> Result<JWToken, JwtParseError> {
    let raw = token_str.trim();
    let mut input = raw;
    // `eof` is essential: without it the JWS shape would match the prefix of
    // a longer input and leave the rest unconsumed.
    let shape = terminated(alt((jwe_shape, jws_shape)), eof)
        .parse_next(&mut input)
        .map_err(|_| classify(raw))?;
    match shape {
        Shape::Jws => decode_jws(raw),
        Shape::Jwe => decode_jwe(raw),
    }
}

/// Parses a JWE token, returning an error if the input is a JWS instead.
#[deprecated(
    since = "0.7.0",
    note = "jwtinfo is being repositioned as a CLI tool and its parsing API is in maintenance mode; \
            for library JWT parsing, use biscuit or some other JWT library (check https://jwt.io for suggestions)"
)]
#[allow(deprecated)]
pub fn parse_jwe(token_str: &str) -> Result<JweToken, JwtParseError> {
    match parse_token(token_str)? {
        JWToken::Jwe(j) => Ok(j),
        JWToken::Jws(_) => Err(JwtParseError::NotAJwe),
    }
}

/// Test-support helpers: unwrap a specific `JWToken` variant. The panicking
/// arms are exercised by `expect_jws_rejects_a_jwe` and
/// `expect_jwe_rejects_a_jws`, so coverage tools see both arms of each match
/// instead of an uncovered `let ... else { panic!() }` region per test.
#[cfg(test)]
impl JWToken {
    fn expect_jws(self) -> JwsToken {
        match self {
            JWToken::Jws(t) => t,
            other => panic!("expected a JWS token, got {other:?}"),
        }
    }

    fn expect_jwe(self) -> JweToken {
        match self {
            JWToken::Jwe(j) => j,
            other => panic!("expected a JWE token, got {other:?}"),
        }
    }
}

#[cfg(test)]
#[allow(deprecated)] // the tests exercise the deprecated library API deliberately
mod test;
