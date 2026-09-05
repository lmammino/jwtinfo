use biscuit::Compact;
use serde_json::Value;
use winnow::{
    combinator::{alt, eof, terminated},
    error::{StrContext, StrContextValue},
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
    take_while(1.., is_base64url_char)
        .context(StrContext::Expected(StrContextValue::Description(
            "base64url segment",
        )))
        .parse_next(input)
}

/// A Base64url segment that may be empty. Required for the unsecured-JWT
/// signature (`alg: none`, RFC 7518 §3.6) and the `dir` encrypted key
/// (RFC 7518 §4.5); also used for the JWE iv/ciphertext/tag segments, which
/// are validated by the content-encryption layer rather than the grammar.
fn b64url_or_empty<'s>(input: &mut &'s str) -> winnow::Result<&'s str> {
    take_while(0.., is_base64url_char)
        .context(StrContext::Expected(StrContextValue::Description(
            "base64url segment (possibly empty)",
        )))
        .parse_next(input)
}

/// The syntactic shape of a token, mirroring the RFC compact-serialization
/// ABNF. The variant payload is the *whole* token string: the grammar's job
/// is validation and classification, and the segment boundaries are left to
/// biscuit (`Compact::decode`), which splits the validated string once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape<'s> {
    /// A 3-segment JWS (header.payload.signature).
    Jws(&'s str),
    /// A 5-segment JWE (header.encrypted-key.iv.ciphertext.tag).
    Jwe(&'s str),
}

/// `JWS-Compact = BASE64URL(header) '.' BASE64URL(payload) '.' BASE64URL(signature)`
/// where the signature segment is empty for unsecured JWTs (RFC 7518 §3.6).
fn jws_shape<'s>(input: &mut &'s str) -> winnow::Result<Shape<'s>> {
    (b64url, ".", b64url_or_empty, ".", b64url_or_empty)
        .take()
        .map(Shape::Jws)
        .context(StrContext::Label("JWS"))
        .parse_next(input)
}

/// `JWE-Compact = BASE64URL(header) '.' BASE64URL(encrypted key) '.' ...`
/// where the encrypted-key segment is empty for `dir` (RFC 7518 §4.5).
fn jwe_shape<'s>(input: &mut &'s str) -> winnow::Result<Shape<'s>> {
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
        .take()
        .map(Shape::Jwe)
        .context(StrContext::Label("JWE"))
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
/// The token is validated and classified by a grammar mirroring the RFC
/// compact-serialization ABNF — an alternation of the 3-segment JWS shape
/// and the 5-segment JWE shape, anchored at the end of input — and biscuit
/// then splits the validated string once and decodes its parts.
pub fn parse_token(token_str: &str) -> Result<JWToken, JwtParseError> {
    let raw = token_str.trim();
    let mut input = raw;
    // `eof` is essential: without it the JWS shape would match the prefix of
    // a longer input and leave the rest unconsumed.
    let shape = terminated(alt((jwe_shape, jws_shape)), eof)
        .parse_next(&mut input)
        .map_err(|_| classify(raw))?;
    match shape {
        Shape::Jws(raw) => decode_jws(raw),
        Shape::Jwe(raw) => decode_jwe(raw),
    }
}

/// Parses a JWE token, returning an error if the input is a JWS instead.
pub fn parse_jwe(token_str: &str) -> Result<JweToken, JwtParseError> {
    match parse_token(token_str)? {
        JWToken::Jwe(j) => Ok(j),
        JWToken::Jws(_) => Err(JwtParseError::NotAJwe),
    }
}

#[cfg(test)]
mod test;
