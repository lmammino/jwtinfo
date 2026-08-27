use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use serde_json::Value;
use std::sync::OnceLock;
use winnow::{
    combinator::separated,
    error::{StrContext, StrContextValue},
    token::take_while,
    Parser,
};

use crate::jw_error::{JwtParseError, ParseError};
use crate::jwe::jwe_handler::JweToken;
use crate::jws::JwsToken;

static BASE64_ENGINE: OnceLock<engine::GeneralPurpose> = OnceLock::new();

#[inline]
pub fn get_base64() -> &'static engine::GeneralPurpose {
    BASE64_ENGINE
        .get_or_init(|| engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD))
}

#[doc(hidden)]
fn parse_base64_string(string_to_parse: &str) -> Result<String, ParseError> {
    let bytes = get_base64().decode(string_to_parse)?;
    let string = String::from_utf8(bytes)?;
    Ok(string)
}

#[derive(Debug, PartialEq, Eq)]
pub enum JWToken {
    Jws(JwsToken),
    Jwe(JweToken),
}

fn is_base64url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn segment<'s>(input: &mut &'s str) -> winnow::Result<&'s str> {
    take_while(1.., is_base64url_char)
        .context(StrContext::Expected(StrContextValue::Description(
            "base64url segment",
        )))
        .parse_next(input)
}

fn decode_json(b64: &str) -> Result<Value, ParseError> {
    let s = parse_base64_string(b64)?;
    Ok(serde_json::from_str(&s)?)
}

pub fn parse_token(token_str: &str) -> Result<JWToken, JwtParseError> {
    let mut input = token_str.trim();
    let parts: Vec<&str> = separated(1.., segment, '.')
        .context(StrContext::Expected(StrContextValue::Description(
            "JWS (h.p.s) or JWE (h.k.iv.c.t)",
        )))
        .parse_next(&mut input)
        .map_err(|_| JwtParseError::InvalidSegment)?;
    if !input.is_empty() {
        return Err(JwtParseError::InvalidSegment);
    }

    match parts.as_slice() {
        [header, payload, signature] => {
            let header = decode_json(header).map_err(JwtParseError::InvalidHeader)?;
            let body = decode_json(payload).map_err(JwtParseError::InvalidBody)?;
            let signature = get_base64()
                .decode(signature)
                .map_err(|e| JwtParseError::InvalidSignature(ParseError::InvalidBase64(e)))?;
            Ok(JWToken::Jws(JwsToken {
                header,
                body,
                signature,
            }))
        }
        [b64_header, b64_key, b64_iv, b64_cipher, b64_tag] => {
            let header =
                parse_base64_string(b64_header).map_err(|_| JwtParseError::InvalidSegment)?;
            let dec = |s: &str| {
                get_base64()
                    .decode(s)
                    .map_err(|_| JwtParseError::InvalidSegment)
            };
            Ok(JWToken::Jwe(JweToken::new(
                header,
                b64_header.as_bytes().to_vec(),
                dec(b64_key)?,
                dec(b64_iv)?,
                dec(b64_cipher)?,
                dec(b64_tag)?,
            )))
        }
        other => Err(JwtParseError::WrongPartCount { found: other.len() }),
    }
}

pub fn parse_jwe(token_str: &str) -> Result<JweToken, JwtParseError> {
    match parse_token(token_str)? {
        JWToken::Jwe(j) => Ok(j),
        JWToken::Jws(_) => Err(JwtParseError::WrongPartCount { found: 3 }),
    }
}

#[cfg(test)]
mod test;
