use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use std::{convert::TryInto, sync::OnceLock};

use crate::jw_error::JweParseError;
use crate::jw_error::ParseError;
use crate::jwe::jwe_handler::JweToken;

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

pub fn split_jwe(token: &str) -> Result<[&str; 5], JweParseError> {
    token
        .split(".")
        .collect::<Vec<&str>>()
        .try_into()
        .map_err(|vec: Vec<&str>| {
            if vec.len() < 5 {
                JweParseError::MissingParts()
            } else {
                JweParseError::TooManyParts()
            }
        })
}

pub fn parse_jwe(token: &str) -> Result<JweToken, JweParseError> {
    let [b64_header, b64_key, b64_iv, b64_cipher, b64_tag] = split_jwe(token)?;

    let decode = |s: &str| get_base64().decode(s);

    let aad = b64_header.as_bytes().to_vec();
    let header = parse_base64_string(b64_header)?;
    let key_encrypted = decode(b64_key)?;
    let iv = decode(b64_iv)?;
    let ciphertext = decode(b64_cipher)?;
    let tag = decode(b64_tag)?;

    Ok(JweToken::new(
        header,
        aad,
        key_encrypted,
        iv,
        ciphertext,
        tag,
    ))
}
