use base64;
use serde::Deserialize;
use std::fmt;
use std::str;

lazy_static! {
    static ref BASE64_CONFIG: base64::Config =
        base64::Config::new(base64::CharacterSet::UrlSafe, false);
}

#[derive(Deserialize, Debug)]
pub struct Header {
    typ: String,
    pub alg: String,
}

#[derive(Debug)]
pub struct Token {
    pub header: Header,
    pub body: String,
    pub signature: Vec<u8>,
}

impl Token {
    pub fn new(header: Header, body: String, signature: Vec<u8>) -> Self {
        Self {
            header,
            body,
            signature,
        }
    }
}

#[derive(Debug)]
pub enum JWTDecodeError {
    MissingSection(String),
    InvalidUtf8(str::Utf8Error),
    InvalidBase64(base64::DecodeError),
    InvalidJSON(serde_json::error::Error),
}

impl fmt::Display for JWTDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JWTDecodeError::MissingSection(s) => {
                write!(f, "{}", format!("Missing token section: {}", s))
            }
            JWTDecodeError::InvalidUtf8(e) => e.fmt(f),
            JWTDecodeError::InvalidBase64(e) => e.fmt(f),
            JWTDecodeError::InvalidJSON(e) => e.fmt(f),
        }
    }
}

impl From<str::Utf8Error> for JWTDecodeError {
    fn from(err: str::Utf8Error) -> JWTDecodeError {
        JWTDecodeError::InvalidUtf8(err)
    }
}

impl From<base64::DecodeError> for JWTDecodeError {
    fn from(err: base64::DecodeError) -> JWTDecodeError {
        JWTDecodeError::InvalidBase64(err)
    }
}

impl From<serde_json::error::Error> for JWTDecodeError {
    fn from(err: serde_json::error::Error) -> JWTDecodeError {
        JWTDecodeError::InvalidJSON(err)
    }
}

fn parse_base64_string(s: &str) -> Result<String, JWTDecodeError> {
    let s = base64::decode_config(s, *BASE64_CONFIG)?;
    let s = str::from_utf8(&s)?;
    Ok(s.to_string())
}

pub fn parse_token(token: &str) -> Result<Token, JWTDecodeError> {
    let mut parts = token.split('.');

    // header
    let header = match parts.next() {
        None => return Err(JWTDecodeError::MissingSection("header".to_string())),
        Some(s) => {
            let header_str = parse_base64_string(s)?;
            serde_json::from_str(&header_str)?
        }
    };

    // body
    let body = match parts.next() {
        None => return Err(JWTDecodeError::MissingSection("body".to_string())),
        Some(s) => parse_base64_string(s)?,
    };

    // signature
    let signature = match parts.next() {
        None => return Err(JWTDecodeError::MissingSection("signature".to_string())),
        Some(s) => base64::decode_config(s, *BASE64_CONFIG)?,
    };

    Ok(Token::new(header, body, signature))
}

#[cfg(test)]
mod test;
