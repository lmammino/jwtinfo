use serde::Deserialize;
use std::error::Error;
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
    MissingSection(),
    InvalidUtf8(str::Utf8Error),
    InvalidBase64(base64::DecodeError),
    InvalidJSON(serde_json::error::Error),
}

impl fmt::Display for JWTDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JWTDecodeError::MissingSection() => {
                write!(f, "{}", "Missing token section".to_string())
            }
            JWTDecodeError::InvalidUtf8(e) => write!(f, "UTF8 error, {}", e),
            JWTDecodeError::InvalidBase64(e) => write!(f, "Base64 error, {}", e),
            JWTDecodeError::InvalidJSON(e) => write!(f, "JSON error, {}", e),
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

#[derive(Debug)]
pub enum JWTDecodePartError {
    Header(JWTDecodeError),
    Body(JWTDecodeError),
    Signature(JWTDecodeError),
    UnexpectedPart(),
}

impl fmt::Display for JWTDecodePartError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JWTDecodePartError::Header(e) => write!(f, "{}", format!("Invalid Header: {}", e)),
            JWTDecodePartError::Body(e) => write!(f, "{}", format!("Invalid Body: {}", e)),
            JWTDecodePartError::Signature(e) => {
                write!(f, "{}", format!("Invalid Signature: {}", e))
            }
            JWTDecodePartError::UnexpectedPart() => write!(
                f,
                "{}",
                "Error: Unexpected fragment after signature".to_string()
            ),
        }
    }
}

impl Error for JWTDecodePartError {}

fn parse_base64_string(s: &str) -> Result<String, JWTDecodeError> {
    let s = base64::decode_config(s, *BASE64_CONFIG)?;
    let s = str::from_utf8(&s)?;
    Ok(s.to_string())
}

fn parse_header(raw_header: Option<&str>) -> Result<Header, JWTDecodeError> {
    match raw_header {
        None => Err(JWTDecodeError::MissingSection()),
        Some(s) => {
            let header_str = parse_base64_string(s)?;
            Ok(serde_json::from_str::<Header>(&header_str)?)
        }
    }
}

fn parse_body(raw_body: Option<&str>) -> Result<String, JWTDecodeError> {
    match raw_body {
        None => Err(JWTDecodeError::MissingSection()),
        Some(s) => Ok(parse_base64_string(s)?),
    }
}

fn parse_signature(raw_signature: Option<&str>) -> Result<Vec<u8>, JWTDecodeError> {
    match raw_signature {
        None => Err(JWTDecodeError::MissingSection()),
        Some(s) => Ok(base64::decode_config(s, *BASE64_CONFIG)?),
    }
}

pub fn parse_token(token: &str) -> Result<Token, JWTDecodePartError> {
    let mut parts = token.split('.');
    let header = parse_header(parts.next()).map_err(JWTDecodePartError::Header)?;
    let body = parse_body(parts.next()).map_err(JWTDecodePartError::Body)?;
    let signature = parse_signature(parts.next()).map_err(JWTDecodePartError::Signature)?;

    if parts.next().is_some() {
        return Err(JWTDecodePartError::UnexpectedPart());
    }

    Ok(Token::new(header, body, signature))
}

#[cfg(test)]
mod test;
