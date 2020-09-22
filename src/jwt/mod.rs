use base64;
use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::str;

lazy_static! {
    static ref BASE64_CONFIG: base64::Config =
        base64::Config::new(base64::CharacterSet::UrlSafe, false);
}

// enum Typ {
//     JWT,
//     // Custom(String),
// }
//
// #[derive(Debug, PartialOrd, PartialEq)]
// struct InvalidInput;
//
// impl str::FromStr for Typ {
//     type Err = InvalidInput;
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "JWT" => Ok(Typ::JWT),
//             "jwt" => Ok(Typ::JWT),
//             _ => Err(InvalidInput),
//         }
//     }
// }

#[derive(Deserialize, Debug)]
pub struct Header {
    typ: String, // Consider add a concrete enum
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
    MissingSection(), // Maybe add index to the beginning and end of the span, e.g. MissingSection(usize),
    //                   which would enable more helpful error messages
    InvalidUtf8(str::Utf8Error),
    InvalidBase64(base64::DecodeError),
    InvalidJSON(serde_json::error::Error),
}

impl fmt::Display for JWTDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use JWTDecodeError::*;

        let (message, argument) = match self {
            MissingSection() => ("Missing token section", ""),
            InvalidUtf8(e) => ("UTF8 error, ", e),
            InvalidBase64(e) => ("Base64 error, ", e),
            InvalidJSON(e) => ("JSON error, ", e),
        };

        write!(f, "{} {}", message, argument);
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
        // match self {
        //     JWTDecodePartError::Header(e) => write!(f, "{}", format!("Invalid Header: {}", e)),
        //     JWTDecodePartError::Body(e) => write!(f, "{}", format!("Invalid Body: {}", e)),
        //     JWTDecodePartError::Signature(e) => {
        //         write!(f, "{}", format!("Invalid Signature: {}", e))
        //     }
        //     JWTDecodePartError::UnexpectedPart() => write!(
        //         f,
        //         "{}",
        //         "Error: Unexpected fragment after signature".to_string()
        //     ),
        // }
        use JWTDecodePartError::*;

        let message = match self {
            Header(e) => format!("Invalid Header: {}", e),
            Body(e) => format!("Invalid Body: {}", e),
            Signature(e) => format!("Invalid Signature: {}", e),
            UnexpectedPart() => "Error: Unexpected fragment after signature".to_string(),
        };

        write!(f, "{}", message)
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

// Consider accepting any type that can act as a &str - <T: AsRef<str>>(token: T)

// Consider retaining the index (line number, character number) of where the error was detected

// Consider adding comments  (and usage examples for public functions)
pub fn parse_token<T: AsRef<str>>(token: T) -> Result<Token, JWTDecodePartError> {
    // abcd.efg.hi
    let mut parts = token.as_ref().split('.');
    let header = parse_header(parts.next()).map_err(JWTDecodePartError::Header)?;
    let body = parse_body(parts.next()).map_err(JWTDecodePartError::Body)?;
    let signature = parse_signature(parts.next()).map_err(JWTDecodePartError::Signature)?;

    // abcd.efg.hi.err
    if parts.next().is_some() {
        return Err(JWTDecodePartError::UnexpectedPart()); // Add the unexpected string?
    }

    Ok(Token::new(header, body, signature))
}


// adding the #[cfg(test] annotation is very useful
#[cfg(test)]
mod test;
