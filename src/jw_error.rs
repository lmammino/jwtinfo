use std::{error::Error, fmt, str, string};

#[derive(Debug)]
pub enum ParseError {
    /// Indicates that a given section was not correctly Base64-encoded
    InvalidBase64(base64::DecodeError),
    /// Indicates that a section did not contain a valid utf8 string
    InvalidStrUtf8(str::Utf8Error),
    InvalidStringUtf8(string::FromUtf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            ParseError::InvalidBase64(e) => format!("Base64 error, {}", e),
            ParseError::InvalidStrUtf8(e) => format!("UTF8 error, {}", e),
            ParseError::InvalidStringUtf8(e) => format!("UTF8 error, {}", e),
        };
        write!(f, "{}", message)
    }
}

impl From<base64::DecodeError> for ParseError {
    fn from(err: base64::DecodeError) -> ParseError {
        ParseError::InvalidBase64(err)
    }
}

impl From<str::Utf8Error> for ParseError {
    fn from(err: str::Utf8Error) -> ParseError {
        ParseError::InvalidStrUtf8(err)
    }
}

impl From<string::FromUtf8Error> for ParseError {
    fn from(err: string::FromUtf8Error) -> ParseError {
        ParseError::InvalidStringUtf8(err)
    }
}

impl Error for ParseError {}

/// Represents an error while parsing a JWT
#[derive(Debug)]
pub enum JWTParseError {
    /// Indicates that an expected section (Header, Body or Signature) was not found
    MissingSection(),
    InvalidFormat(ParseError),
    /// Indicates that a given section did not contain a valid JSON string
    InvalidJSON(serde_json::error::Error),
}

impl fmt::Display for JWTParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JWTParseError::MissingSection() => "Missing token section".to_string(),
            JWTParseError::InvalidFormat(e) => format!("{}", e),
            JWTParseError::InvalidJSON(e) => format!("JSON error, {}", e),
        };
        write!(f, "{}", message)
    }
}

impl From<base64::DecodeError> for JWTParseError {
    fn from(err: base64::DecodeError) -> JWTParseError {
        JWTParseError::InvalidFormat(ParseError::InvalidBase64(err))
    }
}

impl From<ParseError> for JWTParseError {
    fn from(err: ParseError) -> JWTParseError {
        JWTParseError::InvalidFormat(err)
    }
}

impl From<serde_json::error::Error> for JWTParseError {
    fn from(err: serde_json::error::Error) -> JWTParseError {
        JWTParseError::InvalidJSON(err)
    }
}

impl Error for JweParseError {}

/// Represents an error while parsing a given part of a JWT
#[derive(Debug)]
pub enum JWTParsePartError {
    /// Error while parsing the Header part
    Header(JWTParseError),
    /// Error while parsing the Body part
    Body(JWTParseError),
    /// Error while parsing the Signature part
    Signature(JWTParseError),
    /// Error because an additional part was found after the Signature part
    UnexpectedPart(),
}

impl fmt::Display for JWTParsePartError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JWTParsePartError::Header(e) => format!("Invalid Header: {}", e),
            JWTParsePartError::Body(e) => format!("Invalid Body: {}", e),
            JWTParsePartError::Signature(e) => format!("Invalid Signature: {}", e),
            JWTParsePartError::UnexpectedPart() => {
                "Error: Unexpected fragment after signature".to_string()
            }
        };
        write!(f, "{}", message)
    }
}

impl Error for JWTParsePartError {}

#[derive(Debug)]
pub enum JweParseError {
    MissingParts(),
    TooManyParts(),
    InvalidFormat(ParseError),
}

impl fmt::Display for JweParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JweParseError::MissingParts() => "Missing JWE section".to_string(),
            JweParseError::TooManyParts() => "Unespected section".to_string(),
            JweParseError::InvalidFormat(e) => format!("{}", e),
        };
        write!(f, "{}", message)
    }
}

impl From<ParseError> for JweParseError {
    fn from(err: ParseError) -> JweParseError {
        JweParseError::InvalidFormat(err)
    }
}

impl From<base64::DecodeError> for JweParseError {
    fn from(err: base64::DecodeError) -> JweParseError {
        JweParseError::InvalidFormat(ParseError::InvalidBase64(err))
    }
}

#[derive(Debug)]
pub enum JweError {
    ParseError(JweParseError),
    StringError(String),
    Internal(Box<dyn Error + Send + Sync + 'static>),
    JsonError(serde_json::Error),
    InvalidUtf8Error(string::FromUtf8Error),
}

impl fmt::Display for JweError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JweError::ParseError(e) => format!("{}", e),
            JweError::StringError(e) => e.to_string(),
            JweError::Internal(e) => e.to_string(),
            JweError::JsonError(_e) => "not serialized error".to_string(),
            JweError::InvalidUtf8Error(e) => format!("Invalid UTF-8 string: {}", e),
        };
        write!(f, "{}", message)
    }
}

impl Error for JweError {}

impl From<JweParseError> for JweError {
    fn from(e: JweParseError) -> Self {
        JweError::ParseError(e)
    }
}

impl From<String> for JweError {
    fn from(e: String) -> Self {
        JweError::StringError(e)
    }
}

impl From<Box<dyn Error + Send + Sync + 'static>> for JweError {
    fn from(e: Box<dyn Error + Send + Sync + 'static>) -> Self {
        JweError::Internal(e)
    }
}

impl From<serde_json::Error> for JweError {
    fn from(e: serde_json::Error) -> Self {
        JweError::JsonError(e)
    }
}

impl From<string::FromUtf8Error> for JweError {
    fn from(e: string::FromUtf8Error) -> Self {
        JweError::InvalidUtf8Error(e)
    }
}

impl From<ParseError> for JweError {
    fn from(e: ParseError) -> Self {
        JweError::ParseError(JweParseError::InvalidFormat(e))
    }
}
