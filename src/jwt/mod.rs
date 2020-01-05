use base64;
use serde::Deserialize;
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

fn parse_base64_string(s: &str) -> Result<String, String> {
  match base64::decode_config(s, *BASE64_CONFIG) {
    Ok(s) => match str::from_utf8(&s) {
      Ok(s) => Ok(s.to_string()),
      Err(e) => return Err(format!("cannot be decoded to a valid UTF-8 string. {}", e)),
    },
    Err(e) => return Err(format!("is not a valid base64 string. {}", e)),
  }
}

pub fn parse_jwt_token(token: &str) -> Result<Token, String> {
  let parts: Vec<&str> = token.split('.').collect();
  let header_str = match parts.get(0) {
    Some(s) => match parse_base64_string(s) {
      Ok(s) => s,
      Err(e) => return Err(format!("Malformed JWT: Header {}", e)),
    },
    None => return Err("Malformed JWT: Header is missing".to_string()),
  };
  let header: Header = match serde_json::from_str(&header_str) {
    Ok(h) => h,
    Err(e) => return Err(format!("Malformed JWT: Header is not a valid JSON. {}", e)),
  };

  let body = match parts.get(1) {
    Some(s) => match parse_base64_string(s) {
      Ok(s) => s,
      Err(e) => return Err(format!("Malformed JWT: Body {}", e)),
    },
    None => return Err("Malformed JWT: Body is missing".to_string()),
  };

  let signature = match parts.get(2) {
    Some(s) => match base64::decode_config(s, *BASE64_CONFIG) {
      Ok(v) => v,
      Err(e) => {
        return Err(format!(
          "Malformed JWT: cannot decode signature from base64. {}",
          e
        ))
      }
    },
    None => return Err("Malformed JWT: Missing signature".to_string()),
  };

  Ok(Token::new(header, body, signature))
}
