use std::env;
use std::process;
use std::str;
use base64;
use serde::Deserialize;

#[macro_use]
extern crate lazy_static;

#[derive(Deserialize, Debug)]
struct JWTHeader {
    typ: String,
    alg: String
}

#[derive(Debug)]
struct JWTToken {
    header: JWTHeader,
    body: String,
    signature: Vec<u8>
}

lazy_static! {
    static ref BASE64_CONFIG: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
}

impl JWTToken {
    pub fn new(header: JWTHeader, body: String, signature: Vec<u8>) -> Self {
        JWTToken { header, body, signature }
    }
}

fn parse_base64_string (s: &str) -> Result<String, String> {
    match base64::decode_config(s, *BASE64_CONFIG) {
        Ok(s) => match str::from_utf8(&s) {
            Ok(s) => Ok(s.to_string()),
            Err(e) => return Err(format!("cannot be decoded to a valid UTF-8 string. {}", e))
        },
        Err(e) => return Err(format!("is not a valid base64 string. {}", e))
    }
}

fn parse_jwt_token (token: &str) -> Result<JWTToken, String> {
    let parts : Vec<&str> = token.split('.').collect();
    let header_str = match parts.get(0) {
        Some(s) => match parse_base64_string(s) {
            Ok(s) => s,
            Err(e) => return Err(format!("Malformed JWT: Header {}", e))
        },
        None => return Err("Malformed JWT: Header is missing".to_string())
    };
    let header: JWTHeader = match serde_json::from_str(&header_str) {
        Ok(h) => h,
        Err(e) => return Err(format!("Malformed JWT: Header is not a valid JSON. {}", e))
    };

    let body = match parts.get(1) {
        Some(s) => match parse_base64_string(s) {
            Ok(s) => s,
            Err(e) => return Err(format!("Malformed JWT: Body {}", e))
        },
        None => return Err("Malformed JWT: Body is missing".to_string())
    };

    let signature = match parts.get(2) {
        Some(s) => match base64::decode_config(s, *BASE64_CONFIG) {
            Ok(v) => v,
            Err(e) => return Err(format!("Malformed JWT: cannot decode signature from base64. {}", e))
        },
        None => return Err("Malformed JWT: Missing signature".to_string())
    };

    Ok(JWTToken::new(header, body, signature))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let token_wrap = args.get(1);
    if token_wrap.is_none() {
        eprintln!("Error: Missing JWT token. Pass it as first command line argument");
        process::exit(1);
    }
    let token = token_wrap.unwrap();
    let jwt_token = match parse_jwt_token(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    println!("provided token: {:?}", jwt_token);
}
