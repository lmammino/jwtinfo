use std::env;
use std::process;
use std::str;
use base64;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct JWTHeader {
    typ: String,
    alg: String
}

#[derive(Debug)]
struct JWTToken<'a> {
    header: &'a JWTHeader,
    body: &'a str,
    signature: Vec<u8>
}

impl<'a> JWTToken<'a> {
    pub fn new(header: &'a JWTHeader, body: &'a str, signature: Vec<u8>) -> Self {
        JWTToken { header, body, signature }
    }
}

fn parse_base64_string (s: &str) -> Result<&str, &str> {
    match base64::decode(s) {
        Ok(s) => match str::from_utf8(&s) {
            Ok(s) => Ok(s),
            Err(e) => return Err("cannot be decoded to a valid UTF-8 string")
        },
        Err(e) => return Err("is not a valid base64 string")
    }
}

fn parse_jwt_token (token: &str) -> Result<&JWTToken, &str> {
    let parts : Vec<&str> = token.split('.').collect();
    let header_str = match parts.get(0) {
        Some(s) => match parse_base64_string(s) {
            Ok(s) => s,
            Err(e) => return Err(&format!("Malformed JWT: Header {}", e))
        },
        None => return Err("Malformed JWT: Header is missing")
    };
    let header: JWTHeader = match serde_json::from_str(header_str) {
        Ok(h) => h,
        Err(e) => return Err("Malformed JWT: Header is not a valid JSON")
    };

    let body = match parts.get(1) {
        Some(s) => match parse_base64_string(s) {
            Ok(s) => s,
            Err(e) => return Err(&format!("Malformed JWT: Body {}", e))
        },
        None => return Err("Malformed JWT: Body is missing")
    };

    // TODO
    // x JSON parse header
    // x parse body
    // parse signature
    // return new Token instance
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let token_wrap = args.get(1);
    if token_wrap.is_none() {
        eprintln!("Error: Missing JWT token. Pass it as first command line argument");
        process::exit(1);
    }
    let token = token_wrap.unwrap();

    println!("provided token: {}", token);
}
