use std::env;
use std::process;
use std::str;
use base64;

struct Token {
    header: String,
    body: String,
    signature: Vec<u8>
}

fn parse_jwt_token (token: &str) -> Result<&Token, &str> {
    let parts : Vec<&str> = token.split('.').collect();
    let header = match parts.get(0) {
        Some(s) => match base64::decode(s) {
            Ok(s) => str::from_utf8(&s)?,
            Err(e) => return Error("Malformed JWT: Header is not a valid base64 string")
        },
        None() => return Error("Malformed JWT: Header is missing")
    };

    // TODO
    // parse body
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
