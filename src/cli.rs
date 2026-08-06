use jwtinfo::jwt;

use clap::{Arg, ArgAction, Command};
use jwtinfo::jwe::handle_jwe;
use jwtinfo::jwt::stringify_token;
use std::{
    error::Error,
    fs,
    io::{self, Read},
};

#[doc(hidden)]
fn main() -> Result<(), Box<dyn Error>> {
    let mut matches = Command::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT (Json Web Token)")
        .args([
            Arg::new("header")
                .short('H')
                .long("header")
                .action(ArgAction::SetTrue)
                .conflicts_with("full")
                .help("Shows the token header rather than the body"),
            Arg::new("full")
                .short('F')
                .long("full")
                .action(ArgAction::SetTrue)
                .conflicts_with("header")
                .help("Shows both the token header and body"),
            Arg::new("pretty")
                .short('P')
                .long("pretty")
                .action(ArgAction::SetTrue)
                .help("Pretty prints the JWT header or body"),
            Arg::new("token")
                .index(1)
                .allow_hyphen_values(true)
                .required(true)
                .help("the JWT/JWE as a string (use \"-\" to read from stdin)"),
            Arg::new("key")
                .short('K')
                .long("key")
                .help("the path to the private key for the cek decryption in case of JWE"),
        ])
        .get_matches();

    let full_flag = matches.get_flag("full");
    let should_pretty_print = matches.get_flag("pretty");
    let header_flag = matches.get_flag("header");
    let mut token = matches.remove_one::<String>("token").unwrap();
    let mut is_jwt_body = false;
    let mut buffer = String::new();

    // if the token is "-" read it from stdin
    if token == "-" {
        io::stdin().read_to_string(&mut buffer)?;
        token = (buffer.trim()).to_string();
    }

    // if there is a key must be a JWE
    if let Some(key_path) = matches.get_one::<String>("key") {
        let key = fs::read(key_path)?;
        // handle_jwe returns the JWE payload, which could be a UTF-8 string or a
        // JWT to decode (currently we don't handle payload as byte arrays)
        (token, is_jwt_body) = handle_jwe(token, key)?;
    }

    match jwt::parse(&token) {
        Ok(jwt_token) => {
            let stringified =
                stringify_token(jwt_token, full_flag, should_pretty_print, header_flag)?;
            println!("{}", stringified);
            Ok(())
        }
        Err(e) => {
            if !is_jwt_body {
                println!("{}", token);
                Ok(())
            } else {
                eprintln!("Error with token: {}\nDetail: {}", token, e);
                Err(e.into())
            }
        }
    }
}
