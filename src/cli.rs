use jwtinfo::{
    jw_output::{stringify, DisplayOptions},
    jw_parser::{parse_token, JWToken},
    jws,
};

use clap::{Arg, ArgAction, Command};
use jwtinfo::jwe::decrypt_jwe;
use serde_json::Value;
use std::{
    error::Error,
    fs,
    io::{self, Read},
};

#[doc(hidden)]
fn main() -> Result<(), Box<dyn Error>> {
    let mut matches = Command::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT (Json Web JwsToken)")
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
                .help("path to the key file (PEM/DER/JWK or raw bytes) to decrypt a JWE"),
        ])
        .get_matches();

    let opts = DisplayOptions {
        full: matches.get_flag("full"),
        pretty: matches.get_flag("pretty"),
        header: matches.get_flag("header"),
    };
    let mut token = matches.remove_one::<String>("token").unwrap();
    let mut buffer = String::new();

    // if the token is "-" read it from stdin
    if token == "-" {
        io::stdin().read_to_string(&mut buffer)?;
        token = (buffer.trim()).to_string();
    }

    match parse_token(&token) {
        Ok(JWToken::Jws(t)) => {
            // The --key flag is only meaningful for JWE tokens.
            if matches.get_one::<String>("key").is_some() {
                eprintln!("Warning: the --key flag is only applicable to JWE tokens; ignoring it");
            }
            println!("{}", stringify(None, t, opts));
            Ok(())
        }
        Ok(JWToken::Jwe(jwe)) => {
            if let Some(key_path) = matches.get_one::<String>("key") {
                // Decrypt and render. If the payload is a nested JWT we show the
                // outer JWE header together with the inner JWS; otherwise the
                // flags apply to the JWE header and the raw plaintext.
                let key = Some(fs::read(key_path)?);
                let decrypted = decrypt_jwe(&jwe, &token, key)?;
                let jwe_header: Value = serde_json::from_str(&jwe.header)?;
                let output = if decrypted.is_jwt_body {
                    let content = jws::parse(&decrypted.payload_string)?;
                    stringify(Some(jwe_header), content, opts)
                } else {
                    stringify(Some(jwe_header), decrypted.payload_string, opts)
                };
                println!("{}", output);
                Ok(())
            } else {
                // No key: render the JWE header with a placeholder body.
                let jwe_header: Value = serde_json::from_str(&jwe.header)?;
                let t = jws::jwe_placeholder(jwe_header);
                println!("{}", stringify(None, t, opts));
                Ok(())
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            // The error has already been reported: exit directly instead of
            // returning it from `main`, which would make the runtime print it
            // a second time (in Debug form).
            std::process::exit(1);
        }
    }
}
