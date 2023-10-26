use clap::{Arg, ArgAction, Command};
use serde_json::to_string_pretty;
use std::io::{self, Read};
use std::process;

mod jwt;

#[doc(hidden)]
fn main() -> io::Result<()> {
    let matches = Command::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT (Json Web Token)")
        .args([
            Arg::new("header")
                .short('H')
                .long("header")
                .action(ArgAction::SetTrue)
                .help("Shows the token header rather than the body"),
            Arg::new("pretty")
                .short('P')
                .long("pretty")
                .action(ArgAction::SetTrue)
                .help("Pretty prints the JWT header or body"),
            Arg::new("token")
                .index(1)
                .help("the JWT as a string (use \"-\" to read from stdin)"),
        ])
        .get_matches();

    let should_pretty_print = matches.get_flag("pretty");

    let mut token = matches.get_one::<String>("token").unwrap().clone();
    let mut buffer = String::new();

    // if the token is "-" read it from stdin
    if token == "-" {
        io::stdin().read_to_string(&mut buffer)?;
        token = (*buffer.trim()).to_string();
    }

    let jwt_token = match jwt::parse(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let part = if matches.get_flag("header") {
        jwt_token.header
    } else {
        jwt_token.body
    };

    let stringified = if should_pretty_print {
        to_string_pretty(&part)?
    } else {
        part.to_string()
    };

    println!("{}", stringified);

    Ok(())
}
