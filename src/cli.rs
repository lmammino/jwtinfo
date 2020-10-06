use clap::{App, Arg};
use std::io::{self, Read};
use std::process;

mod jwt;

#[macro_use]
extern crate lazy_static;

#[doc(hidden)]
fn main() -> io::Result<()> {
    let matches = App::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT (Json Web Token)")
        .arg(
            Arg::with_name("header")
                .short("H")
                .long("header")
                .help("Shows the token header rather than the body")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("token")
                .help("the JWT as a string (use \"-\" to read from stdin)")
                .required(true)
                .index(1),
        )
        .get_matches();

    let mut token = matches.value_of("token").unwrap();
    let mut buffer = String::new();

    // if the token is "-" read it from stdin
    if token == "-" {
        io::stdin().read_to_string(&mut buffer)?;
        token = &*buffer.trim();
    }

    let jwt_token = match jwt::parse(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let part = if matches.is_present("header") {
        jwt_token.header
    } else {
        jwt_token.body
    };
    println!("{}", part.to_string());

    Ok(())
}
