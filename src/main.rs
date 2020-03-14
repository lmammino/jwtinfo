use clap::{App, Arg};
use std::io::{self, Read};
use std::process;

#[macro_use]
extern crate lazy_static;

mod jwt;

fn main() -> io::Result<()> {
    let matches = App::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT token")
        .arg(
            Arg::with_name("token")
                .help("the JWT token as a string (use \"-\" to read from stdin)")
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

    let jwt_token = match jwt::parse_token(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    println!("{}", jwt_token.body);

    Ok(())
}
