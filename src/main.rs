use clap::{App, Arg};
use std::process;

#[macro_use]
extern crate lazy_static;

mod jwt;

fn main() {
    let matches = App::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT token")
        .arg(
            Arg::with_name("token")
                .help("the JWT token as a string")
                .required(true)
                .index(1),
        )
        .get_matches();

    let token = matches.value_of("token").unwrap();
    let jwt_token = match jwt::parse_token(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    println!("{}", jwt_token.body);
}
