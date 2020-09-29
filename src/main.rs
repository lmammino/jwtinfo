#![crate_name = "jwtinfo"]

//! # jwtinfo
//!
//! `jwt` is a command line utility and a small library to parse JWT tokens
//!
//! ## Installation
//!
//! ```bash
//! cargo install jwtinfo
//! ```
//!
//! ## Usage
//!
//! ```bash
//! $ jwtinfo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
//! ```
//!
//! Which will print:
//!
//! ```json
//! {"sub":"1234567890","name":"John Doe","iat":1516239022}
//! ```
//!
//! ## Programmatic usage
//!
//! Install with cargo:
//!
//! ```toml
//! [dependencies]
//! jwtinfo = "*"
//! ```
//!
//! Then use it in your code
//!
//! ```rust
//! use jwtinfo::{jwt};
//!
//! let token = jwt::parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").unwrap();
//! assert_eq!(token.header.alg, "HS256");
//! assert_eq!(token.body, "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
//! ```

use clap::{App, Arg};
use std::io::{self, Read};
use std::process;

pub mod jwt;

#[macro_use]
extern crate lazy_static;

#[allow(dead_code)]
#[doc(hidden)]
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

    let jwt_token = match jwt::parse(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    println!("{}", jwt_token.body);

    Ok(())
}
