use std::env;
use std::process;

#[macro_use]
extern crate lazy_static;

mod jwt;

fn main() {
    let args: Vec<String> = env::args().collect();
    let token_wrap = args.get(1);
    if token_wrap.is_none() {
        eprintln!("Error: Missing JWT token. Pass it as first command line argument");
        process::exit(1);
    }
    let token = token_wrap.unwrap();
    let jwt_token = match jwt::parse_jwt_token(token) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    println!("provided token: {:?}", jwt_token);
}
