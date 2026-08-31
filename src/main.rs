#![crate_name = "jwtinfo"]

//! # jwtinfo
//!
//! `jwt` is a command line utility and a small library to parse JWT
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
//! ## JWE decryption
//!
//! If the token is encrypted (JWE), provide a key file to decrypt it:
//!
//! ```bash
//! $ jwtinfo --key /path/to/private.pem "$(cat /path/to/jwe.txt)"
//! ```
//!
//! Supported algorithms:
//!
//! - Key management (`alg`): `dir`, `RSA-OAEP`, `RSA-OAEP-256`
//! - Content encryption (`enc`): `A128GCM`, `A256GCM`
//!
//! For `dir`, the key file must contain the raw content-encryption key (CEK) bytes.
//! For RSA-based algorithms, the key file must be a PEM-encoded private key in PKCS#1 or PKCS#8 format.
//! At the moment only `.pem` keys are supported; additional formats will be added in the future.
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
//! use jwtinfo::{jws};
//!
//! let token = jws::parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").unwrap();
//! assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
//! assert_eq!(token.body.to_string(), "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
//! ```

pub mod jw_error;
pub mod jw_output;
pub mod jw_parser;
pub mod jwe;
pub mod jws;
