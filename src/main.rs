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
//! The key file can be an RSA private key (PEM/DER/JWK) or a symmetric key
//! (raw 16/24/32-byte file or `oct` JWK). For `dir` it must contain the raw
//! content-encryption key (CEK) bytes.
//!
//! GCMKW (`A128GCMKW`/`A256GCMKW`) is subject to a known limitation of the
//! biscuit library, which cannot parse the RFC 7518 base64url `iv`/`tag`
//! header parameters; only biscuit-produced GCMKW tokens can be decrypted.
//! See the README for details.
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
