#![crate_name = "jwtinfo"]

//! # jwtinfo
//!
//! `jwtinfo` is a command line tool to inspect JWTs and decrypt supported JWEs.
//! The library parsing API is deprecated since 0.7.0 and in maintenance mode;
//! the CLI remains supported. JWS signatures and claims are not verified.
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
//! - Key management (`alg`): `dir`, `RSA-OAEP`, `RSA-OAEP-256`,
//!   `A128KW`, `A192KW`, `A256KW`
//! - Content encryption (`enc`): `A128GCM`, `A256GCM`
//!
//! The key file can be an RSA private key (PEM/DER/JWK) or a symmetric key
//! (raw bytes or `oct` JWK). For `dir`, the decoded key must be the
//! content-encryption key (16 bytes for A128GCM, 32 for A256GCM).
//!
//! GCMKW (`A128GCMKW`/`A256GCMKW`) is subject to a known limitation of the
//! biscuit library, which cannot parse the RFC 7518 base64url `iv`/`tag`
//! header parameters; only biscuit-produced GCMKW tokens can be decrypted.
//! See the README for details.
//!
//! ## Programmatic usage
//!
//! > **Deprecation notice (0.7.0):** jwtinfo is being repositioned as a CLI
//! > tool: the parsing library API is deprecated and in maintenance mode.
//! > It remains functional, but it will not gain new features and may be
//! > removed in a future release. For library JWT parsing, use
//! > [`biscuit`](https://crates.io/crates/biscuit) or some other JWT
//! > library ([check jwt.io for suggestions](https://jwt.io/libraries)).
//!
//! For existing library consumers, use a versioned dependency and consult
//! the changelog for the breaking 0.7.0 API changes:
//!
//! ```toml
//! [dependencies]
//! jwtinfo = "0.7"
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
