# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — version 0.7.0

Version 0.7.0 is a feature release that adds JWE decryption and rebuilds the
token parser on [winnow](https://crates.io/crates/winnow) (validation and
classification) and [biscuit](https://crates.io/crates/biscuit) (compact
splitting, base64url decoding, `dir`/GCMKW decryption). It contains breaking
changes for library users.

### Added

- **JWE decryption** with `-K/--key <path>`: encrypted tokens can be decrypted
  to inspect their payload, including nested JWE→JWS tokens (`cty: "JWT"`),
  whose headers are shown as `jwe_header` and `jws_header`.
  - Key management algorithms (`alg`): `dir`, `RSA-OAEP`, `RSA-OAEP-256`,
    `A128KW`, `A192KW`, `A256KW`.
  - Content encryption algorithms (`enc`): `A128GCM`, `A256GCM`.
  - Key formats (auto-detected, any format works for any algorithm): RSA
    private keys (PEM or DER, PKCS#1 or PKCS#8, or a JWK), symmetric keys
    (raw 16/24/32-byte file or `oct` JWK).
- JWE tokens provided without a key print a placeholder body asking for
  `-K/--key`; the header can still be inspected with `--header`.

### Changed

- Token parsing is now grammar-based: winnow checks the compact alphabet and
  distinguishes the 3-segment JWS and 5-segment JWE shapes; biscuit decodes
  the parts. Algorithm-specific JWE validation happens during decryption.
  The `base64` dependency is gone.
- Empty signature segments (unsecured JWTs, `alg: none`) and empty
  encrypted-key segments (`dir` JWEs) parse correctly.

### Deprecated

- The parsing library API: `jws::parse`, `jw_parser::parse_token`,
  `jw_parser::parse_jwe`, `jwe::handle_jwe`, `jwe::decrypt_jwe`. jwtinfo is
  being repositioned as a CLI tool: the API remains functional but is in
  maintenance mode, will not gain new features, and may be removed in a
  future release. For library JWT parsing, use
  [biscuit](https://crates.io/crates/biscuit) or some other JWT library
  ([check jwt.io for suggestions](https://jwt.io/libraries)).

### Breaking (library API)

- `jws::parse` and `JwsToken::from_str` reject JWE inputs with `NotAJws`.
  Use `jw_parser::parse_token` for either type. `jwe_placeholder` is removed;
  encrypted placeholders are rendered by `TokenOutput::EncryptedJwe`.
- `jw_output::stringify` takes `(TokenOutput, DisplayOptions)`. The explicit
  borrowed output enum replaces `TokenContent` and `Output`.

- The `jwt` module is renamed `jws`; `jwt::Token` is now `jws::JwsToken`.
- New entry point `jw_parser::parse_token` returns the `JWToken` enum
  (`Jws(JwsToken)` | `Jwe(JweToken)`). `jws::parse` and
  `jw_parser::parse_jwe` remain.
- Error types are reshaped in `jw_error`: `ParseError`, `JwtParseError`,
  `JweError`, `JweCryptoError` replace `JWTParseError`/`JWTParsePartError`.
- `ParseError::InvalidBase64` carries the decoder's pre-formatted message
  (`String`) instead of `base64::DecodeError`. Two observable consequences:
  the `From<base64::DecodeError>` conversion is gone (downstream `?` breaks),
  and the variant is no longer an error `source()`.
- `jwe::JweToken` is constructed from the raw compact string
  (`JweToken::new(&str) -> Result<_, JwtParseError>`), enforces the 5-segment
  shape (rejecting non-5-segment inputs with `WrongPartCount` and empty header
  segments with `InvalidSegment`), and has private fields with read-only
  accessors: struct literals, field mutation, and exhaustive destructuring
  no longer compile. `aad` is a method
  (derived from the first raw segment) instead of a field, and `raw()` returns
  a `String`.
- `jwe::decrypt_jwe` takes the parsed token only:
  `decrypt_jwe(&JweToken, Option<Vec<u8>>)`.
- `jwe::jwe_handler::{decryptor, key_loader}` are crate-private. Biscuit types
  no longer appear in the public API.

### Behavior deltas

- Tokens with an empty header segment (e.g. `.payload.signature`) are rejected
  at parse time with `Invalid base64url segment` instead of producing a
  confusing empty-JSON decode error later.
- Base64 errors are reported with the delegated decoder's wording (e.g.
  `invalid length at 16`, `non-zero trailing bits at 13`); classification
  prefixes (`Invalid Header:`, `Invalid Body:`, `Invalid Signature:`) are
  unchanged.
- `dir`/GCMKW tokens carrying surrounding whitespace now decrypt; previously
  the untrimmed string was forwarded to biscuit and failed with a cryptic
  `invalid symbol` decode error.
- All CLI errors are reported once, in `Display` form; previously decryption
  errors leaked `Debug` output and parse errors could print twice.

### Known limitations

- GCMKW (`A128GCMKW`/`A256GCMKW`) decryption is delegated to biscuit, which
  expects the GCMKW `iv`/`tag` protected-header parameters as JSON byte
  arrays, while [RFC 7518 §4.7](https://datatracker.ietf.org/doc/html/rfc7518#section-4.7)
  defines them as base64url strings. Only biscuit-produced GCMKW tokens can be
  decrypted; standards-compliant tokens are detected and rejected with a clear
  error.
- Not yet supported: `RSA1_5`, `ECDH-ES` (+`-KW` variants), `PBES2-*`, the
  `A192GCM`/`A192GCMKW` variants, the `A1xxCBC-HSxxx` content-encryption
  family, and EC/OKP (EdDSA) keys.
