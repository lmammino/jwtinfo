# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

jwtinfo is a Rust command-line tool for inspecting JWTs and decrypting supported JWEs. The library parsing API is deprecated since 0.7.0. JWS signatures and claims are not verified.

## Architecture

- **Binary entry point**: `src/cli.rs` - CLI application using clap for argument parsing
- **Library entry point**: `src/main.rs` - Exposes the public API
- **Token parsing**: `src/jw_parser.rs` - winnow checks the compact alphabet and classifies JWS (3 segments) vs JWE (5 segments); biscuit decodes the parts. Decryption enforces algorithm-specific invariants.
- **JWS types/logic**: `src/jws.rs` - `JwsToken`, `parse()`, `FromStr`
- **JWE decryption**: `src/jwe.rs` + `src/jwe/jwe_handler/` - decryption and `DecryptedJwe`
  - `key_loader.rs` - loads keys from PEM/DER/JWK/raw bytes into a `LoadedKey` (symmetric bytes or RSA private key)
  - `decryptor.rs` - algorithm dispatch: RSA-OAEP via `rsa` crate, AES-KW via `aes-kw`, `dir`/GCMKW via `biscuit`
- **Output formatting**: `src/jw_output.rs` - flag-driven rendering of explicit `TokenOutput` variants
- **Errors**: `src/jw_error.rs` - `ParseError`, `JwtParseError`, `JweError`
- **Unit tests**: `src/jws/test.rs`, `src/jwe/test.rs`, `src/jw_parser/test.rs`

The project follows a dual structure:

- Library crate: Provides `jws::parse()` function and `JwsToken` struct (the parsing API is deprecated since 0.7.0 and in maintenance mode; see CHANGELOG.md — jwtinfo is repositioning as a CLI tool)
- Binary crate: CLI wrapper that uses the library for command-line interaction

## Common Development Commands

### Building

```bash
cargo build          # Build in debug mode
cargo build --release # Build optimized release
```

### Testing

```bash
cargo test           # Run all tests
cargo test jws       # Run specific module tests
```

### Linting and Formatting

```bash
cargo clippy         # Run Clippy linter
cargo fmt            # Format code
```

### Running the CLI

```bash
cargo run -- <jwt_token>              # Run with a JWT token
cargo run -- --header <jwt_token>     # Show header instead of body
cargo run -- --pretty <jwt_token>     # Pretty print output
```

### Coverage (Development)

Coverage uses cargo-llvm-cov, matching CI:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --all-features --workspace --html
```

### Nix Development

For Nix users:

```bash
nix develop          # Enter development shell
nix shell github:lmammino/jwtinfo -c jwtinfo <token>  # Try without installing
```

## Key Components

### JWT Token Structure

The `JwsToken` struct in `src/jws.rs` contains:

- `header`: JWT header as `serde_json::Value`
- `body`: JWT payload as `serde_json::Value`
- `signature`: Signature bytes (unused in current implementation)

### Token parsing (`src/jw_parser.rs`)

- `parse_token(&str) -> Result<JWToken, JwtParseError>` - entry point; an alt-of-shapes winnow grammar classifies the token as JWS (3 segments) or JWE (5 segments)
- Leaf parsers: `b64url` (non-empty segment) and `b64url_or_empty` (unsecured-JWT signature, `dir` key, and the JWE iv/ciphertext/tag segments)
- `Shape` enum - grammar output identifying JWS or JWE; the caller retains the input and biscuit decodes its parts
- `classify(&str)` - fallback error mapping (`InvalidSegment` vs `WrongPartCount`) when both shapes fail
- `JWToken` enum: `Jws(JwsToken)` | `Jwe(JweToken)`
- `parse_jwe(&str) -> Result<JweToken, JwtParseError>` - convenience wrapper

### Output formatting (`src/jw_output.rs`)

- `stringify(content: TokenOutput, opts: DisplayOptions)` - shared renderer
- `DisplayOptions { full, pretty, header }` - mirrors the CLI display flags
- `TokenOutput` distinguishes JWS, encrypted JWE, decrypted plaintext JWE, and nested JWS; its variants borrow their content
- `jws::parse` rejects JWE inputs; the encrypted placeholder belongs to output formatting only

### Error Handling

Error hierarchy in `src/jw_error.rs`:

- `ParseError`: Low-level parsing errors (base64, JSON, UTF-8)
- `JwtParseError`: High-level errors indicating which token part failed (Header/Body/Signature), wrong part count, or invalid segment
- `JweError`: wraps JWE parsing, JSON, UTF-8 and crypto errors
- `JweCryptoError`: decryption/algorithm errors

### CLI Features

- Reads JWT from command line argument or stdin (use "-")
- `--header` flag to show header(s) instead of body
- `--full` flag to show all sections (header + claims)
- `--pretty` flag for formatted JSON output
- `--key` flag to decrypt JWE tokens; on a JWS token it warns but continues
- For a nested JWE->JWS token (with `--key`), `--header`/`--full` include both the outer `jwe_header` and the inner `jws_header`
