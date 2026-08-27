# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

jwtinfo is a Rust command-line tool and library for parsing JWT (JSON Web Tokens). It extracts and displays the header and body of JWTs without verification.

## Architecture

- **Binary entry point**: `src/cli.rs` - CLI application using clap for argument parsing
- **Library entry point**: `src/main.rs` - Exposes the public API
- **Token parsing**: `src/jw_parser.rs` - winnow-based parser that detects JWS (3 parts) vs JWE (5 parts)
- **JWS types/logic**: `src/jws.rs` - `JwsToken`, `parse()`, `FromStr`
- **JWE decryption**: `src/jwe.rs` + `src/jwe/jwe_handler/` - decryption and `DecryptedJwe`
- **Output formatting**: `src/jw_output.rs` - generic flag-driven rendering (`stringify`)
- **Errors**: `src/jw_error.rs` - `ParseError`, `JwtParseError`, `JweError`
- **Unit tests**: `src/jws/test.rs`, `src/jwe/test.rs`, `src/jw_parser/test.rs`

The project follows a dual structure:

- Library crate: Provides `jws::parse()` function and `JwsToken` struct
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

Coverage requires Rust nightly and grcov:

```bash
rustup install nightly
cargo install grcov
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zno-landing-pads"
cargo +nightly test
grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
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

- `parse_token(&str) -> Result<JWToken, JwtParseError>` - entry point; detects JWS vs JWE by part count (3 vs 5) using winnow
- `JWToken` enum: `Jws(JwsToken)` | `Jwe(JweToken)`
- `parse_jwe(&str) -> Result<JweToken, JwtParseError>` - convenience wrapper

### Output formatting (`src/jw_output.rs`)

- `stringify<T: TokenContent>(jwe_header, content, full, pretty, header)` - single generic renderer
- `TokenContent` implemented for `JwsToken` and `String` (plaintext JWE payload)
- `jwe_header: Option<Value>` - `Some` when there is an outer JWE level
- `Output` enum distinguishes `Json` (serialized) from `Raw` (verbatim plaintext)

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

