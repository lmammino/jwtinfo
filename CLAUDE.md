# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

jwtinfo is a Rust command-line tool and library for parsing JWT (JSON Web Tokens). It extracts and displays the header and body of JWTs without verification.

## Architecture

- **Binary entry point**: `src/cli.rs` - CLI application using clap for argument parsing
- **Library entry point**: `src/main.rs` - Exposes the public API
- **Core JWT logic**: `src/jwt.rs` - Contains the JWT parsing implementation
- **Tests**: `src/jwt/test.rs` - Unit tests for JWT parsing functionality

The project follows a dual structure:
- Library crate: Provides `jwt::parse()` function and `Token` struct
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
cargo test jwt       # Run specific module tests
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
The `Token` struct in `src/jwt.rs` contains:
- `header`: JWT header as `serde_json::Value`
- `body`: JWT payload as `serde_json::Value`
- `signature`: Signature bytes (unused in current implementation)

### Error Handling
Two-level error hierarchy:
- `JWTParseError`: Low-level parsing errors (base64, JSON, UTF-8)
- `JWTParsePartError`: High-level errors indicating which JWT part failed

### CLI Features
- Reads JWT from command line argument or stdin (use "-")
- `--header` flag to show header instead of body
- `--pretty` flag for formatted JSON output