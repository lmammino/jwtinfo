# jwtinfo

[![build badge](https://github.com/lmammino/jwtinfo/workflows/Rust/badge.svg)](https://github.com/lmammino/jwtinfo/actions?query=workflow%3ARust)
[![codecov](https://codecov.io/gh/lmammino/jwtinfo/graph/badge.svg)](https://codecov.io/gh/lmammino/jwtinfo)
[![crates.io badge](https://img.shields.io/crates/v/jwtinfo.svg)](https://crates.io/crates/jwtinfo)
[![API documentation](https://docs.rs/jwtinfo/badge.svg)](https://docs.rs/jwtinfo)
[![License: MIT](https://img.shields.io/crates/l/jwtinfo.svg)](#license)

A command line tool to inspect [JWTs](https://www.rfc-editor.org/rfc/rfc7519):
decode the header and claims of a signed token (JWS), or decrypt an encrypted
token (JWE) using your key.

> [!IMPORTANT]
> **The Rust library API is deprecated starting with 0.7.0.** jwtinfo is
> maintained as a CLI tool. Its library parsing/decryption API remains
> functional but is in maintenance mode, will not gain new features, and may
> be removed in a future release. See [Rust library deprecation](#rust-library-deprecation)
> for migration guidance. The CLI is not deprecated.

This README follows development on `main`. Package managers and the
installers below provide the latest published release, which may not yet
include all changes described here. See the [releases](https://github.com/lmammino/jwtinfo/releases)
and [changelog](CHANGELOG.md) for version-specific changes.

## Features

- Inspect JWS headers and JSON claims without verifying the signature.
- Decrypt supported JWE tokens with an RSA or symmetric key.
- Show the payload, headers, or full contents, with optional JSON formatting.
- Read a token from an argument or stdin and pipe JSON output to other tools.
- Inspect both headers and the inner claims of a JWE wrapping a JWS.

jwtinfo is an inspection tool: it does not validate JWS signatures, expiry,
issuer, or audience. Successful JWE decryption checks its authentication tag,
but does not verify the signature or claims of a nested JWS.

## Usage

Pass a compact token as an argument, or use `-` to read it from stdin.
Surrounding whitespace is accepted.

```bash
token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
jwtinfo "$token"
```

The default output is the JSON payload:

```json
{"iat":1516239022,"name":"John Doe","sub":"1234567890"}
```

Show the header or both the header and claims:

```bash
jwtinfo --header "$token"
jwtinfo --full --pretty "$token"
```

The second command prints:

```json
{
  "claims": {
    "iat": 1516239022,
    "name": "John Doe",
    "sub": "1234567890"
  },
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  }
}
```

Read a token from a file or use [jq](https://jqlang.org/) to select a claim:

```bash
jwtinfo --full --pretty - < token.txt
jwtinfo "$token" | jq -r .name
```

| Option | Purpose |
| --- | --- |
| `-H, --header` | Show the available header(s) |
| `-F, --full` | Show the headers and payload |
| `-P, --pretty` | Pretty-print JSON output |
| `-K, --key <path>` | Read a key file to decrypt a JWE |
| `-h, --help` | Show command-line help |
| `-V, --version` | Show the installed version |

`--header` and `--full` are mutually exclusive. Parsing, file-reading,
and decryption failures produce an error on stderr and a nonzero exit status.
Supplying `--key` for a JWS prints a warning and continues decoding; it
does not verify the signature.

### JWE decryption

Provide a key file and a compact encrypted token:

```bash
jwtinfo --key /path/to/private.pem - < /path/to/jwe.txt
jwtinfo --key /path/to/private.pem --full --pretty - < /path/to/jwe.txt
```

Without a key, a JWE produces a placeholder asking for a decryption key.
You can still inspect its header:

```bash
jwtinfo --header --pretty - < /path/to/jwe.txt
```

Supported content encryption (`enc`): **`A128GCM` and `A256GCM`**.

| Key management (`alg`) | Required key | Accepted formats |
| --- | --- | --- |
| `RSA-OAEP`, `RSA-OAEP-256` | RSA private key | PKCS#1/PKCS#8 PEM or DER; RSA JWK |
| `dir` | Content-encryption key: 16 bytes for `A128GCM`, 32 for `A256GCM` | Raw bytes; `oct` JWK |
| `A128KW`, `A192KW`, `A256KW` | Key-encryption key: 16, 24, or 32 bytes respectively | Raw bytes; `oct` JWK |

Files of exactly 16, 24, or 32 bytes are always treated as raw symmetric
keys, without trimming or text decoding. Other files are checked for PEM,
JWK, and DER encodings. A raw file contains the key bytes themselves, not
their hexadecimal or base64 text representation; do not append a newline.

### Display modes

| Input | Default | `--header` | `--full` |
| --- | --- | --- | --- |
| JWS | JSON claims | Header | `{header, claims}` |
| JWE without a key | JSON placeholder string | JWE header | `{header, claims: placeholder}` |
| Decrypted JWE plaintext | Raw UTF-8 text | JWE header | `{header, payload}` |
| Decrypted JWE with `cty: "JWT"` and an inner JWS | Inner JSON claims | `{jwe_header, jws_header}` | `{jwe_header, jws_header, claims}` |

`--pretty` formats JSON output. It leaves raw decrypted plaintext unchanged,
even if that plaintext happens to contain JSON. In full output, a plaintext
JWE payload is a JSON string. The `cty: "JWT"` header determines whether
the decrypted payload is parsed as a nested token.

### Limitations

- JWS inspection expects a base64url-encoded JSON header and JSON payload;
  it does not support detached or unencoded payloads. Empty signatures,
  including unsecured JWTs with `alg: "none"`, can be inspected.
- Decrypted JWE payloads must be UTF-8 text. Binary payloads are not supported.
- Nested display supports JWE → JWS. A payload marked `cty: "JWT"` that
  contains another JWE is rejected; recursive decryption is not implemented.
- Decryption rejects headers containing `zip` (compression) or `crit`
  (critical extensions). Their headers can still be inspected without a key.
- `RSA1_5`, `ECDH-ES` (including key-wrap variants), `PBES2-*`,
  `A192GCM`, `A192GCMKW`, and the `A128CBC-HS256` / `A192CBC-HS384` /
  `A256CBC-HS512` family are unsupported, as are EC and OKP keys.
- **GCMKW interoperability:** `A128GCMKW` / `A256GCMKW` decryption uses
  biscuit, which expects the header's `iv` and `tag` as JSON byte arrays.
  The base64url strings required by [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7)
  are rejected with an explicit limitation error. Do not expect standard
  GCMKW tokens from other JOSE libraries to decrypt.

## Install

You can install the binary in several ways:

### npm

Install via npm (Node.js package manager):

```bash
npm install -g jwtinfo
```

Or use `npx` to run without installing:

```bash
npx jwtinfo <token>
```

### Homebrew

Install via [Homebrew](https://brew.sh/) (macOS and Linux):

```bash
# Add the tap
brew tap lmammino/tap

# Install jwtinfo
brew install jwtinfo
```

Or install directly in one command:

```bash
brew install lmammino/tap/jwtinfo
```

### Shell Installer (macOS, Linux, WSL)

Download and install precompiled binaries with a single command:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/lmammino/jwtinfo/releases/latest/download/jwtinfo-installer.sh | sh
```

### PowerShell Installer (Windows)

Download and install precompiled binaries with PowerShell:

```powershell
irm https://github.com/lmammino/jwtinfo/releases/latest/download/jwtinfo-installer.ps1 | iex
```

### Cargo

You can install the binary in your system with
[`cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html):

```bash
cargo install jwtinfo --locked
```

### Precompiled binaries

Pre-compiled binaries for multiple platforms are available in the [Releases](https://github.com/lmammino/jwtinfo/releases) page.

### Using Nix

If you are using [Nix](https://nixos.org/), you can install the `jwtinfo` binary
with the following command:

```bash
nix profile install github:lmammino/jwtinfo
```

Or, if you prefer to use a configuration file, you can add the following to your
flake:

```nix
jwtinfo = {
    url = "github:lmammino/jwtinfo";
    inputs.nixpkgs.follows = "nixpkgs";
};

# ... with home.nix
home.packages = [ inputs.jwtinfo.packages."x86_64-linux".default ];

# ... with configuration.nix
environment.systemPackages = [ inputs.jwtinfo.packages."x86_64-linux".default ];
```

Make sure to replace `"x86_64-linux"` with your target platform.

You can also just try it out in a Nix shell with:

```bash
nix shell github:lmammino/jwtinfo -c jwtinfo <some_jwt_token>
```

Finally, for development purposes, you can clone this repo and then run:

```bash
nix develop
```

### Alternatives

If you don't want to install a binary for debugging JWT, a super simple `bash`
alternative called
[`jwtinfo.sh`](https://gist.github.com/lmammino/920ee0699af627a3492f86c607c859f6)
is available.

## Rust library deprecation

Starting with 0.7.0, the parsing/decryption functions `jws::parse`,
`jw_parser::parse_token`, `jw_parser::parse_jwe`, `jwe::handle_jwe`, and
`jwe::decrypt_jwe` are deprecated. The library remains functional in
maintenance mode, but new integrations should use a dedicated JWT library.
Consider [biscuit](https://crates.io/crates/biscuit), which jwtinfo uses
internally, or consult the [JWT library directory](https://jwt.io/libraries);
check the library's algorithm and validation support for your application.

Version 0.7.0 also breaks the previous library API. Existing consumers
should consult the [migration details in the changelog](CHANGELOG.md#breaking-library-api)
and [API documentation](https://docs.rs/jwtinfo). In particular:

- `jwt::Token` becomes `jws::JwsToken`; the `jwt` module becomes `jws`.
- `jws::parse` and `JwsToken::from_str` accept JWS inputs only. The
  deprecated `jw_parser::parse_token` returns a `JWToken` enum for either
  JWS or JWE.
- JWE fields use read-only accessors, and decryption/output signatures and
  error types have changed.

Installing and using the CLI through Cargo remains supported.

## Development

Use a current stable Rust toolchain. CI tests stable Rust; this project does
not currently declare a minimum supported Rust version.

```bash
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

To run the local CLI:

```bash
cargo run -- --help
cargo run -- --full --pretty - < token.txt
```

### Coverage

CI uses [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov).
For a local HTML report:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --all-features --workspace --html
```

Open `target/llvm-cov/html/index.html`. To produce the LCOV report used by CI:

```bash
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
```

### Releases

Releases are driven by version tags and cargo-dist. The workflow builds
binaries and installers, creates a GitHub release, publishes to crates.io
and npm, and updates the Homebrew tap. See the [release checklist](RELEASING.md)
before pushing a tag.

## Credits

A special thank you goes to the
[Rust Reddit community](https://www.reddit.com/r/rust/) for providing a lot of
useful suggestions on how to improve this project. A special thanks goes to:
[mardiros](https://www.reddit.com/user/mardiros/),
[matthieum](https://www.reddit.com/user/matthieum/),
[steveklabnik1](https://www.reddit.com/user/steveklabnik1/),
[ESBDB](https://www.reddit.com/user/ESBDB/),
[Dushistov](https://www.reddit.com/user/Dushistov/),
[Doddzilla7](https://www.reddit.com/user/Doddzilla7/). Another huge thank you
goes to the
[Rust stackoverflow community](https://chat.stackoverflow.com/rooms/62927/rust),
especially to [Denys Séguret](https://chat.stackoverflow.com/users/263525).

Big thanks also go to [Tim McNamara](https://twitter.com/timClicks) for
conducting a
[live code review](https://loige.co/learning-rust-through-open-source-and-live-code-reviews)
of this codebase.

## Contributing

Everyone is very welcome to contribute to this project. You can contribute just
by submitting bugs or suggesting improvements by
[opening an issue on GitHub](https://github.com/lmammino/jwtinfo/issues).

## License

Licensed under [MIT License](LICENSE). © Luciano Mammino & Stefano Abalsamo.
