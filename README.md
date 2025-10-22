# jwtinfo

[![build badge](https://github.com/lmammino/jwtinfo/workflows/Rust/badge.svg)](https://github.com/lmammino/jwtinfo/actions?query=workflow%3ARust)
[![codecov](https://codecov.io/gh/lmammino/jwtinfo/graph/badge.svg?token=jYukD16Axe)](https://codecov.io/gh/lmammino/jwtinfo)
[![crates.io badge](https://img.shields.io/crates/v/jwtinfo.svg)](https://crates.io/crates/jwtinfo)
[![Documentation](https://docs.rs/jwtinfo/badge.svg)](https://docs.rs/jwtinfo)
[![rustc badge](https://img.shields.io/badge/rustc-1.40+-lightgray.svg)](https://blog.rust-lang.org/2019/12/19/Rust-1.40.0.html)
[![Clippy Linting Result](https://img.shields.io/badge/clippy-<3-yellowgreen)](https://github.com/rust-lang/rust-clippy)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/jwtinfo.svg)](#license)
[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/lmammino/jwtinfo)

A command line tool to get information about
[JWTs](https://tools.ietf.org/html/rfc7519) (Json Web Tokens).

## Usage

`jwtinfo` is a command line interface that allows you to inspect a given JWT.
The tool currently allows to see the body of the token in JSON format. It
accepts a single command line argument which should be a valid JWT.

Here's an example:

```bash
jwtinfo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Which will print:

```json
{ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }
```

If you want to visualize the token header (rather than the body), you can do
that by passing the `--header` flag:

```bash
jwtinfo --header eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Which will print:

```json
{ "alg": "HS256", "typ": "JWT" }
```

If you want to see both the header and the claims at the same time, you can use
the `--full` flag:

```bash
jwtinfo --full eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Which will print:

```json
{"header":{"alg":"HS256","typ":"JWT"},"claims":{"sub":"1234567890","name":"John Doe","iat":1516239022}}
```

For better readability, you can combine `--full` with the `--pretty` flag to
get formatted output:

```bash
jwtinfo --full --pretty eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Which will print:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "claims": {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  }
}
```

You can combine the tool with other command line utilities, for instance
[`jq`](https://stedolan.github.io/jq/):

```bash
jwtinfo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c | jq .
```

> [!NOTE]
> **Encrypted [JWE](https://datatracker.ietf.org/doc/html/rfc7516) Tokens**: If you provide an encrypted JWE token (JSON Web Encryption), the tool will detect it by checking for the `enc` field in the header. Since JWE tokens are encrypted, the claims/body cannot be read without decryption. In this case, `jwtinfo` will display the special placeholder string `"<encrypted JWE body>"` instead of the actual claims. The header can still be inspected normally using the `--header` flag.

## Install

You can install the binary in several ways:

### Cargo

You can install the binary in your system with
[`cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html):

```bash
cargo install jwtinfo
```

At this point `jwtinfo` will be available as a binary in your system.

### Install script

The following script will download and install precompiled binaries from the
latest GitHub release

```bash
curl https://raw.githubusercontent.com/lmammino/jwtinfo/main/install.sh | sh
```

By default, it will install the binary in `/usr/local/bin`. You can customize
this by setting the `INSTALL_DIRECTORY` environment variable before running the
script (e.g. `INSTALL_DIRECTORY=$HOME` will install the binary in `$HOME/bin`).

If you want to install a specific release you can set the `RELEASE_TAG`
environment variable to point to your target version before running the script
(e.g. `RELESE_TAG=v0.1.7`).

### Precompiled binaries

Pre-compiled binaries for x64 (Windows, macOs and Unix) and ARMv7 are available
in the [Releases](https://github.com/lmammino/jwtinfo/releases) page.

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

#### Alternatives

If you don't want to install a binary for debugging JWT, a super simple `bash`
alternative called
[`jwtinfo.sh`](https://gist.github.com/lmammino/920ee0699af627a3492f86c607c859f6)
is available.

## Programmatic usage

Install with cargo:

```toml
[dependencies]
jwtinfo = "*"
```

Then use it in your code

```rust
use jwtinfo::{jwt};
let token_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
let token = jwt::parse(token_str).unwrap();
assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
```

Since `jwt:Token` implements `str::FromStr`, you can also do the following:

```rust
use jwtinfo::{jwt};
let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".parse::<jwt::Token>().unwrap();
assert_eq!(token.header.to_string(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
assert_eq!(token.body.to_string(), "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}");
```

## Coverage reports

If you want to run coverage reports locally you can follow this recipe.

First of all you will need Rust Nightly that you can get with `rustup`

```bash
rustup install nightly
```

You will also need `grcov` that you can get with `cargo`:

```bash
cargo install grcov
```

Now you can run the tests in profile mode:

```bash
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zno-landing-pads"
cargo +nightly test
```

This will run your tests and generate coverage info in `./target/debug/`

Now we can run `grcov`:

```bash
grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
```

Finally you will have your browsable coverage report at
`./target/debug/coverage/index.html`.

### Tarpaulin coverage

Since `grcov` tends to be somewhat inaccurate at times, you can also get a
coverage report by running [tarpaulin](https://github.com/xd009642/tarpaulin)
using docker:

```bash
docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin:develop-nightly bash -c 'cargo build && cargo tarpaulin -o Html'
```

Your coverage report will be available as `tarpaulin-report.html` in the root of
the project.

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
