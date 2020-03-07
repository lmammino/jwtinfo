# jwtinfo

[![build badge](https://github.com/lmammino/jwtinfo/workflows/Rust/badge.svg)](https://github.com/lmammino/jwtinfo/actions?query=workflow%3ARust)
[![crates.io badge](http://meritbadge.herokuapp.com/jwtinfo)](https://crates.io/crates/jwtinfo)
[![rustc badge](https://img.shields.io/badge/rustc-1.40+-lightgray.svg)](https://blog.rust-lang.org/2019/12/19/Rust-1.40.0.html)
[![Clippy Linting Result](https://img.shields.io/badge/clippy-<3-yellowgreen)](https://github.com/rust-lang/rust-clippy)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/jwtinfo.svg)](#license)


A command line tool to get information about JWT tokens

## Usage

`jwtinfo` is a command line interface that allows you to inspect a given JWT token. The tool currently allows to see the body of the token in JSON format. It accepts a single command line argument which should be a valid JWT token.

Here's an example:

```bash
jwtinfo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Which will print:

```json
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

You can combine the tool with other command line utilities, for instance [`jq`](https://stedolan.github.io/jq/):

```bash
jwtinfo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c | jq .
```

## Install

You can install the binary in several ways:

### Cargo

You can install the binary in your system with [`cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html):

```bash
cargo install jwtinfo
```

At this point `jwtinfo` will be available as a binary in your system.

### Precompiled binaries

Pre-compiled binaries for x64 Windows, MacOs and Unix are available in the [Releases](https://github.com/lmammino/jwtinfo/releases) page.

## Contributing

Everyone is very welcome to contribute to this project.
You can contribute just by submitting bugs or suggesting improvements by
[opening an issue on GitHub](https://github.com/lmammino/jwtinfo/issues).

## License

Licensed under [MIT License](LICENSE). © Luciano Mammino & Stefano Abalsamo.
