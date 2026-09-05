use crate::jws::JwsToken;
use serde_json::{json, to_string_pretty, Value};

/// How a token should be rendered, mirroring the CLI display flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayOptions {
    /// Show both the header and the payload (`--full`).
    pub full: bool,
    /// Pretty-print the JSON output (`--pretty`).
    pub pretty: bool,
    /// Show only the header(s) (`--header`).
    pub header: bool,
}

/// The available inspection results. An encrypted JWE has no readable body
/// and never needs to masquerade as a signed token.
pub enum TokenOutput<'a> {
    Jws(&'a JwsToken),
    EncryptedJwe {
        header: &'a Value,
    },
    DecryptedJwe {
        header: &'a Value,
        payload: &'a str,
    },
    NestedJws {
        header: &'a Value,
        token: &'a JwsToken,
    },
}

const ENCRYPTED_BODY: &str = "Detected a JWE token but no private key was provided. Please use the -K/--key flag to decrypt it.";

/// Render an inspection result. Plaintext is emitted verbatim by default;
/// headers and full output are JSON. Header selection takes precedence.
pub fn stringify(content: TokenOutput<'_>, opts: DisplayOptions) -> String {
    let value = match content {
        TokenOutput::Jws(token) => {
            if opts.header {
                token.header.clone()
            } else if opts.full {
                json!({"header": token.header, "claims": token.body})
            } else {
                token.body.clone()
            }
        }
        TokenOutput::EncryptedJwe { header } => {
            if opts.header {
                header.clone()
            } else if opts.full {
                json!({"header": header, "claims": ENCRYPTED_BODY})
            } else {
                json!(ENCRYPTED_BODY)
            }
        }
        TokenOutput::DecryptedJwe { header, payload } => {
            if opts.header {
                header.clone()
            } else if opts.full {
                json!({"header": header, "payload": payload})
            } else {
                return payload.to_owned();
            }
        }
        TokenOutput::NestedJws { header, token } => {
            if opts.header {
                json!({"jwe_header": header, "jws_header": token.header})
            } else if opts.full {
                json!({"jwe_header": header, "jws_header": token.header, "claims": token.body})
            } else {
                token.body.clone()
            }
        }
    };
    if opts.pretty {
        to_string_pretty(&value).expect("serializing a serde_json::Value cannot fail")
    } else {
        value.to_string()
    }
}
