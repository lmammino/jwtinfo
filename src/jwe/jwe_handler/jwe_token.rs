use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// The protected JWE header, deserialized from the token's first segment.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    /// Key management algorithm (e.g. `dir`, `RSA-OAEP`, `RSA-OAEP-256`).
    pub alg: String,
    /// Content encryption algorithm (e.g. `A128GCM`, `A256GCM`).
    pub enc: String,
    /// Content type; `JWT` when the plaintext payload is a nested JWT.
    pub cty: Option<String>,

    /// Any additional unprotected/unknown header members.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// A parsed (but not yet decrypted) JWE token.
#[derive(Debug, PartialEq, Eq)]
pub struct JweToken {
    /// The Base64url-decoded protected header, as a JSON string.
    pub header: String,
    /// The authenticated associated data: the raw Base64url header segment.
    pub aad: Vec<u8>,
    /// The encrypted content-encryption key (empty for `dir`).
    pub key_encrypted: Vec<u8>,
    /// The initialization vector.
    pub iv: Vec<u8>,
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// The authentication tag.
    pub tag: Vec<u8>,
}

impl JweToken {
    /// Builds a `JweToken` from its raw parts.
    pub fn new(
        header: String,
        aad: Vec<u8>,
        key_encrypted: Vec<u8>,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    ) -> Self {
        Self {
            header,
            aad,
            key_encrypted,
            iv,
            ciphertext,
            tag,
        }
    }
}
