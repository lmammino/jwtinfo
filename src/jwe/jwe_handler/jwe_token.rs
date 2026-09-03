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
    /// The full compact serialization, kept verbatim: the biscuit decryptor
    /// re-parses it for `dir`/GCMKW, and the raw protected-header segment
    /// (its first segment) doubles as the authenticated associated data.
    raw: String,
    /// The Base64url-decoded protected header, as a JSON string.
    pub header: String,
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
    /// Builds a `JweToken` from its raw compact form and decoded parts.
    pub fn new(
        raw: String,
        header: String,
        key_encrypted: Vec<u8>,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    ) -> Self {
        Self {
            raw,
            header,
            key_encrypted,
            iv,
            ciphertext,
            tag,
        }
    }

    /// The full compact serialization the token was parsed from.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The authenticated associated data: the raw Base64url-encoded protected
    /// header segment, i.e. the first segment of the compact form
    /// (RFC 7516 §5.1, step 14).
    pub fn aad(&self) -> &[u8] {
        self.raw.split('.').next().unwrap_or("").as_bytes()
    }
}
impl JweHeader {
    /// `true` when the GCMKW `iv`/`tag` parameters are carried as base64url
    /// strings, as required by RFC 7518 §4.7 (most JOSE libraries), rather
    /// than as JSON byte arrays, which is the form biscuit produces and
    /// accepts.
    ///
    /// GCMKW decryption is delegated to biscuit, which fails to deserialize
    /// the standard form; this lets us report the limitation up front with a
    /// clear error instead of a cryptic serde message.
    pub(crate) fn has_string_gcmkw_params(&self) -> bool {
        ["iv", "tag"]
            .iter()
            .any(|param| self.extra.get(*param).is_some_and(Value::is_string))
    }
}
