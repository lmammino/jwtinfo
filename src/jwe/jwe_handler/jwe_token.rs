use biscuit::Compact;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::jw_error::JwtParseError;

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
///
/// The original compact parts and their decoded values are kept together
/// and cannot be mutated. Manual decryptors use the decoded values and the
/// original protected header as AAD; biscuit consumes the compact parts.
/// Biscuit decodes those parts again internally. This representation keeps
/// both backends consistent; it does not promise a particular scan count.
#[derive(Debug, PartialEq, Eq)]
pub struct JweToken {
    /// biscuit's split of the compact serialization: the five raw segments.
    compact: Compact,
    /// The Base64url-decoded protected header, as a JSON string.
    header: String,
    /// The encrypted content-encryption key (empty for `dir`).
    key_encrypted: Vec<u8>,
    /// The initialization vector.
    iv: Vec<u8>,
    /// The encrypted ciphertext.
    ciphertext: Vec<u8>,
    /// The authentication tag.
    tag: Vec<u8>,
}

impl JweToken {
    /// The decoded protected header. Parsed token parts are immutable so
    /// both decryption backends always observe the same authenticated data.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// The wrapped content-encryption key, empty for `dir`.
    pub fn key_encrypted(&self) -> &[u8] {
        &self.key_encrypted
    }

    /// The initialization vector.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// The encrypted payload.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The content authentication tag.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Instantiates a `JweToken` from the raw compact string alone.
    ///
    /// Checks the five-part shape and decodes each segment. Call
    /// [`crate::jw_parser::parse_token`] for the full compact grammar and
    /// surrounding-whitespace handling. Algorithm-specific checks happen
    /// during decryption.
    ///
    /// # Errors
    ///
    /// Returns [`JwtParseError::WrongPartCount`] when the input does not
    /// split into exactly five segments, and [`JwtParseError::InvalidSegment`]
    /// when the header segment is empty, a segment cannot be
    /// base64url-decoded, or the header is not valid UTF-8.
    pub fn new(raw: &str) -> Result<Self, JwtParseError> {
        let compact = Compact::decode(raw);
        if compact.len() != 5 {
            return Err(JwtParseError::WrongPartCount {
                found: compact.len(),
            });
        }
        if compact.parts[0].is_empty() {
            return Err(JwtParseError::InvalidSegment);
        }
        let invalid = |_| JwtParseError::InvalidSegment;
        let header = String::from_utf8(compact.part::<Vec<u8>>(0).map_err(invalid)?)
            .map_err(|_| JwtParseError::InvalidSegment)?;
        let segment = |index: usize| compact.part::<Vec<u8>>(index).map_err(invalid);
        Ok(Self {
            header,
            key_encrypted: segment(1)?,
            iv: segment(2)?,
            ciphertext: segment(3)?,
            tag: segment(4)?,
            compact,
        })
    }

    /// The full compact serialization the token was parsed from, re-derived
    /// from the raw segments.
    pub fn raw(&self) -> String {
        self.compact.encode()
    }

    /// The authenticated associated data: the raw Base64url-encoded protected
    /// header segment, i.e. the first segment of the compact form
    /// (RFC 7516 §5.1, step 14).
    ///
    /// Indexing is infallible: `new` only returns after `part(4)` succeeds,
    /// so every live `JweToken` holds exactly five parts.
    pub fn aad(&self) -> &[u8] {
        self.compact.parts[0].as_ref()
    }

    /// biscuit's split of the compact form, for the decryptors that consume
    /// the parts directly (no string re-parsing).
    pub(crate) fn compact(&self) -> &Compact {
        &self.compact
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
