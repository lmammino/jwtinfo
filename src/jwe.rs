pub mod jwe_handler;

use crate::jwe::jwe_handler::{AlgorithmFactory, JweHeader};

use crate::jw_error::JweError;
use crate::jw_parser::parse_jwe;

/// The result of decrypting a JWE payload.
pub struct DecryptedJwe {
    /// The decrypted plaintext payload.
    pub payload_string: String,
    /// `true` when the JWE `cty` header is `"jwt"`, i.e. the payload is a nested JWT.
    pub is_jwt_body: bool,
}

/// Decrypts a JWE token using the provided private key or CEK.
///
/// Returns the plaintext payload along with whether it is a nested JWT
/// (based on the `cty` header).
pub fn handle_jwe(token: String, key: Vec<u8>) -> Result<DecryptedJwe, JweError> {
    let jwe_token = parse_jwe(token.as_str())?;
    let jwe_header: JweHeader = serde_json::from_str(&jwe_token.header)?;
    let cty = jwe_header.cty;
    let is_jwt_body = match cty {
        Some(cty) => cty.to_lowercase() == "jwt",
        None => false,
    };
    let key_decryptor = AlgorithmFactory::get_key_decryptor(jwe_header.alg.as_str())?;
    let key_decrypted = key_decryptor.decrypt_cek(&key, &jwe_token.key_encrypted)?;
    let content_decryptor = AlgorithmFactory::get_content_decryptor(jwe_header.enc.as_str())?;
    let cipher = jwe_token.decrypt_content(&*content_decryptor, &key_decrypted)?;
    let payload_string = String::from_utf8(cipher)?;
    Ok(DecryptedJwe {
        payload_string,
        is_jwt_body,
    })
}

#[cfg(test)]
mod test;
