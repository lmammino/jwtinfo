pub mod jwe_handler;

use crate::jw_error::{JweCryptoError, JweError};
use crate::jw_parser::parse_jwe;
use crate::jwe::jwe_handler::{decryptor, key_loader, JweHeader};

/// The result of decrypting a JWE payload.
#[derive(Debug)]
pub struct DecryptedJwe {
    /// The decrypted plaintext payload.
    pub payload_string: String,
    /// `true` when the JWE `cty` header is `"jwt"`, i.e. the payload is a nested JWT.
    pub is_jwt_body: bool,
}

/// Decrypts a JWE token using the provided key.
///
/// The key is used for `dir`, RSA, EC, AES-KW and GCMKW algorithms, loaded
/// from PEM/DER/JWK or raw bytes (see `key_loader::load_key`).
pub fn handle_jwe(token: String, key: Option<Vec<u8>>) -> Result<DecryptedJwe, JweError> {
    let jwe_token = parse_jwe(token.as_str())?;
    let jwe_header: JweHeader = serde_json::from_str(&jwe_token.header)?;
    let is_jwt_body = jwe_header
        .cty
        .as_deref()
        .map(|c| c.eq_ignore_ascii_case("jwt"))
        .unwrap_or(false);

    let alg = jwe_header.alg.as_str();
    let enc = jwe_header.enc.as_str();

    let cipher = if alg.starts_with("PBES2") {
        // PBES2 (password-based) decryption is not implemented yet.
        Err(JweCryptoError::UnsupportedAlgorithm(format!(
            "{alg} (PBES2 is not supported yet)"
        )))?
    } else if matches!(alg, "RSA-OAEP" | "RSA-OAEP-256") {
        // biscuit does not implement RSA key management: use the `rsa` crate
        // to unwrap the CEK, then decrypt the content with AES-GCM.
        let key = key.ok_or(JweError::MissingKey)?;
        let cek = decryptor::decrypt_rsa_oaep(&key, &jwe_token.key_encrypted, alg)?;
        decryptor::decrypt_gcm_content(
            &cek,
            &jwe_token.aad,
            &jwe_token.iv,
            &jwe_token.ciphertext,
            &jwe_token.tag,
            enc,
        )?
    } else if matches!(alg, "A128KW" | "A192KW" | "A256KW") {
        let key = key.ok_or(JweError::MissingKey)?;
        decryptor::decrypt_aes_kw(
            &key,
            &jwe_token.aad,
            &jwe_token.key_encrypted,
            &jwe_token.iv,
            &jwe_token.ciphertext,
            &jwe_token.tag,
            enc,
        )?
    } else {
        let key = key.ok_or(JweError::MissingKey)?;
        let jwk = key_loader::load_key(&key)?;
        decryptor::decrypt_with_biscuit(&token, &jwk, alg, enc)?
    };

    let payload_string = String::from_utf8(cipher)?;
    Ok(DecryptedJwe {
        payload_string,
        is_jwt_body,
    })
}

#[cfg(test)]
mod test;
