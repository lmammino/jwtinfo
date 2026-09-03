pub mod jwe_handler;

use biscuit::jwk::JWK;
use biscuit::Empty;

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
/// The key file is loaded once (see `key_loader::load_key` for the supported
/// formats) and its material is matched against the token's `alg`:
/// RSA private keys for `RSA-OAEP`/`RSA-OAEP-256`, symmetric keys for
/// `dir`, AES-KW and GCMKW.
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
        return Err(JweCryptoError::UnsupportedAlgorithm(format!(
            "{alg} (PBES2 is not supported yet)"
        ))
        .into());
    } else {
        // Every other algorithm needs a key: load it once, then dispatch on
        // the parsed key material so that all formats (raw bytes, JWK, PEM,
        // DER) work for every algorithm.
        let key = key.ok_or(JweError::MissingKey)?;
        let loaded = key_loader::load_key(&key)?;

        if matches!(alg, "RSA-OAEP" | "RSA-OAEP-256") {
            // biscuit does not implement RSA key management: use the `rsa`
            // crate to unwrap the CEK, then decrypt the content with AES-GCM.
            let rsa_key = loaded.into_rsa(alg)?;
            let cek = decryptor::decrypt_rsa_oaep(&rsa_key, &jwe_token.key_encrypted, alg)?;
            decryptor::decrypt_gcm_content(
                &cek,
                &jwe_token.aad,
                &jwe_token.iv,
                &jwe_token.ciphertext,
                &jwe_token.tag,
                enc,
            )?
        } else if matches!(alg, "A128KW" | "A192KW" | "A256KW") {
            let kek = loaded.into_symmetric(alg)?;
            decryptor::decrypt_aes_kw(
                &kek,
                &jwe_token.aad,
                &jwe_token.key_encrypted,
                &jwe_token.iv,
                &jwe_token.ciphertext,
                &jwe_token.tag,
                enc,
            )?
        } else {
            // `dir` and GCMKW are handled by biscuit, which only accepts
            // symmetric keys (as an octet JWK).
            let kek = loaded.into_symmetric(alg)?;
            let jwk = JWK::new_octet_key(&kek, Empty {});
            decryptor::decrypt_with_biscuit(&token, &jwk, alg, enc)?
        }
    };

    let payload_string = String::from_utf8(cipher)?;
    Ok(DecryptedJwe {
        payload_string,
        is_jwt_body,
    })
}

#[cfg(test)]
mod test;
