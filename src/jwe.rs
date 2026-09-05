pub mod jwe_handler;

use biscuit::jwk::JWK;
use biscuit::Empty;

use crate::jw_error::{JweCryptoError, JweError};
use crate::jw_parser::parse_jwe;
use crate::jwe::jwe_handler::{decryptor, key_loader, JweHeader, JweToken};

/// The result of decrypting a JWE payload.
#[derive(Debug)]
pub struct DecryptedJwe {
    /// The decrypted plaintext payload.
    pub payload_string: String,
    /// `true` when the JWE `cty` header is `"jwt"`, i.e. the payload is a nested JWT.
    pub is_jwt_body: bool,
}

/// Parses and decrypts a JWE token using the provided key.
///
/// Convenience entry point for callers holding the compact token as a
/// string; use [`decrypt_jwe`] instead if the token has already been parsed
/// (e.g. via [`crate::jw_parser::parse_jwe`]) to avoid parsing it twice.
pub fn handle_jwe(token: &str, key: Option<Vec<u8>>) -> Result<DecryptedJwe, JweError> {
    let jwe_token = parse_jwe(token)?;
    decrypt_jwe(&jwe_token, key)
}

/// Decrypts an already-parsed JWE token using the provided key.
///
/// The token carries everything the decryptors need: its compact form,
/// held as biscuit's split parts (fed directly to the `dir`/GCMKW
/// decryptor — no string is re-parsed — and used to derive the AAD), and
/// the decoded segments (consumed by the RSA-OAEP and AES-KW paths).
///
/// The key file is loaded once (see `key_loader::load_key` for the supported
/// formats) and its material is matched against the token's `alg`:
/// RSA private keys for `RSA-OAEP`/`RSA-OAEP-256`, symmetric keys for
/// `dir`, AES-KW and GCMKW.
pub fn decrypt_jwe(jwe_token: &JweToken, key: Option<Vec<u8>>) -> Result<DecryptedJwe, JweError> {
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
    } else if alg.ends_with("GCMKW") && jwe_header.has_string_gcmkw_params() {
        // Known biscuit limitation: it expects the GCMKW `iv`/`tag` protected
        // header parameters as JSON byte arrays, but RFC 7518 §4.7 encodes
        // them as base64url strings (the form produced by every other JOSE
        // library). Only biscuit-encrypted GCMKW tokens can be decrypted.
        return Err(JweCryptoError::UnsupportedAlgorithm(format!(
            "{alg}: the 'iv'/'tag' header parameters are base64url strings per RFC 7518 §4.7, \
             but biscuit (used for GCMKW decryption) only understands them as byte arrays; \
             this token cannot be decrypted (known limitation, see the README)"
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
                jwe_token.aad(),
                &jwe_token.iv,
                &jwe_token.ciphertext,
                &jwe_token.tag,
                enc,
            )?
        } else if matches!(alg, "A128KW" | "A192KW" | "A256KW") {
            let kek = loaded.into_symmetric(alg)?;
            decryptor::decrypt_aes_kw(
                &kek,
                jwe_token.aad(),
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
            decryptor::decrypt_with_biscuit(jwe_token.compact(), &jwk, alg, enc)?
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
