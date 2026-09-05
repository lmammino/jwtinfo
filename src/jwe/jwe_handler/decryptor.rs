use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key as AesKey, Nonce};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use biscuit::jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm};
use biscuit::jwe::Compact as JweCompact;
use biscuit::jwk::JWK;
use biscuit::{Compact, Empty};
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

use crate::jw_error::JweCryptoError;

fn aes_kw_unwrap_cek(
    kek: &[u8],
    key_encrypted: &[u8],
    cek_len: usize,
) -> Result<Vec<u8>, JweCryptoError> {
    // AES-KW adds an eight-byte integrity register to the CEK. In particular,
    // reject an integrity register alone before the dependency can unwrap it.
    if key_encrypted.len() != cek_len + 8 {
        return Err(JweCryptoError::WrappedCekLengthMismatch {
            expected: cek_len + 8,
            actual: key_encrypted.len(),
        });
    }
    let mut buf = vec![0u8; cek_len];
    let res = match kek.len() {
        16 => {
            let k: [u8; 16] = kek
                .try_into()
                .map_err(|_| JweCryptoError::InvalidKey("invalid AES-KW key length".into()))?;
            KwAes128::new((&k).into()).unwrap_key(key_encrypted, &mut buf)
        }
        24 => {
            let k: [u8; 24] = kek
                .try_into()
                .map_err(|_| JweCryptoError::InvalidKey("invalid AES-KW key length".into()))?;
            KwAes192::new((&k).into()).unwrap_key(key_encrypted, &mut buf)
        }
        32 => {
            let k: [u8; 32] = kek
                .try_into()
                .map_err(|_| JweCryptoError::InvalidKey("invalid AES-KW key length".into()))?;
            KwAes256::new((&k).into()).unwrap_key(key_encrypted, &mut buf)
        }
        _ => {
            return Err(JweCryptoError::InvalidKey(
                "AES-KW requires a 16/24/32-byte key".into(),
            ))
        }
    };
    let cek = res.map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))?;
    if cek.len() != cek_len {
        return Err(JweCryptoError::CekLengthMismatch {
            expected: cek_len,
            actual: cek.len(),
        });
    }
    Ok(cek.to_vec())
}

pub fn decrypt_aes_kw(
    key_bytes: &[u8],
    aad: &[u8],
    key_encrypted: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    enc: &str,
) -> Result<Vec<u8>, JweCryptoError> {
    // CEK length is dictated by the content-encryption algorithm.
    let cek_len = match enc {
        "A128GCM" => 16,
        "A256GCM" => 32,
        other => return Err(JweCryptoError::UnsupportedAlgorithm(other.to_string())),
    };
    let cek = aes_kw_unwrap_cek(key_bytes, key_encrypted, cek_len)?;
    decrypt_gcm_content(&cek, aad, iv, ciphertext, tag, enc)
}

/// Unwraps the CEK with RSA-OAEP (`RSA-OAEP` uses SHA-1, `RSA-OAEP-256` uses SHA-256).
///
/// Note: `biscuit` does not implement RSA key management (its `unwrap_key`
/// only supports `dir` and GCMKW), so this path uses the `rsa` crate directly.
pub fn decrypt_rsa_oaep(
    key: &RsaPrivateKey,
    key_encrypted: &[u8],
    alg: &str,
) -> Result<Vec<u8>, JweCryptoError> {
    let padding = match alg {
        "RSA-OAEP" => Oaep::new::<Sha1>(),
        "RSA-OAEP-256" => Oaep::new::<Sha256>(),
        other => return Err(JweCryptoError::UnsupportedAlgorithm(other.to_string())),
    };

    key.decrypt(padding, key_encrypted)
        .map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))
}

/// Decrypts the payload with AES-GCM (`A128GCM`/`A256GCM`), using the
/// Base64url-encoded protected header as AAD.
pub fn decrypt_gcm_content(
    cek: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    enc: &str,
) -> Result<Vec<u8>, JweCryptoError> {
    let payload = Payload {
        msg: &[ciphertext, tag].concat(),
        aad,
    };
    let iv_array: [u8; 12] = iv.try_into().map_err(|_| JweCryptoError::InvalidIvLength)?;
    let nonce = Nonce::from(iv_array);

    let res = match enc {
        "A128GCM" => {
            let key: [u8; 16] = cek
                .try_into()
                .map_err(|_| JweCryptoError::CekLengthMismatch {
                    expected: 16,
                    actual: cek.len(),
                })?;
            Aes128Gcm::new(&AesKey::<Aes128Gcm>::from(key)).decrypt(&nonce, payload)
        }
        "A256GCM" => {
            let key: [u8; 32] = cek
                .try_into()
                .map_err(|_| JweCryptoError::CekLengthMismatch {
                    expected: 32,
                    actual: cek.len(),
                })?;
            Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(key)).decrypt(&nonce, payload)
        }
        other => return Err(JweCryptoError::UnsupportedAlgorithm(other.to_string())),
    };
    res.map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))
}

fn parse_alg<T>(name: &str) -> Result<T, JweCryptoError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(serde_json::Value::String(name.to_string()))
        .map_err(|_| JweCryptoError::UnsupportedAlgorithm(name.to_string()))
}

pub fn decrypt_with_biscuit(
    compact: &Compact,
    jwk: &JWK<Empty>,
    alg: &str,
    enc: &str,
) -> Result<Vec<u8>, JweCryptoError> {
    // Feed biscuit the parts we already hold (from the single split done at
    // parse time) instead of a string it would re-split.
    let compact = JweCompact::<Vec<u8>, Empty>::Encrypted(compact.clone());
    let cek_alg: KeyManagementAlgorithm = parse_alg(alg)?;
    let enc_alg: ContentEncryptionAlgorithm = parse_alg(enc)?;
    let decrypted = compact
        .into_decrypted(jwk, cek_alg, enc_alg)
        .map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))?;
    decrypted
        .payload()
        .cloned()
        .map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))
}
