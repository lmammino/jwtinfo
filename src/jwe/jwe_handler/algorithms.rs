use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce,
};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

use crate::jw_error::JweCryptoError;

pub trait KeyDecryptor {
    fn decrypt_cek(
        &self,
        input_key: &[u8],
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>, JweCryptoError>;
}

pub trait ContentDecryptor {
    fn decrypt_payload(
        &self,
        cek: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JweCryptoError>;
}

pub struct AesGcmContentDecryptor {
    key_len: usize,
}

impl AesGcmContentDecryptor {
    pub fn new(key_len: usize) -> Self {
        Self { key_len }
    }
}

impl ContentDecryptor for AesGcmContentDecryptor {
    fn decrypt_payload(
        &self,
        cek: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JweCryptoError> {
        let payload_concat = [ciphertext, tag].concat();
        let payload = Payload {
            msg: &payload_concat,
            aad,
        };

        let iv_array: [u8; 12] = iv.try_into().map_err(|_| JweCryptoError::InvalidIvLength)?;

        let nonce = Nonce::from(iv_array);

        match self.key_len {
            16 => {
                let key_array: [u8; 16] =
                    cek.try_into()
                        .map_err(|_| JweCryptoError::CekLengthMismatch {
                            expected: self.key_len,
                            actual: cek.len(),
                        })?;
                let key = Key::<Aes128Gcm>::from(key_array);
                Aes128Gcm::new(&key).decrypt(&nonce, payload)
            }
            32 => {
                let key_array: [u8; 32] =
                    cek.try_into()
                        .map_err(|_| JweCryptoError::CekLengthMismatch {
                            expected: self.key_len,
                            actual: cek.len(),
                        })?;
                let key = Key::<Aes256Gcm>::from(key_array);
                Aes256Gcm::new(&key).decrypt(&nonce, payload)
            }
            _ => return Err(JweCryptoError::UnsupportedKeyLength(self.key_len)),
        }
        .map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))
    }
}

pub struct DirectKeyDecryptor;

impl KeyDecryptor for DirectKeyDecryptor {
    fn decrypt_cek(
        &self,
        input_key: &[u8],
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>, JweCryptoError> {
        if !encrypted_key.is_empty() {
            return Err(JweCryptoError::InvalidRsaKey("".to_string()));
        }
        Ok(input_key.to_vec())
    }
}

pub struct RsaKeyDecryptor {
    alg_name: String,
}

impl RsaKeyDecryptor {
    pub fn new(alg_name: &str) -> Self {
        Self {
            alg_name: alg_name.to_string(),
        }
    }
}

impl KeyDecryptor for RsaKeyDecryptor {
    fn decrypt_cek(
        &self,
        input_key: &[u8],
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>, JweCryptoError> {
        let key_str = std::str::from_utf8(input_key)
            .map_err(|e| JweCryptoError::InvalidRsaKey(e.to_string()))?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(key_str)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(key_str))
            .map_err(|e| JweCryptoError::InvalidRsaKey(e.to_string()))?;

        let padding = match self.alg_name.as_str() {
            "RSA-OAEP" => Oaep::new::<Sha1>(),
            "RSA-OAEP-256" => Oaep::new::<Sha256>(),
            _ => {
                return Err(JweCryptoError::UnsupportedAlgorithm(
                    self.alg_name.to_string(),
                ))
            }
        };

        private_key
            .decrypt(padding, encrypted_key)
            .map_err(|e| JweCryptoError::DecryptionFailed(e.to_string()))
    }
}

pub struct AlgorithmFactory;

impl AlgorithmFactory {
    pub fn get_key_decryptor(alg: &str) -> Result<Box<dyn KeyDecryptor>, JweCryptoError> {
        match alg {
            "dir" => Ok(Box::new(DirectKeyDecryptor)),
            "RSA-OAEP" | "RSA-OAEP-256" => Ok(Box::new(RsaKeyDecryptor::new(alg))),
            _ => Err(JweCryptoError::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    pub fn get_content_decryptor(enc: &str) -> Result<Box<dyn ContentDecryptor>, JweCryptoError> {
        match enc {
            "A128GCM" => Ok(Box::new(AesGcmContentDecryptor::new(16))),
            "A256GCM" => Ok(Box::new(AesGcmContentDecryptor::new(32))),
            _ => Err(JweCryptoError::UnsupportedAlgorithm(enc.to_string())),
        }
    }
}
