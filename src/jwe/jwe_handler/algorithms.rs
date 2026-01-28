use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce,
};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;
use std::{convert::TryInto, error::Error};

pub type CryptoResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub trait KeyDecryptor {
    fn decrypt_cek(&self, input_key: &[u8], encrypted_key: &[u8]) -> CryptoResult<Vec<u8>>;
}

pub trait ContentDecryptor {
    fn decrypt_payload(
        &self,
        cek: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> CryptoResult<Vec<u8>>;
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
    ) -> CryptoResult<Vec<u8>> {
        if cek.len() != self.key_len {
            return Err("Cek length mismatch".into());
        }

        let payload_concat = [ciphertext, tag].concat();
        let payload = Payload {
            msg: &payload_concat,
            aad,
        };

        let iv_array: [u8; 12] = iv
            .try_into()
            .map_err(|_| "IV length invalid: must be 12 bytes")?;

        let nonce = Nonce::from(iv_array);

        match self.key_len {
            16 => {
                let key_array: [u8; 16] = cek
                    .try_into()
                    .map_err(|_| "CEK length mismatch: expected 16 bytes (A128GCM)")?;
                let key = Key::<Aes128Gcm>::from(key_array);
                Aes128Gcm::new(&key).decrypt(&nonce, payload)
            }
            32 => {
                let key_array: [u8; 32] = cek
                    .try_into()
                    .map_err(|_| "CEK length mismatch: expected 32 bytes (A256GCM)")?;
                let key = Key::<Aes256Gcm>::from(key_array);
                Aes256Gcm::new(&key).decrypt(&nonce, payload)
            }
            _ => return Err(format!("Unsupported key length: {}", self.key_len).into()),
        }
        .map_err(|e| format!("Decryption failed: {}", e).into())
    }
}

pub struct DirectKeyDecryptor;

impl KeyDecryptor for DirectKeyDecryptor {
    fn decrypt_cek(&self, input_key: &[u8], encrypted_key: &[u8]) -> CryptoResult<Vec<u8>> {
        if !encrypted_key.is_empty() {
            return Err("With 'dir' algorithm, encrypted_key must be empty".into());
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
    fn decrypt_cek(&self, input_key: &[u8], encrypted_key: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_str = std::str::from_utf8(input_key)
            .map_err(|_| "The RSA key received is not a valid UTF-8")?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(key_str)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(key_str))
            .map_err(|e| format!("Error while loading RSA key: {}", e))?;

        let padding = match self.alg_name.as_str() {
            "RSA-OAEP" => Oaep::new::<Sha1>(),
            "RSA-OAEP-256" => Oaep::new::<Sha256>(),
            _ => return Err(format!("Algorithm not supported: {}", self.alg_name).into()),
        };

        private_key
            .decrypt(padding, encrypted_key)
            .map_err(|e| format!("Failed RSA decrypt: {}", e).into())
    }
}

pub struct AlgorithmFactory;

impl AlgorithmFactory {
    pub fn get_key_decryptor(alg: &str) -> Result<Box<dyn KeyDecryptor>, String> {
        match alg {
            "dir" => Ok(Box::new(DirectKeyDecryptor)),
            "RSA-OAEP" | "RSA-OAEP-256" => Ok(Box::new(RsaKeyDecryptor::new(alg))),
            _ => Err(format!("Unsupported alg: {}", alg)),
        }
    }

    pub fn get_content_decryptor(enc: &str) -> Result<Box<dyn ContentDecryptor>, String> {
        match enc {
            "A128GCM" => Ok(Box::new(AesGcmContentDecryptor::new(16))),
            "A256GCM" => Ok(Box::new(AesGcmContentDecryptor::new(32))),
            _ => Err(format!("Unsupported enc: {}", enc)),
        }
    }
}
