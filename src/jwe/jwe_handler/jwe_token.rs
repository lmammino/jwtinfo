use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::jwe::jwe_handler::algorithms::{ContentDecryptor, CryptoResult};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    pub alg: String,
    pub enc: String,
    pub cty: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug)]
pub struct JweToken {
    pub header: String,
    pub aad: Vec<u8>,
    pub key_encrypted: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl JweToken {
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

    pub fn decrypt_content(
        &self,
        decryptor: &dyn ContentDecryptor,
        cek: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        decryptor.decrypt_payload(cek, &self.aad, &self.iv, &self.ciphertext, &self.tag)
    }
}
