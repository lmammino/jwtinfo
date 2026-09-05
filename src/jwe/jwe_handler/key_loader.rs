use biscuit::jwk::{AlgorithmParameters, JWK};
use biscuit::Empty;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{BigUint, RsaPrivateKey};

use crate::jw_error::JweCryptoError;

/// Key material extracted from a key file, independent of its file format.
#[derive(Debug)]
pub enum LoadedKey {
    /// Symmetric key bytes: a raw key file, or the `k` field of an `oct` JWK.
    Symmetric(Vec<u8>),
    /// An RSA private key loaded from a PEM/DER file or a JWK.
    Rsa(Box<RsaPrivateKey>),
}

impl LoadedKey {
    /// A short human-readable description, used in error messages.
    fn describe(&self) -> &'static str {
        match self {
            LoadedKey::Symmetric(_) => "a symmetric key",
            LoadedKey::Rsa(_) => "an RSA private key",
        }
    }

    /// Unwraps the RSA private key, or errors if the key file holds another
    /// kind of key.
    pub fn into_rsa(self, alg: &str) -> Result<RsaPrivateKey, JweCryptoError> {
        match self {
            LoadedKey::Rsa(k) => Ok(*k),
            other => Err(JweCryptoError::InvalidKey(format!(
                "{alg} requires an RSA private key, but the key file contains {}",
                other.describe()
            ))),
        }
    }

    /// Unwraps the symmetric key bytes, or errors if the key file holds
    /// another kind of key.
    pub fn into_symmetric(self, alg: &str) -> Result<Vec<u8>, JweCryptoError> {
        match self {
            LoadedKey::Symmetric(k) => Ok(k),
            other => Err(JweCryptoError::InvalidKey(format!(
                "{alg} requires a symmetric key, but the key file contains {}",
                other.describe()
            ))),
        }
    }
}

/// Loads a decryption key from raw file bytes, auto-detecting the format:
///
/// - PEM (RSA, PKCS#1 or PKCS#8)
/// - DER (RSA, PKCS#1 or PKCS#8)
/// - JWK (JSON Web Key, `kty` of `oct` or `RSA`)
/// - raw bytes (a symmetric key of 16/24/32 bytes)
///
/// Exact raw-key lengths take precedence over text sniffing: arbitrary key
/// bytes may start with a JSON brace, a PEM prefix, or whitespace. Supported
/// RSA encodings and JWKs containing usable symmetric keys are longer.
pub fn load_key(bytes: &[u8]) -> Result<LoadedKey, JweCryptoError> {
    if matches!(bytes.len(), 16 | 24 | 32) {
        return Ok(LoadedKey::Symmetric(bytes.to_vec()));
    }
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();

    if trimmed.starts_with("-----BEGIN") {
        load_pem(trimmed)
    } else if trimmed.starts_with('{') {
        load_jwk(trimmed)
    } else if let Ok(key) = load_der(bytes) {
        Ok(key)
    } else {
        Err(JweCryptoError::InvalidKey(format!(
            "unrecognized key format ({} bytes); expected an RSA key (PEM/DER), a JWK, or a symmetric key of 16/24/32 bytes",
            bytes.len()
        )))
    }
}

fn load_pem(pem: &str) -> Result<LoadedKey, JweCryptoError> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
        .map(|key| LoadedKey::Rsa(Box::new(key)))
        .map_err(|_| {
            JweCryptoError::InvalidKey(
                "unsupported PEM key: expected an RSA private key (PKCS#1 or PKCS#8)".into(),
            )
        })
}

fn load_der(bytes: &[u8]) -> Result<LoadedKey, JweCryptoError> {
    RsaPrivateKey::from_pkcs1_der(bytes)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(bytes))
        .map(|key| LoadedKey::Rsa(Box::new(key)))
        .map_err(|_| {
            JweCryptoError::InvalidKey(
                "unsupported DER key: expected an RSA private key (PKCS#1 or PKCS#8)".into(),
            )
        })
}

fn load_jwk(text: &str) -> Result<LoadedKey, JweCryptoError> {
    let jwk: JWK<Empty> =
        serde_json::from_str(text).map_err(|e| JweCryptoError::InvalidKey(e.to_string()))?;

    match jwk.algorithm {
        AlgorithmParameters::OctetKey(p) => Ok(LoadedKey::Symmetric(p.value)),
        AlgorithmParameters::RSA(p) => {
            // biscuit (num-bigint) and rsa (num-bigint-dig) use distinct
            // BigUint types: convert through the big-endian byte representation.
            let n = BigUint::from_bytes_be(&p.n.to_bytes_be());
            let e = BigUint::from_bytes_be(&p.e.to_bytes_be());
            let d = p
                .d
                .map(|d| BigUint::from_bytes_be(&d.to_bytes_be()))
                .ok_or_else(|| {
                    JweCryptoError::InvalidKey("RSA JWK is missing the private exponent 'd'".into())
                })?;
            let primes = match (p.p, p.q) {
                (Some(prime_p), Some(prime_q)) => vec![
                    BigUint::from_bytes_be(&prime_p.to_bytes_be()),
                    BigUint::from_bytes_be(&prime_q.to_bytes_be()),
                ],
                _ => Vec::new(),
            };
            // Without primes, `rsa` recovers them from `d` (NIST SP 800-56B C.2).
            RsaPrivateKey::from_components(n, e, d, primes)
                .map(|key| LoadedKey::Rsa(Box::new(key)))
                .map_err(|err| JweCryptoError::InvalidKey(format!("invalid RSA JWK: {err}")))
        }
        AlgorithmParameters::EllipticCurve(_) => Err(JweCryptoError::InvalidKey(
            "unsupported JWK: EC keys cannot be used by any supported JWE algorithm".into(),
        )),
        AlgorithmParameters::OctetKeyPair(_) => Err(JweCryptoError::InvalidKey(
            "unsupported JWK: OKP/EdDSA keys cannot be used by any supported JWE algorithm".into(),
        )),
    }
}

#[cfg(test)]
mod test;

/// Test-support helpers: unwrap a specific `LoadedKey` variant. The
/// panicking arms are exercised by `expect_symmetric_rejects_an_rsa_key`
/// and `expect_rsa_rejects_a_symmetric_key`, so coverage tools see both
/// arms of each match instead of an uncovered inline panic region per test.
#[cfg(test)]
impl LoadedKey {
    fn expect_symmetric(self) -> Vec<u8> {
        match self {
            LoadedKey::Symmetric(bytes) => bytes,
            other => panic!("expected a symmetric key, got {other:?}"),
        }
    }

    fn expect_rsa(self) -> RsaPrivateKey {
        match self {
            LoadedKey::Rsa(key) => *key,
            other => panic!("expected an RSA private key, got {other:?}"),
        }
    }
}
