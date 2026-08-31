use crate::jw_parser::get_base64;
use base64::Engine as _;
use biscuit::jwk::{
    AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, JWK,
};
use biscuit::Empty;
use p256::elliptic_curve::sec1::ToSec1Point;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::json;

use crate::jw_error::JweCryptoError;

pub fn load_key(bytes: &[u8]) -> Result<JWK<Empty>, JweCryptoError> {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();

    if trimmed.starts_with("-----BEGIN") {
        load_pem(trimmed)
    } else if trimmed.starts_with('{') {
        serde_json::from_slice(bytes).map_err(|e| JweCryptoError::InvalidKey(e.to_string()))
    } else if let Ok(jwk) = load_der(bytes) {
        Ok(jwk)
    } else if matches!(bytes.len(), 16 | 24 | 32) {
        Ok(JWK::new_octet_key(bytes, Empty {}))
    } else {
        Err(JweCryptoError::InvalidKey(format!("unrecognized key format ({} bytes); expected PEM, DER, JWK, or a symmetric key of 16/24/32 bytes", bytes.len())))
    }
}

fn load_pem(pem: &str) -> Result<JWK<Empty>, JweCryptoError> {
    if let Ok(key) =
        RsaPrivateKey::from_pkcs1_pem(pem).or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
    {
        return rsa_to_jwk(&key);
    }
    if let Ok(key) = p256::SecretKey::from_pem(pem) {
        return Ok(ec_p256_to_jwk(&key));
    }
    if let Ok(key) = p384::SecretKey::from_pem(pem) {
        return Ok(ec_p384_to_jwk(&key));
    }
    Err(JweCryptoError::InvalidKey("unsupported PEM key".into()))
}

fn load_der(bytes: &[u8]) -> Result<JWK<Empty>, JweCryptoError> {
    if let Ok(key) =
        RsaPrivateKey::from_pkcs1_der(bytes).or_else(|_| RsaPrivateKey::from_pkcs8_der(bytes))
    {
        return rsa_to_jwk(&key);
    }
    if let Ok(key) = p256::SecretKey::from_der(bytes) {
        return Ok(ec_p256_to_jwk(&key));
    }
    if let Ok(key) = p384::SecretKey::from_der(bytes) {
        return Ok(ec_p384_to_jwk(&key));
    }
    Err(JweCryptoError::InvalidKey("unsupported DER key".into()))
}

fn rsa_to_jwk(key: &RsaPrivateKey) -> Result<JWK<Empty>, JweCryptoError> {
    let b64 = |v: &rsa::BigUint| get_base64().encode(v.to_bytes_be());
    let params = json!({
            "kty": "RSA",
            "n": b64(key.n()),
            "e": b64(key.e()),
            "d": b64(key.d()),
        "additional": {}
    });

    serde_json::from_value::<JWK<Empty>>(params)
        .map_err(|e| JweCryptoError::InvalidKey(e.to_string()))
}

fn ec_p256_to_jwk(key: &p256::SecretKey) -> JWK<Empty> {
    let public = p256::PublicKey::from(key); // arithmetic
    let point = public.to_sec1_point(false); // x || y non compresso
    JWK {
        common: Default::default(),
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
            d: Some(key.to_bytes().to_vec()),
        }),
        additional: Empty {},
    }
}

fn ec_p384_to_jwk(key: &p384::SecretKey) -> JWK<Empty> {
    let public = p384::PublicKey::from(key);
    let point = public.to_sec1_point(false);
    JWK {
        common: Default::default(),
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P384,
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
            d: Some(key.to_bytes().to_vec()),
        }),
        additional: Empty {},
    }
}
