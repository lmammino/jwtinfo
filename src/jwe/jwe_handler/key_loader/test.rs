use super::*;

const RSA_PEM: &[u8] = include_bytes!("../../tests/fixtures/priv_simple_token.pem");
const RSA_DER: &[u8] = include_bytes!("../../tests/fixtures/priv_simple_token.der");
const RSA_JWK: &[u8] = include_bytes!("../../tests/fixtures/priv_simple_token.jwk");
const OCT_JWK: &[u8] = include_bytes!("../../tests/fixtures/aeskw_kek.json");
const EC_PEM: &[u8] = include_bytes!("../../tests/fixtures/ec_key.pem");
const EC_JWK: &[u8] = include_bytes!("../../tests/fixtures/ec_key.jwk");

#[test]
fn raw_bytes_load_as_symmetric() {
    for len in [16usize, 24, 32] {
        match load_key(&vec![0x42; len]).unwrap() {
            LoadedKey::Symmetric(bytes) => assert_eq!(bytes.len(), len),
            LoadedKey::Rsa(_) => panic!("expected a symmetric key"),
        }
    }
}

#[test]
fn oct_jwk_loads_as_symmetric() {
    assert!(matches!(load_key(OCT_JWK), Ok(LoadedKey::Symmetric(_))));
}

#[test]
fn rsa_keys_load_as_rsa() {
    for (name, bytes) in [("PEM", RSA_PEM), ("DER", RSA_DER), ("JWK", RSA_JWK)] {
        match load_key(bytes).unwrap() {
            LoadedKey::Rsa(_) => {}
            other => panic!("expected an RSA key from the {name} fixture, got {other:?}"),
        }
    }
}

#[test]
fn ec_keys_are_rejected_clearly() {
    // No supported JWE algorithm can use EC keys: they must be rejected with
    // an explanatory error instead of loading as something unusable.
    let err = load_key(EC_PEM).unwrap_err();
    assert!(err.to_string().contains("expected an RSA private key"));

    let err = load_key(EC_JWK).unwrap_err();
    assert!(err.to_string().contains("EC keys cannot be used"));
}

#[test]
fn unrecognized_keys_are_rejected() {
    let err = load_key(b"garbage").unwrap_err();
    assert!(err.to_string().contains("unrecognized key format"));

    // Neither a valid DER structure nor a valid symmetric key length.
    let err = load_key(&[0x42; 17]).unwrap_err();
    assert!(err.to_string().contains("unrecognized key format"));
}

#[test]
fn rsa_jwk_without_private_exponent_is_rejected() {
    let jwk: serde_json::Value = serde_json::from_slice(RSA_JWK).unwrap();
    let public_only = serde_json::to_vec(&serde_json::json!({
        "kty": "RSA",
        "n": jwk["n"],
        "e": jwk["e"],
    }))
    .unwrap();
    let err = load_key(&public_only).unwrap_err();
    assert!(err.to_string().contains("missing the private exponent 'd'"));
}

#[test]
fn key_type_mismatches_are_reported() {
    let symmetric = load_key(&[0x42; 16]).unwrap();
    let err = symmetric.into_rsa("RSA-OAEP-256").unwrap_err();
    assert_eq!(
        err.to_string(),
        "Invalid key: RSA-OAEP-256 requires an RSA private key, but the key file contains a symmetric key"
    );

    let rsa = load_key(RSA_PEM).unwrap();
    let err = rsa.into_symmetric("A128KW").unwrap_err();
    assert_eq!(
        err.to_string(),
        "Invalid key: A128KW requires a symmetric key, but the key file contains an RSA private key"
    );
}
