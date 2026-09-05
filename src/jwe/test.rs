use crate::jw_error::JwtParseError;
use crate::jw_parser::parse_jwe;
use crate::jwe::decrypt_jwe;
use crate::jwe::handle_jwe;
use crate::jwe::jwe_handler::{JweHeader, JweToken};

const EXAMPLE_JWE: &str = include_str!("tests/fixtures/simple_token.txt");
const EXAMPLE_JWE_KEY: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.pem");
const EXAMPLE_JWE_KEY_DER: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.der");
const EXAMPLE_JWE_KEY_JWK: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.jwk");
const AESKW_JWE: &str = include_str!("tests/fixtures/aeskw_token.txt");
const AESKW_JWE_KEK_JWK: &[u8] = include_bytes!("tests/fixtures/aeskw_kek.json");
const GCMKW_JWE: &str = include_str!("tests/fixtures/gcmkw_token.txt");
const GCMKW_JWE_KEK: &[u8] = include_bytes!("tests/fixtures/gcmkw_kek.key");
const DIR_JWE: &str = include_str!("tests/fixtures/dir_token.txt");
const DIR_JWE_CEK: &[u8] = include_bytes!("tests/fixtures/dir_cek.key");

/// Build an authenticated AES-256-GCM token with independently chosen wrapped
/// key bytes, so invalid key-management inputs still have valid content tags.
fn aes256_token(header: serde_json::Value, cek: &[u8; 32], wrapped: Vec<u8>) -> String {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let mut compact = biscuit::Compact::default();
    compact.push(&serde_json::to_vec(&header).unwrap()).unwrap();
    let iv = [5u8; 12];
    let encrypted = Aes256Gcm::new_from_slice(cek)
        .unwrap()
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: b"authenticated test payload",
                aad: compact.parts[0].as_ref(),
            },
        )
        .unwrap();
    let boundary = encrypted.len() - 16;
    for part in [
        wrapped,
        iv.to_vec(),
        encrypted[..boundary].to_vec(),
        encrypted[boundary..].to_vec(),
    ] {
        compact.push(&part).unwrap();
    }
    compact.encode()
}

#[test]
fn aes_kw_rejects_empty_and_short_unwrapped_keys() {
    use crate::jw_error::{JweCryptoError, JweError};
    use aes_kw::{KeyInit, KwAes128};
    let header = serde_json::json!({"alg": "A128KW", "enc": "A256GCM"});
    let token = aes256_token(header.clone(), &[0; 32], vec![0xa6; 8]);
    for byte in [2, 7, 99] {
        assert!(matches!(
            handle_jwe(&token, Some(vec![byte; 16])),
            Err(JweError::Crypto(JweCryptoError::WrappedCekLengthMismatch {
                expected: 40,
                actual: 8
            }))
        ));
    }
    let kek = [2u8; 16];
    let mut wrapped = [0u8; 24];
    KwAes128::new_from_slice(&kek)
        .unwrap()
        .wrap_key(&[3; 16], &mut wrapped)
        .unwrap();
    let mut cek = [0u8; 32];
    cek[..16].fill(3);
    let token = aes256_token(header, &cek, wrapped.to_vec());
    assert!(matches!(
        handle_jwe(&token, Some(kek.to_vec())),
        Err(JweError::Crypto(JweCryptoError::WrappedCekLengthMismatch {
            expected: 40,
            actual: 24
        }))
    ));
}

#[test]
fn assert_parse_jwe_header_fields() {
    let token = EXAMPLE_JWE.trim();
    let parsed = parse_jwe(token).unwrap();
    let header: JweHeader = serde_json::from_str(&parsed.header).unwrap();

    assert_eq!(header.alg, "RSA-OAEP-256");
    assert_eq!(header.enc, "A256GCM");
}

#[test]
fn aes_kw_requires_the_key_size_declared_by_alg() {
    use crate::jw_error::{JweCryptoError, JweError};
    use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
    let cek = [3u8; 32];
    for actual in [16, 24, 32] {
        let kek = vec![2u8; actual];
        let mut wrapped = [0u8; 40];
        match actual {
            16 => KwAes128::new_from_slice(&kek)
                .unwrap()
                .wrap_key(&cek, &mut wrapped),
            24 => KwAes192::new_from_slice(&kek)
                .unwrap()
                .wrap_key(&cek, &mut wrapped),
            _ => KwAes256::new_from_slice(&kek)
                .unwrap()
                .wrap_key(&cek, &mut wrapped),
        }
        .unwrap();
        for (alg, expected) in [("A128KW", 16), ("A192KW", 24), ("A256KW", 32)] {
            let token = aes256_token(
                serde_json::json!({"alg": alg, "enc": "A256GCM"}),
                &cek,
                wrapped.to_vec(),
            );
            let result = handle_jwe(&token, Some(kek.clone()));
            if actual == expected {
                assert_eq!(result.unwrap().payload_string, "authenticated test payload");
            } else {
                assert!(
                    matches!(result, Err(JweError::Crypto(JweCryptoError::KekLengthMismatch {
                    expected: e, actual: a, ..
                })) if e == expected && a == actual)
                );
            }
        }
    }
}

#[test]
fn assert_handle_jwe_decrypts_payload() {
    let token = EXAMPLE_JWE.trim();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
    assert!(!decrypted.is_jwt_body);
}

#[test]
fn assert_handle_jwe_without_key_fails() {
    let token = EXAMPLE_JWE.trim();
    let err = handle_jwe(token, None).unwrap_err();
    assert!(err.to_string().contains("--key"));
}

#[test]
fn assert_decrypt_jwe_accepts_pre_parsed_token() {
    // The parsed token is self-contained: decrypt_jwe needs no access to
    // the original string, because JweToken carries its raw compact form.
    let parsed = parse_jwe(EXAMPLE_JWE.trim()).unwrap();
    let decrypted = decrypt_jwe(&parsed, Some(EXAMPLE_JWE_KEY.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");

    // And the dir fixture exercises the biscuit path through the shared parts:
    let parsed = parse_jwe(DIR_JWE.trim()).unwrap();
    let decrypted = decrypt_jwe(&parsed, Some(DIR_JWE_CEK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "super secret dir payload");
}

#[test]
fn assert_handle_jwe_decrypts_payload_with_der_key() {
    // RSA-OAEP-256 token decrypted with the same key in PKCS#8 DER format.
    let token = EXAMPLE_JWE.trim();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY_DER.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
}

#[test]
fn assert_handle_jwe_decrypts_payload_with_jwk_key() {
    // RSA-OAEP-256 token decrypted with the same key as a JWK (n/e/d only,
    // primes recovered by the rsa crate).
    let token = EXAMPLE_JWE.trim();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY_JWK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
}

#[test]
fn assert_handle_jwe_aes_kw_decrypts_payload_with_jwk_key() {
    // A128KW token decrypted with a symmetric key provided as an oct JWK.
    let token = AESKW_JWE.trim();
    let decrypted = handle_jwe(token, Some(AESKW_JWE_KEK_JWK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "aes-kw secret payload");
    assert!(!decrypted.is_jwt_body);
}

#[test]
fn assert_handle_jwe_dir_decrypts_payload() {
    // `dir` tokens have an empty encrypted-key segment: the raw key file is
    // the content-encryption key itself.
    let token = DIR_JWE.trim();
    let decrypted = handle_jwe(token, Some(DIR_JWE_CEK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "super secret dir payload");
    assert!(!decrypted.is_jwt_body);
}

#[test]
fn assert_handle_jwe_gcmkw_with_rfc7518_params_reports_limitation() {
    // Known biscuit limitation: RFC 7518 §4.7 encodes the GCMKW iv/tag
    // protected-header parameters as base64url strings, but biscuit only
    // understands them as byte arrays. Standards-compliant tokens must fail
    // with a clear error, not biscuit's cryptic deserialization message.
    let token = GCMKW_JWE.trim();
    let err = handle_jwe(token, Some(GCMKW_JWE_KEK.to_vec())).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("A128GCMKW"));
    assert!(msg.contains("RFC 7518"));
    assert!(msg.contains("known limitation"));
}

#[test]
fn assert_handle_jwe_accepts_surrounding_whitespace() {
    // Declared behavior delta: the old implementation forwarded the
    // untrimmed string to biscuit on the dir/GCMKW path, so a token with
    // surrounding whitespace failed with a cryptic
    // Crypto(DecryptionFailed("invalid symbol at ...")) error. Parsing now
    // trims once and biscuit consumes the shared parts, so whitespace is
    // tolerated end-to-end.
    let token = format!(" {}\n", DIR_JWE.trim());
    let decrypted = handle_jwe(&token, Some(DIR_JWE_CEK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "super secret dir payload");
}

#[test]
fn assert_jwe_token_new_enforces_the_input_contract() {
    // The grammar guarantees a 5-segment shape on the parse_token path;
    // direct callers of JweToken::new must get the same classification
    // parse_token would report, not a silently truncated token.
    // 6 segments: the sixth would previously be ignored.
    let err = JweToken::new("e30.e30.e30.e30.e30.bXk").unwrap_err();
    assert!(matches!(err, JwtParseError::WrongPartCount { found: 6 }));
    // 4 segments: previously a swallowed "Out of bounds" as InvalidSegment.
    let err = JweToken::new("e30.e30.e30.e30").unwrap_err();
    assert!(matches!(err, JwtParseError::WrongPartCount { found: 4 }));
    // The empty string splits as a single (empty) segment.
    let err = JweToken::new("").unwrap_err();
    assert!(matches!(err, JwtParseError::WrongPartCount { found: 1 }));
    // Empty header segment: previously a token with header="" and aad=[]
    // was built successfully.
    let err = JweToken::new(".e30.e30.e30.e30").unwrap_err();
    assert!(matches!(err, JwtParseError::InvalidSegment));
}
