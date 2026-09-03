use crate::jw_parser::parse_jwe;
use crate::jwe::handle_jwe;
use crate::jwe::jwe_handler::JweHeader;

const EXAMPLE_JWE: &str = include_str!("tests/fixtures/simple_token.txt");
const EXAMPLE_JWE_KEY: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.pem");
const EXAMPLE_JWE_KEY_DER: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.der");
const EXAMPLE_JWE_KEY_JWK: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.jwk");
const AESKW_JWE: &str = include_str!("tests/fixtures/aeskw_token.txt");
const AESKW_JWE_KEK_JWK: &[u8] = include_bytes!("tests/fixtures/aeskw_kek.json");
const DIR_JWE: &str = include_str!("tests/fixtures/dir_token.txt");
const DIR_JWE_CEK: &[u8] = include_bytes!("tests/fixtures/dir_cek.key");

#[test]
fn assert_parse_jwe_header_fields() {
    let token = EXAMPLE_JWE.trim();
    let parsed = parse_jwe(token).unwrap();
    let header: JweHeader = serde_json::from_str(&parsed.header).unwrap();

    assert_eq!(header.alg, "RSA-OAEP-256");
    assert_eq!(header.enc, "A256GCM");
}

#[test]
fn assert_handle_jwe_decrypts_payload() {
    let token = EXAMPLE_JWE.trim().to_string();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
    assert!(!decrypted.is_jwt_body);
}

#[test]
fn assert_handle_jwe_without_key_fails() {
    let token = EXAMPLE_JWE.trim().to_string();
    let err = handle_jwe(token, None).unwrap_err();
    assert!(err.to_string().contains("--key"));
}

#[test]
fn assert_handle_jwe_decrypts_payload_with_der_key() {
    // RSA-OAEP-256 token decrypted with the same key in PKCS#8 DER format.
    let token = EXAMPLE_JWE.trim().to_string();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY_DER.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
}

#[test]
fn assert_handle_jwe_decrypts_payload_with_jwk_key() {
    // RSA-OAEP-256 token decrypted with the same key as a JWK (n/e/d only,
    // primes recovered by the rsa crate).
    let token = EXAMPLE_JWE.trim().to_string();
    let decrypted = handle_jwe(token, Some(EXAMPLE_JWE_KEY_JWK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "This is a super secret message!");
}

#[test]
fn assert_handle_jwe_aes_kw_decrypts_payload_with_jwk_key() {
    // A128KW token decrypted with a symmetric key provided as an oct JWK.
    let token = AESKW_JWE.trim().to_string();
    let decrypted = handle_jwe(token, Some(AESKW_JWE_KEK_JWK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "aes-kw secret payload");
    assert!(!decrypted.is_jwt_body);
}

#[test]
fn assert_handle_jwe_dir_decrypts_payload() {
    // `dir` tokens have an empty encrypted-key segment: the raw key file is
    // the content-encryption key itself.
    let token = DIR_JWE.trim().to_string();
    let decrypted = handle_jwe(token, Some(DIR_JWE_CEK.to_vec())).unwrap();
    assert_eq!(decrypted.payload_string, "super secret dir payload");
    assert!(!decrypted.is_jwt_body);
}
