use crate::jw_parser::parse_jwe;
use crate::jwe::handle_jwe;
use crate::jwe::jwe_handler::JweHeader;

const EXAMPLE_JWE: &str = include_str!("tests/fixtures/simple_token.txt");
const EXAMPLE_JWE_KEY: &[u8] = include_bytes!("tests/fixtures/priv_simple_token.pem");

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
