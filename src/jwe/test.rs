use crate::jw_parser::parse_jwe;
use crate::jwe::handle_jwe;
use crate::jwe::jwe_handler::JweHeader;

const EXAMPLE_JWE: &str = include_str!("examples/example_token.txt");
const EXAMPLE_JWE_KEY: &[u8] = include_bytes!("examples/example_priv.pem");

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
    let decrypted = handle_jwe(token, EXAMPLE_JWE_KEY.to_vec()).unwrap();
    assert_eq!(decrypted, "Questo e' un messaggio super segreto!");
}
