use assert_cmd::cargo::*;
use predicates::prelude::*;

const TEST_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA";
const TEST_JWE: &str = include_str!("../src/jwe/tests/fixtures/simple_token.txt");
const TEST_JWE_DECRYPTED: &str = "This is a super secret message!";

#[test]
fn test_default_shows_body() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"foo":"bar"}"#));
}

#[test]
fn test_header_flag_shows_header() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--header")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"alg":"HS256","typ":"JWT"}"#));
}

#[test]
fn test_full_flag_shows_both_header_and_claims() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--full")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""header":"#))
        .stdout(predicate::str::contains(r#""claims":"#))
        .stdout(predicate::str::contains(r#""alg":"HS256"#))
        .stdout(predicate::str::contains(r#""foo":"bar"#));
}

#[test]
fn test_full_flag_with_pretty() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--full")
        .arg("--pretty")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"header\": {"))
        .stdout(predicate::str::contains("\"claims\": {"))
        .stdout(predicate::str::contains(r#""alg": "HS256""#))
        .stdout(predicate::str::contains(r#""foo": "bar""#));
}

#[test]
fn test_full_and_header_flags_conflict() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--full")
        .arg("--header")
        .arg(TEST_JWT)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_pretty_flag_formats_output() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--pretty")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""foo": "bar""#));
}

#[test]
fn test_stdin_input() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("-")
        .write_stdin(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"foo":"bar"}"#));
}

#[test]
fn test_invalid_jwt_returns_error() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("invalid.jwt.token")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid Header"));
}

#[test]
fn test_full_flag_structure() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let output = cmd.arg("--full").arg(TEST_JWT).output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();

    // Parse the JSON to ensure it has the correct structure
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(json.get("header").is_some(), "Should have 'header' field");
    assert!(json.get("claims").is_some(), "Should have 'claims' field");

    let header = json.get("header").unwrap();
    assert_eq!(header.get("alg").unwrap(), "HS256");
    assert_eq!(header.get("typ").unwrap(), "JWT");

    let claims = json.get("claims").unwrap();
    assert_eq!(claims.get("foo").unwrap(), "bar");
}

// JWE (encrypted JWT) tests
#[test]
fn test_jwe_shows_encrypted_message() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Detected a JWE token but no private key was provided",
        ));
}

#[test]
fn test_jwe_header_flag_shows_header() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--header")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""enc":"A256GCM""#))
        .stdout(predicate::str::contains(r#""alg":"RSA-OAEP-256""#));
}

#[test]
fn test_jwe_full_flag_shows_header_and_encrypted_message() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--full")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""header":"#))
        .stdout(predicate::str::contains(r#""claims":"#))
        .stdout(predicate::str::contains(r#""enc":"A256GCM""#))
        .stdout(predicate::str::contains(
            "Detected a JWE token but no private key was provided",
        ));
}

#[test]
fn test_jwe_pretty_flag() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--pretty")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Detected a JWE token but no private key was provided",
        ));
}

#[test]
fn test_jwe_with_key_decrypts_payload() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/priv_simple_token.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--key")
        .arg(key_path)
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_JWE_DECRYPTED));
}

const TEST_NESTED_JWE: &str = include_str!("../src/jwe/tests/fixtures/jwe_nested_token.txt");
const TEST_NESTED_JWE_KEY: &str = "src/jwe/tests/fixtures/priv_key_nested_jwt.pem";

#[test]
fn test_nested_jwe_default_shows_inner_claims() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--key")
        .arg(TEST_NESTED_JWE_KEY)
        .arg(TEST_NESTED_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""iss":"mittente""#))
        .stdout(predicate::str::contains(
            r#""msg":"Questo e' un messaggio super segreto!""#,
        ));
}

#[test]
fn test_nested_jwe_header_flag_shows_both_headers() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--key")
        .arg(TEST_NESTED_JWE_KEY)
        .arg("--header")
        .arg(TEST_NESTED_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""jwe_header":"#))
        .stdout(predicate::str::contains(r#""jws_header":"#))
        .stdout(predicate::str::contains(r#""alg":"HS256""#));
}

#[test]
fn test_nested_jwe_full_flag_shows_complete_structure() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("--key")
        .arg(TEST_NESTED_JWE_KEY)
        .arg("--full")
        .arg(TEST_NESTED_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""jwe_header":"#))
        .stdout(predicate::str::contains(r#""jws_header":"#))
        .stdout(predicate::str::contains(r#""claims":"#))
        .stdout(predicate::str::contains(r#""iss":"mittente""#));
}

// Flag handling on decrypted JWE with a plaintext (non-JWT) payload.
#[test]
fn test_jwe_with_key_header_flag_shows_jwe_header() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/priv_simple_token.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--header")
        .arg("--key")
        .arg(key_path)
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""enc":"A256GCM""#))
        .stdout(predicate::str::contains(r#""alg":"RSA-OAEP-256""#))
        .stdout(predicate::str::contains(r#""typ":"JWE""#));
}

#[test]
fn test_jwe_with_key_full_shows_header_and_payload() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/priv_simple_token.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--full")
        .arg("--key")
        .arg(key_path)
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""header":"#))
        .stdout(predicate::str::contains(r#""payload":"#))
        .stdout(predicate::str::contains(TEST_JWE_DECRYPTED));
}

#[test]
fn test_jwe_with_key_pretty_header_flag() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/priv_simple_token.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--pretty")
        .arg("--header")
        .arg("--key")
        .arg(key_path)
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""alg": "RSA-OAEP-256""#))
        .stdout(predicate::str::contains(r#""enc": "A256GCM""#));
}

// A JWS token passed with --key must warn on stderr but still succeed.
#[test]
fn test_jws_with_key_warns_and_still_works() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/priv_simple_token.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--key")
        .arg(key_path)
        .arg(TEST_JWT)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "the --key flag is only applicable to JWE tokens",
        ))
        .stdout(predicate::str::contains(r#"{"foo":"bar"}"#));
}

// Empty base64url segments are legitimate:
// - unsecured JWTs (RFC 7518 §3, alg: none) have an empty signature;
// - dir JWEs (RFC 7516 §4.5) have an empty encrypted-key segment.
#[test]
fn test_alg_none_jws_with_empty_signature_segment() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg("eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.")
        .assert()
        .success()
        .stdout(predicate::str::contains("{\"foo\":\"bar\"}"));
}

#[test]
fn test_dir_jwe_with_empty_key_segment_decrypts() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/dir_cek.key",
        env!("CARGO_MANIFEST_DIR")
    );
    let token = include_str!("../src/jwe/tests/fixtures/dir_token.txt");
    cmd.arg("--key")
        .arg(key_path)
        .arg(token.trim())
        .assert()
        .success()
        .stdout(predicate::str::contains("super secret dir payload"));
}

#[test]
fn test_invalid_token_prints_error_once() {
    // Regression test: main() used to return the error after eprintln-ing
    // it, so the Termination impl printed it a second time in Debug form.
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let output = cmd.arg("a.b.c.d").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected 3 parts (JWS) or 5 parts (JWE) but found 4"));
    assert_eq!(
        stderr.matches("Error:").count(),
        1,
        "the error must be reported exactly once, stderr was: {stderr}"
    );
}

#[test]
fn test_wrong_key_type_reports_clear_error() {
    // A symmetric key file cannot decrypt an RSA-OAEP-256 token: the error
    // must say what the algorithm requires and what the file contains.
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/dir_cek.key",
        env!("CARGO_MANIFEST_DIR")
    );
    cmd.arg("--key")
        .arg(key_path)
        .arg(TEST_JWE)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "RSA-OAEP-256 requires an RSA private key, but the key file contains a symmetric key",
        ));
}

#[test]
fn test_jwe_without_key_shows_placeholder() {
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    cmd.arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Detected a JWE token but no private key was provided",
        ));
}

#[test]
fn test_decryption_errors_print_in_display_form() {
    // Regression test: decryption errors used to escape main via `?` and be
    // printed by the Termination impl in Debug form, e.g.
    // `Error: Crypto(UnsupportedAlgorithm("A128GCMKW: ..."))`. The CLI now
    // has a single error boundary printing every error in Display form.
    let mut cmd = cargo_bin_cmd!("jwtinfo");
    let key_path = format!(
        "{}/src/jwe/tests/fixtures/gcmkw_kek.key",
        env!("CARGO_MANIFEST_DIR")
    );
    let token = include_str!("../src/jwe/tests/fixtures/gcmkw_token.txt");
    cmd.arg("--key")
        .arg(key_path)
        .arg(token.trim())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Error: Unsupported algorithm: A128GCMKW",
        ))
        .stderr(predicate::str::contains("known limitation"))
        .stderr(
            predicate::str::contains("Crypto(")
                .and(predicate::str::contains("UnsupportedAlgorithm("))
                .not(),
        );
}
