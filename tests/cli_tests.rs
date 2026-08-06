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
        .success()
        .stdout(predicate::str::contains("invalid.jwt.token"));
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
