use assert_cmd::Command;
use predicates::prelude::*;

const TEST_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA";
const TEST_JWE: &str = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJraWQiOiIxOGIxY2Y3NThjMWQ0ZWM2YmRhNjU4OTM1N2FiZGQ4NSIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.gCbxP78o3DgpDTUQbuHniuGgYpATqgGkRGy7paC6hRrz7N7eIa6sAOWDO9Fhnj-c8ocMl4cF4Jb_mv5qRPCh9r57PBqx7jOhMIMPTwJGpjcyBaqtHlZlu1vupY5tQ3Y2jGz1Ti4BnywaeEHPyIPQJtN7F7hIAORzj7IY4sIKkVXtQJZgaKW8pEHq_GCqj8i5aaiM0uJnRG3GOh3livp9Npjv9doqp3gyPa1zjrg2H1RsOGn0j2QMGvtuVfkuNwF-SoPKFECyHOq0ZK1oH2sTO8-JwvHflbIZQr5xWTpS8q7MbUXEuqURtrg0Tj-2z6tdaOLT4b3UeDufK2ar3bBfRD4-nRALtoY0ekcMyGFOS7o1Mxl3hy5sIG-EySyWeuBVy68aDWDpi9qZoQuY1TbxxakjncCOGu_Gh1l1m_mK2l_IdyXCT_GCfzFq4ZTkPZ5eydNBAPZuxBLUb4BrMb5iDdZjT7AgGOlRre_wIRHmmKm8W9nDeQQRmbIXO23JuOw9.BDCarfq2r_Uk8DHNfsNwSQ.4DuQx1cfJXadHnudrVaBss45zxyd6iouuSzZUyOeM4ikF_7hDOgwmaCma-Z97_QZBJ5DzVn9SJhKUTAqpVR3BRGAxJ_HAXU5jaTjXqbvUaxsh7Z5TgZ9eck0FIoe1lkwv51xEvYqqQ_Xojr4MAEmLuME_9ArCK9mNaMADIzOj4VoQtaDP1l26ytocc-oENifBRYGu28LbJLkyQKzyQy6FuAOtWjLM0WCXV7-o_dvj6qfeYHNBD7YBSxyqdgD8dcxMBNd2sK73YsZPHEa0V1-8zz7hm3bH3tZelpwPWScqLLW_SUH586c0FVeI6ggvqzjfLZ_Y6eQibVSdXfOtJBk22QrLsuCXbRK8G1w9t23Pwu8ukUAw4v0l7HeaW_0SJyKSPQANRP83MyFbK7fmzTYaW9TYN2JrKN-PLpd2dIFSm2Ga_EfaCwNJBm4RDMzDNrf-O0AissvYyHb0WaALiCiFCogliYqLzRB6xDb-b4964M.J7WDOFLRRPJ7lLpTfN2mOiXLDg5xtaF-sLQ4mOeN5oc";

#[test]
fn test_default_shows_body() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"foo":"bar"}"#));
}

#[test]
fn test_header_flag_shows_header() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--header")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"alg":"HS256","typ":"JWT"}"#));
}

#[test]
fn test_full_flag_shows_both_header_and_claims() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
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
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
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
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--full")
        .arg("--header")
        .arg(TEST_JWT)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_pretty_flag_formats_output() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--pretty")
        .arg(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""foo": "bar""#));
}

#[test]
fn test_stdin_input() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("-")
        .write_stdin(TEST_JWT)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"foo":"bar"}"#));
}

#[test]
fn test_invalid_jwt_returns_error() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("invalid.jwt.token")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error:"));
}

#[test]
fn test_full_flag_structure() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
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
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains("<encrypted JWE body>"));
}

#[test]
fn test_jwe_header_flag_shows_header() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--header")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""enc":"A256CBC-HS512""#))
        .stdout(predicate::str::contains(r#""alg":"RSA-OAEP""#));
}

#[test]
fn test_jwe_full_flag_shows_header_and_encrypted_message() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--full")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""header":"#))
        .stdout(predicate::str::contains(r#""claims":"#))
        .stdout(predicate::str::contains(r#""enc":"A256CBC-HS512""#))
        .stdout(predicate::str::contains("<encrypted JWE body>"));
}

#[test]
fn test_jwe_pretty_flag() {
    let mut cmd = Command::cargo_bin("jwtinfo").unwrap();
    cmd.arg("--pretty")
        .arg(TEST_JWE)
        .assert()
        .success()
        .stdout(predicate::str::contains("<encrypted JWE body>"));
}
