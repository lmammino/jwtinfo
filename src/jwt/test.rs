#[cfg(test)]
use super::*;

#[test]
fn assert_parse_successfully() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let parsed_token = parse(token).unwrap();
    assert_eq!(
        String::from("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
        parsed_token.header.to_string()
    );
    assert_eq!(
        String::from("{\"foo\":\"bar\"}"),
        parsed_token.body.to_string()
    );
}

#[test]
fn assert_parse_successfully_from_str() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let parsed_token = token.parse::<Token>().unwrap();
    assert_eq!(
        String::from("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
        parsed_token.header.to_string()
    );
    assert_eq!(
        String::from("{\"foo\":\"bar\"}"),
        parsed_token.body.to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_invalid_header() {
    let token = String::from(
        "invalid_header.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let parsed_token = parse(token);
    assert!(parsed_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Header:"));
}

#[test]
fn assert_parse_fails_due_to_invalid_body() {
    let token = String::from(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid_body.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let parsed_token = parse(token);
    assert!(parsed_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Body:"));
}

#[test]
fn assert_parse_fails_due_to_invalid_signature() {
    let token =
        String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.invalid_signature");
    let parsed_token = parse(token);
    assert!(parsed_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Signature:"));
}

#[test]
fn assert_parse_fails_due_to_more_then_three_fragment() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA.one_more_fragment");
    let parsed_token = parse(token);
    assert_eq!(
        String::from("Error: Unexpected fragment after signature"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_body() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    let parsed_token = parse(token);
    assert_eq!(
        String::from("Invalid Body: Missing token section"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_signature() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ");
    let parsed_token = parse(token);
    assert_eq!(
        String::from("Invalid Signature: Missing token section"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_invalid_json_header() {
    let token = String::from("eyJhbGc6ICJIUzI1NiIsInR5cCI6ICJKV1QifQ.eyJmb28iOiJiYXIifQ.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU");
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert!(err.starts_with("Invalid Header: JSON error"));
}

#[test]
fn assert_parse_fail_due_invalid_json_body() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXJ9.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU");
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert!(err.starts_with("Invalid Body: JSON error"));
}

#[test]
fn assert_fails_with_non_base64_header() {
    let token = String::from(
        "ĄČĘĖĮŠŲŪąčęėįšųū\x09#$#434.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Header: Base64 error, Invalid byte 196, offset 0."
    );
}

#[test]
fn assert_fails_with_non_base64_body() {
    let token = String::from(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ĄČĘĖĮŠŲŪąčęėįšųū\x09#$#434.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Body: Base64 error, Invalid byte 196, offset 0."
    );
}

#[test]
fn assert_fails_with_non_base64_signature() {
    let token = String::from(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.ĄČĘĖĮŠŲŪąčęėįšųū\x09#$#434",
    );
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Signature: Base64 error, Invalid byte 196, offset 0."
    );
}

#[test]
fn assert_fails_with_non_valid_token() {
    let token = String::from(r"I'm \x00\x09writing \x52\x75\x73\x74!\x00\x09");
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Header: Base64 error, Encoded text cannot have a 6-bit remainder."
    );
}

#[test]
fn assert_fails_with_token_from_invalid_lossy_utf8() {
    let token = String::from_utf8_lossy(
        b"\x00\x09\x52\x09\x00\x75\x00\x09\x73\x00\x09\x74\x00\x09\x00\x09",
    );
    let parsed_token = parse(token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Header: Base64 error, Invalid byte 0, offset 0."
    );
}

#[test]
fn assert_parse_jwe_with_encrypted_message() {
    // This is a real JWE token with 5 parts (header.encrypted_key.iv.ciphertext.tag)
    let token = String::from("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJraWQiOiIxOGIxY2Y3NThjMWQ0ZWM2YmRhNjU4OTM1N2FiZGQ4NSIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.gCbxP78o3DgpDTUQbuHniuGgYpATqgGkRGy7paC6hRrz7N7eIa6sAOWDO9Fhnj-c8ocMl4cF4Jb_mv5qRPCh9r57PBqx7jOhMIMPTwJGpjcyBaqtHlZlu1vupY5tQ3Y2jGz1Ti4BnywaeEHPyIPQJtN7F7hIAORzj7IY4sIKkVXtQJZgaKW8pEHq_GCqj8i5aaiM0uJnRG3GOh3livp9Npjv9doqp3gyPa1zjrg2H1RsOGn0j2QMGvtuVfkuNwF-SoPKFECyHOq0ZK1oH2sTO8-JwvHflbIZQr5xWTpS8q7MbUXEuqURtrg0Tj-2z6tdaOLT4b3UeDufK2ar3bBfRD4-nRALtoY0ekcMyGFOS7o1Mxl3hy5sIG-EySyWeuBVy68aDWDpi9qZoQuY1TbxxakjncCOGu_Gh1l1m_mK2l_IdyXCT_GCfzFq4ZTkPZ5eydNBAPZuxBLUb4BrMb5iDdZjT7AgGOlRre_wIRHmmKm8W9nDeQQRmbIXO23JuOw9.BDCarfq2r_Uk8DHNfsNwSQ.4DuQx1cfJXadHnudrVaBss45zxyd6iouuSzZUyOeM4ikF_7hDOgwmaCma-Z97_QZBJ5DzVn9SJhKUTAqpVR3BRGAxJ_HAXU5jaTjXqbvUaxsh7Z5TgZ9eck0FIoe1lkwv51xEvYqqQ_Xojr4MAEmLuME_9ArCK9mNaMADIzOj4VoQtaDP1l26ytocc-oENifBRYGu28LbJLkyQKzyQy6FuAOtWjLM0WCXV7-o_dvj6qfeYHNBD7YBSxyqdgD8dcxMBNd2sK73YsZPHEa0V1-8zz7hm3bH3tZelpwPWScqLLW_SUH586c0FVeI6ggvqzjfLZ_Y6eQibVSdXfOtJBk22QrLsuCXbRK8G1w9t23Pwu8ukUAw4v0l7HeaW_0SJyKSPQANRP83MyFbK7fmzTYaW9TYN2JrKN-PLpd2dIFSm2Ga_EfaCwNJBm4RDMzDNrf-O0AissvYyHb0WaALiCiFCogliYqLzRB6xDb-b4964M.J7WDOFLRRPJ7lLpTfN2mOiXLDg5xtaF-sLQ4mOeN5oc");

    let parsed_token = parse(token).unwrap();

    // Verify the header is correctly parsed and contains the "enc" field
    assert!(parsed_token.header.get("enc").is_some());
    assert_eq!(
        parsed_token.header.get("enc").unwrap().as_str().unwrap(),
        "A256CBC-HS512"
    );
    assert_eq!(
        parsed_token.header.get("alg").unwrap().as_str().unwrap(),
        "RSA-OAEP"
    );

    // Verify the body shows the encrypted message
    assert_eq!(
        parsed_token.body.as_str().unwrap(),
        "<encrypted JWE body>"
    );
}
