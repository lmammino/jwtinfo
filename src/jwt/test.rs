#[cfg(test)]
use super::*;

#[test]
fn assert_parse_successfully() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let parsed_token = parse(&token).unwrap();
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
fn assert_parse_successfullt_from_str() {
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
    let parsed_token = parse(&token);
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
    let parsed_token = parse(&token);
    assert!(parsed_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Body:"));
}

#[test]
fn assert_parse_fails_due_to_invalid_signature() {
    let token =
        String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.invalid_signature");
    let parsed_token = parse(&token);
    assert!(parsed_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Signature:"));
}

#[test]
fn assert_parse_fails_due_to_more_then_three_fragment() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA.one_more_fragment");
    let parsed_token = parse(&token);
    assert_eq!(
        String::from("Error: Unexpected fragment after signature"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_body() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    let parsed_token = parse(&token);
    assert_eq!(
        String::from("Invalid Body: Missing token section"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_signature() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ");
    let parsed_token = parse(&token);
    assert_eq!(
        String::from("Invalid Signature: Missing token section"),
        parsed_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_invalid_json_header() {
    let token = String::from("eyJhbGc6ICJIUzI1NiIsInR5cCI6ICJKV1QifQ.eyJmb28iOiJiYXIifQ.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU");
    let parsed_token = parse(&token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert!(err.starts_with("Invalid Header: JSON error"));
}

#[test]
fn assert_parse_fail_due_invalid_json_body() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXJ9.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU");
    let parsed_token = parse(&token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert!(err.starts_with("Invalid Body: JSON error"));
}

#[test]
fn assert_fails_with_non_base64_header() {
    let token = String::from(
        "ĄČĘĖĮŠŲŪąčęėįšųū\x09#$#434.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let parsed_token = parse(&token);
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
    let parsed_token = parse(&token);
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
    let parsed_token = parse(&token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Signature: Base64 error, Invalid byte 196, offset 0."
    );
}

#[test]
fn assert_fails_with_non_valid_token() {
    let token = String::from(r"I'm \x00\x09writing \x52\x75\x73\x74!\x00\x09");
    let parsed_token = parse(&token);
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
    let parsed_token = parse(&token);
    let err = format!("{}", parsed_token.unwrap_err());
    assert_eq!(
        err,
        "Invalid Header: Base64 error, Invalid byte 0, offset 0."
    );
}
