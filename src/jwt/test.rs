#[cfg(test)]
use super::*;

#[test]
fn assert_parse_successfully() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let jwt_token = parse(&token);
    assert_eq!(String::from("{\"foo\":\"bar\"}"), jwt_token.unwrap().body);
}

#[test]
fn assert_parse_successfullt_from_str() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let jwt_token = token.parse::<Token>();
    assert_eq!(String::from("{\"foo\":\"bar\"}"), jwt_token.unwrap().body);
}

#[test]
fn assert_parse_fails_due_to_invalid_header() {
    let token = String::from(
        "invalid_header.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let jwt_token = parse(&token);
    assert!(jwt_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Header:"));
}

#[test]
fn assert_parse_fails_due_to_invalid_body() {
    let token = String::from(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid_body.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
    );
    let jwt_token = parse(&token);
    assert!(jwt_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Body:"));
}

#[test]
fn assert_parse_fails_due_to_invalid_signature() {
    let token =
        String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.invalid_signature");
    let jwt_token = parse(&token);
    assert!(jwt_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Signature:"));
}

#[test]
fn assert_parse_fails_due_to_more_then_three_fragment() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA.one_more_fragment");
    let jwt_token = parse(&token);
    assert_eq!(
        String::from("Error: Unexpected fragment after signature"),
        jwt_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_body() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    let jwt_token = parse(&token);
    assert_eq!(
        String::from("Invalid Body: Missing token section"),
        jwt_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_to_missing_signature() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ");
    let jwt_token = parse(&token);
    assert_eq!(
        String::from("Invalid Signature: Missing token section"),
        jwt_token.unwrap_err().to_string()
    );
}

#[test]
fn assert_parse_fails_due_invalid_json_header() {
    let token = String::from("eyJhbGc6ICJIUzI1NiIsInR5cCI6ICJKV1QifQ.eyJmb28iOiJiYXIifQ.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU");
    let jwt_token = parse(&token);
    assert!(jwt_token
        .unwrap_err()
        .to_string()
        .starts_with("Invalid Header: JSON error"));
}
