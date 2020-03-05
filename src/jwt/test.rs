use super::*;

#[test]
fn assert_parse_token_successfully() {
    let token = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA");
    let jwt_token = parse_token(&token);
    assert_eq!(String::from("{\"foo\":\"bar\"}"), jwt_token.unwrap().body);
}
