#[cfg(test)]
use super::*;

const TEST_JWS: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA";
const TEST_JWE: &str = include_str!("../jwe/tests/fixtures/simple_token.txt");

#[test]
fn jws_3_parts_produces_jws_token() {
    let JWToken::Jws(t) = parse_token(TEST_JWS).unwrap() else {
        panic!("expected Jws")
    };
    assert_eq!(t.header["alg"], "HS256");
    assert_eq!(t.header["typ"], "JWT");
    assert_eq!(t.body["foo"], "bar");
    assert_eq!(t.signature.len(), 32);
}

#[test]
fn jwe_5_parts_produces_jwe_token() {
    let JWToken::Jwe(j) = parse_token(TEST_JWE.trim()).unwrap() else {
        panic!("expected Jwe")
    };
    assert!(j.header.contains("A256GCM"));
    assert_eq!(j.iv.len(), 12);
    assert_eq!(j.tag.len(), 16);
}

#[test]
fn too_many_or_few_parts_yield_wrong_part_count() {
    assert!(matches!(
        parse_token("a.b.c.d").err().unwrap(),
        JwtParseError::WrongPartCount { found: _ }
    ));
    assert!(matches!(
        parse_token("a.b").err().unwrap(),
        JwtParseError::WrongPartCount { found: _ }
    ));
    assert!(matches!(
        parse_token("a.b.c.d.e.f").err().unwrap(),
        JwtParseError::WrongPartCount { found: _ }
    ));
}

#[test]
fn wrong_part_count_is_reported() {
    assert!(matches!(
        parse_token("a.b.c.d"),
        Err(JwtParseError::WrongPartCount { found: 4 })
    ));
    assert!(matches!(
        parse_token("a.b"),
        Err(JwtParseError::WrongPartCount { found: 2 })
    ));
    assert!(matches!(
        parse_token("a.b.c.d.e.f"),
        Err(JwtParseError::WrongPartCount { found: 6 })
    ));
}

#[test]
fn invalid_chars_in_segment_are_rejected() {
    assert!(matches!(
        parse_token("#.b.c"),
        Err(JwtParseError::InvalidSegment)
    ));
    assert!(matches!(
        parse_token("ab==.b.c"),
        Err(JwtParseError::InvalidSegment)
    ));
    assert!(matches!(
        parse_token("a.b.c!"),
        Err(JwtParseError::InvalidSegment)
    ));
}

#[test]
fn empty_input_is_rejected() {
    // With empty segments allowed, the empty string parses as a single empty
    // segment; it fails the 3/5-part check with a clearer message.
    assert!(matches!(
        parse_token(""),
        Err(JwtParseError::WrongPartCount { found: 1 })
    ));
}

#[test]
fn empty_signature_segment_is_allowed() {
    // Unsecured JWT (RFC 7518 §3.6, `alg: none`): empty signature segment.
    let token = "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.";
    let JWToken::Jws(t) = parse_token(token).unwrap() else {
        panic!("expected Jws")
    };
    assert_eq!(t.body["foo"], "bar");
    assert!(t.signature.is_empty());
}

#[test]
fn empty_encrypted_key_segment_is_allowed() {
    // `dir` JWE (RFC 7518 §4.5): the encrypted key is an empty octet sequence.
    let token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..VvWKimYzMS9Z9MkX.uO-BF7wDC-g6L5h4DUa1iim2cTCvCFDW._cE8ch4ES_mGc3YtpnEWJA";
    let JWToken::Jwe(j) = parse_token(token).unwrap() else {
        panic!("expected Jwe")
    };
    assert!(j.key_encrypted.is_empty());
    assert_eq!(j.ciphertext.len(), 24);
}

#[test]
fn undecodable_b64_in_jws_header() {
    // 'A' is valid base64url but too short to decode → InvalidHeader
    assert!(matches!(
        parse_token("AA.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA"),
        Err(JwtParseError::InvalidHeader(_))
    ));
}

#[test]
fn parse_jwe_on_a_jws_reports_not_a_jwe() {
    // Previously this reported "expected 3 parts (JWS) or 5 parts (JWE) but
    // found 3", which is confusing for a perfectly valid JWS.
    let err = parse_jwe(TEST_JWS).unwrap_err();
    assert!(matches!(err, JwtParseError::NotAJwe));
    assert_eq!(
        err.to_string(),
        "Expected a JWE token (5 parts), but the input is a JWS (3 parts)"
    );
}

#[test]
fn empty_header_segment_fails_fast() {
    // The grammar requires non-empty header segments (b64url, not
    // b64url_or_empty), so tokens like ".p.s" are rejected structurally
    // instead of producing a confusing empty-JSON decode error.
    assert!(matches!(
        parse_token(".p.s"),
        Err(JwtParseError::InvalidSegment)
    ));
    // A JWE with an empty header used to parse (empty header string) and
    // only fail later when the header was deserialized.
    assert!(matches!(
        parse_token("..iv.ct.tag"),
        Err(JwtParseError::InvalidSegment)
    ));
    // "...." (five empty segments) is where the old code was ugliest: it
    // leaked a raw serde Debug string ("Error(\"EOF while parsing a value\",
    // line: 1, column: 0)") out of main. "..a" is its 3-part twin.
    assert!(matches!(
        parse_token("...."),
        Err(JwtParseError::InvalidSegment)
    ));
    assert!(matches!(
        parse_token("..a"),
        Err(JwtParseError::InvalidSegment)
    ));
}

#[test]
fn shape_grammar_rejects_prefix_matches() {
    // The eof anchor prevents the 3-segment JWS shape from matching the
    // prefix of a longer token.
    assert!(matches!(
        parse_token("a.b.c.d.e.f.g"),
        Err(JwtParseError::WrongPartCount { found: 7 })
    ));
}

#[test]
fn jwe_token_carries_raw_form_and_derives_aad() {
    let token = TEST_JWE.trim();
    let JWToken::Jwe(j) = parse_token(token).unwrap() else {
        panic!("expected Jwe")
    };
    // The compact form round-trips verbatim (the empty `dir` key segment
    // included), and the AAD is derived from its first segment.
    assert_eq!(j.raw(), token);
    assert_eq!(j.aad(), token.split('.').next().unwrap().as_bytes());
}
