// policy_test.mbt — Verification policy tests.

///|

///|
fn verify_with_policy(
  req : RequestContext,
  signed : SignedFields,
  key : KeyRecord,
  policy : VerificationPolicy,
  now : Int64,
) -> Result[VerificationReport, HsError] {
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let clock = FixedClock::new(now)
  let nonces = InMemoryNonceStore::new()
  verify_request(
    req,
    signed.signature_input,
    signed.signature,
    resolver,
    policy,
    clock,
    nonces,
    Limits::default(),
    AnyValid,
  )
}

///|

///|

///|

///|

///|

///|

///|
test "policy_reject_unknown_parameters" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: [{ name: "custom", value: SfString("x") }],
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_derived(Method)],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    reject_unknown_parameters: true,
  }
  let result = verify_with_policy(req, signed, key, strict, 1700000000L)
  match result {
    Ok(report) => inspect(report.verified.length(), content="0")
    Err(e) => inspect(e.kind_name(), content="SignatureMismatch")
  }
  let lenient : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    reject_unknown_parameters: false,
  }
  let ok = verify_with_policy(req, signed, key, lenient, 1700000000L).unwrap()
  inspect(ok.verified.length(), content="1")
}

///|

///|
test "policy_alg_field_must_match_key" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: Some("rsa-pss-sha512"),
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_derived(Method)],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let result = verify_with_policy(
    req,
    signed,
    key,
    VerificationPolicy::hmac_only(),
    1700000000L,
  )
  match result {
    Ok(report) => inspect(report.verified.length(), content="0")
    Err(e) => inspect(e.kind_name(), content="SignatureMismatch")
  }
}
