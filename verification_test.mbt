// verification_test.mbt — Verifier tests.

///|
fn verified_report(
  req : RequestContext,
  signed : SignedFields,
  key : KeyRecord,
  now : Int64,
) -> Result[VerificationReport, HsError] {
  let ctx = make_verify_ctx(key, now)
  verify_with_ctx(ctx, req, signed.signature_input, signed.signature, AnyValid)
}

///|

///|

///|

///|
test "verify_created_in_future" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let key = make_test_key("k1", "test-secret")
  // Verify at a time before created exceeds the skew tolerance.
  let ctx = make_verify_ctx(key, 1700000000L - 400L)
  let parsed = parse_signature_input(signed.signature_input, Limits::default()).unwrap()
  let sig = parse_signature_field(signed.signature, Limits::default()).unwrap()
  let sig_bytes = get_signature(sig, "sig1").unwrap()
  match
    verify_label(
      TargetRequest(req),
      parsed.entries[0],
      sig_bytes,
      ctx.0,
      ctx.1,
      ctx.2,
      ctx.3,
      ctx.4,
    ) {
    Ok(_) => abort("created in future must fail")
    Err(e) => inspect(e.kind_name(), content="CreatedInFuture")
  }
  // Within skew: success.
  let ok = verified_report(req, signed, key, 1700000000L - 100L).unwrap()
  inspect(ok.verified.length(), content="1")
}

///|

///|
test "verify_multisig_one_fails_one_ok" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let o1 = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  // Second signature signed with one secret but verified against another.
  let sign_key2 = make_test_key("k2", "sign-secret")
  let params2 : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k2"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options2 : SignOptions = {
    label: "sig2",
    components: [covered_derived(Path)],
    parameters: params2,
    algorithm: "hmac-sha256",
    key: sign_key2,
  }
  let o2 = sign_request(req, options2, Limits::default()).unwrap()
  let combined_input = o1.signature_input + ", " + o2.signature_input
  let combined_sig = o1.signature + ", " + o2.signature
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let _ = resolver.add(
    make_test_key("k2", "different-secret"),
    Limits::default(),
  )
  let policy = VerificationPolicy::hmac_only()
  let clock = FixedClock::new(1700000000L)
  let nonces = InMemoryNonceStore::new()
  let report = verify_request(
    req,
    combined_input,
    combined_sig,
    resolver,
    policy,
    clock,
    nonces,
    Limits::default(),
    AnyValid,
  ).unwrap()
  inspect(report.verified.length(), content="1")
  inspect(report.rejected.length(), content="1")
  inspect(report.verified[0].label, content="sig1")
  inspect(report.rejected[0].label.unwrap(), content="sig2")
}

///|
test "verify_rejects_oversized_input" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let big = String::make(200000, 'a')
  let ctx3 = make_verify_ctx(key, 1700000000L)
  match verify_with_ctx(ctx3, req, big, "x", AnyValid) {
    Ok(_) => abort("oversized input must fail")
    Err(e) => inspect(e.kind_name(), content="InputTooLarge")
  }
}
