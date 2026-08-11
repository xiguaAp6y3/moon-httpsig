// digest_binding_test.mbt — Content-Digest binding tests.

///|
fn sha256_b64(body : String) -> String {
  base64_encode_bytes(sha256_raw(@utf8.encode(body)))
}

///|
fn digest_headers(digest_b64 : String) -> OrderedHeaders {
  let h = OrderedHeaders::new()
  let _ = h.append("content-digest", "sha-256=:" + digest_b64 + ":")
  h
}

///|

///|

///|
test "digest_header_modified_fails" {
  let body = @utf8.encode("hello world")
  let headers = digest_headers(sha256_b64("different"))
  let covered = [covered_field("content-digest")]
  match validate_content_digest(covered, headers, body, Limits::default()) {
    Ok(_) => abort("mismatched digest must fail")
    Err(e) => inspect(e.kind_name(), content="ContentDigestInvalid")
  }
}

///|

///|

///|
test "digest_binding_callback" {
  let mut called = false
  let binding = CallbackDigestBinding::new(fn(_h, _b) {
    called = true
    Ok(())
  })
  let _ = binding.validate(OrderedHeaders::new(), @utf8.encode("x"))
  inspect(called, content="true")
  let failing = CallbackDigestBinding::new(fn(_h, _b) {
    Err(hs_error(DigestBinding, ContentDigestInvalid, "callback failed"))
  })
  match failing.validate(OrderedHeaders::new(), @utf8.encode("x")) {
    Ok(_) => abort("callback error must propagate")
    Err(e) => inspect(e.kind_name(), content="ContentDigestInvalid")
  }
}

///|

///|
test "digest_policy_in_verifier" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let body = @utf8.encode("hello world")
  let digest_b64 = sha256_b64("hello world")
  let _ = h.append("content-digest", "sha-256=:" + digest_b64 + ":")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    Some(body),
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_field("content-digest"), covered_field("content-type")],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let clock = FixedClock::new(1700000000L)
  let nonces = InMemoryNonceStore::new()
  let strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    require_content_digest: true,
  }
  let report = verify_request(
    req,
    signed.signature_input,
    signed.signature,
    resolver,
    strict,
    clock,
    nonces,
    Limits::default(),
    AnyValid,
  ).unwrap()
  inspect(report.verified.length(), content="1")
}
