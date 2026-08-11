// response_test.mbt — Response signing and verification tests.

///|
fn resp_ctx() -> ResponseContext {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append("content-length", "18")
  let req_headers = OrderedHeaders::new()
  let _ = req_headers.append("content-type", "application/json")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("param=Value&Pet=dog"),
    req_headers,
    None,
  ).unwrap()
  match ResponseContext::new_default(503, h, None, Some(req)) {
    Ok(r) => r
    Err(_) => abort("response build failed")
  }
}

///|

///|

///|
test "response_req_components" {
  let resp = resp_ctx()
  let key = make_test_key("rk1", "response-secret")
  // Sign the response covering the request's method via req.
  let req_comp = covered_derived_with_params(Method, {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: true,
    name: None,
  })
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("rk1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "respsig",
    components: [covered_derived(Status), req_comp],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_response(resp, options, Limits::default()).unwrap()
  inspect(
    signed.signature_base.text.contains("\"@method\";req: POST"),
    content="true",
  )
  inspect(
    signed.signature_input,
    content="respsig=(\"@status\" \"@method\";req);created=1700000000;keyid=\"rk1\"",
  )
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let clock = FixedClock::new(1700000000L)
  let nonces = InMemoryNonceStore::new()
  let report = verify_response(
    resp,
    signed.signature_input,
    signed.signature,
    resolver,
    VerificationPolicy::hmac_only(),
    clock,
    nonces,
    Limits::default(),
    AnyValid,
  ).unwrap()
  inspect(report.verified.length(), content="1")
}

///|

///|
test "response_tampered_related_request_fails" {
  let resp = resp_ctx()
  let key = make_test_key("rk1", "response-secret")
  let req_comp = covered_derived_with_params(Method, {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: true,
    name: None,
  })
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("rk1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "respsig",
    components: [req_comp],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_response(resp, options, Limits::default()).unwrap()
  // Tamper the related request's method.
  let th = OrderedHeaders::new()
  let tampered_req = RequestContext::new_default(
    "DELETE",
    "https",
    "example.com",
    "/foo",
    Some("param=Value&Pet=dog"),
    th,
    None,
  ).unwrap()
  let tampered_resp = ResponseContext::new_default(
    503,
    th,
    None,
    Some(tampered_req),
  ).unwrap()
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let clock = FixedClock::new(1700000000L)
  let nonces = InMemoryNonceStore::new()
  let r = verify_response(
    tampered_resp,
    signed.signature_input,
    signed.signature,
    resolver,
    VerificationPolicy::hmac_only(),
    clock,
    nonces,
    Limits::default(),
    AnyValid,
  )
  match r {
    Ok(report) => inspect(report.verified.length(), content="0")
    Err(_) => ()
  }
}
