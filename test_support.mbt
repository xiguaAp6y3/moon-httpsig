// test_support.mbt — Shared helpers for the test suite.
//
// These helpers are public so that the blackbox test package and the
// examples can reuse them; they are not part of the intended production API
// surface.

///|
/// Builds a request context for tests with the given headers.
pub fn make_test_request(
  method : String,
  path : String,
  query : String?,
  headers : OrderedHeaders,
) -> Result[RequestContext, HsError] {
  RequestContext::new_default(
    method,
    "https",
    "example.com",
    path,
    query,
    headers,
    None,
  )
}

///|
/// Builds an HMAC-SHA256 key record for tests.
pub fn make_test_key(keyid : String, secret : String) -> KeyRecord {
  {
    keyid,
    algorithm: "hmac-sha256",
    material: SharedSecret(@utf8.encode(secret)),
  }
}

///|
/// Builds a minimal request context for signing tests.
pub fn make_minimal_request() -> RequestContext {
  let headers = OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let _ = headers.append("date", "Tue, 20 Apr 2021 02:07:55 GMT")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("param=Value&Pet=dog"),
    headers,
    None,
  )
  match req {
    Ok(r) => r
    Err(_) => abort("test request construction failed")
  }
}

///|
/// Signs a minimal request with the given covered components and a fixed
/// created time, returning the signed fields.
pub fn sign_test_request(
  components : Array[CoveredComponent],
  keyid : String,
  created : Int64,
) -> Result[SignedFields, HsError] {
  let req = make_minimal_request()
  let key = make_test_key(keyid, "test-secret")
  let params : SignatureParameters = {
    created: Some(created),
    expires: None,
    keyid: Some(keyid),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components,
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  sign_request(req, options, Limits::default())
}

///|
/// Builds a default verification context: resolver, policy, clock, nonce
/// store, and limits ready for `verify_request`.
pub fn make_verify_ctx(
  key : KeyRecord,
  created : Int64,
) -> (
  InMemoryKeyResolver,
  VerificationPolicy,
  FixedClock,
  InMemoryNonceStore,
  Limits,
) {
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let policy = VerificationPolicy::hmac_only()
  let clock = FixedClock::new(created)
  let nonces = InMemoryNonceStore::new()
  (resolver, policy, clock, nonces, Limits::default())
}

///|
/// Verifies a signed request with a fixed clock, returning the report.
pub fn verify_test_request(
  request : RequestContext,
  signed : SignedFields,
  key : KeyRecord,
  now : Int64,
) -> Result[VerificationReport, HsError] {
  let (resolver, policy, clock, nonces, limits) = make_verify_ctx(key, now)
  verify_request(
    request,
    signed.signature_input,
    signed.signature,
    resolver,
    policy,
    clock,
    nonces,
    limits,
    AnyValid,
  )
}

///|
/// Asserts that two byte buffers are equal (test helper).
pub fn assert_bytes_eq(a : Bytes, b : Bytes, what : String) -> Unit {
  if !constant_time_equal(a, b) {
    abort("bytes differ for: " + what)
  }
}

///|
/// Verifies a request using a `make_verify_ctx` context. Keeps test bodies
/// short so that canonical formatting does not split long calls.
pub fn verify_with_ctx(
  ctx : (
    InMemoryKeyResolver,
    VerificationPolicy,
    FixedClock,
    InMemoryNonceStore,
    Limits,
  ),
  req : RequestContext,
  input : String,
  sig : String,
  multi : MultiSignaturePolicy,
) -> Result[VerificationReport, HsError] {
  verify_request(req, input, sig, ctx.0, ctx.1, ctx.2, ctx.3, ctx.4, multi)
}

///|
/// Verifies a single label using a `make_verify_ctx` context.
pub fn verify_label_with_ctx(
  ctx : (
    InMemoryKeyResolver,
    VerificationPolicy,
    FixedClock,
    InMemoryNonceStore,
    Limits,
  ),
  target : SignTarget,
  entry : SignatureInputEntry,
  sig : Bytes,
) -> Result[VerifiedSignature, HsError] {
  verify_label(target, entry, sig, ctx.0, ctx.1, ctx.2, ctx.3, ctx.4)
}

///|
/// Returns `"ok"` when the request verifies, otherwise the rejection kind.
/// Compact helper for negative tests.
pub fn verify_outcome(
  ctx : (
    InMemoryKeyResolver,
    VerificationPolicy,
    FixedClock,
    InMemoryNonceStore,
    Limits,
  ),
  req : RequestContext,
  input : String,
  sig : String,
) -> String {
  match verify_with_ctx(ctx, req, input, sig, AnyValid) {
    Ok(report) => if report.verified.is_empty() { "rejected" } else { "ok" }
    Err(e) =>
      if e.kind() is SignatureMismatch {
        "rejected"
      } else {
        e.kind_name()
      }
  }
}

///|
/// Returns the error kind of a single-label verification, or `"ok"`.
pub fn verify_label_outcome(
  ctx : (
    InMemoryKeyResolver,
    VerificationPolicy,
    FixedClock,
    InMemoryNonceStore,
    Limits,
  ),
  target : SignTarget,
  entry : SignatureInputEntry,
  sig : Bytes,
) -> String {
  match verify_label_with_ctx(ctx, target, entry, sig) {
    Ok(_) => "ok"
    Err(e) => e.kind_name()
  }
}
