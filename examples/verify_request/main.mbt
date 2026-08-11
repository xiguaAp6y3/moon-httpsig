// verify_request — Verify an HMAC-SHA256 request signature.

///|
fn main {
  let h = @hsig.OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let req = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    None,
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("shared-secret")),
  }
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [
      @hsig.covered_field("content-type"),
      @hsig.covered_derived(@hsig.DerivedComponent::Method),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_request(req, options, @hsig.Limits::default()).unwrap()
  let resolver = @hsig.InMemoryKeyResolver::new()
  let _ = resolver.add(key, @hsig.Limits::default())
  let clock = @hsig.FixedClock::new(1700000000L)
  let nonces = @hsig.InMemoryNonceStore::new()
  let policy = @hsig.VerificationPolicy::hmac_only()
  let limits = @hsig.Limits::default()
  let report = @hsig.verify_request(
    req,
    signed.signature_input,
    signed.signature,
    resolver,
    policy,
    clock,
    nonces,
    limits,
    @hsig.MultiSignaturePolicy::AnyValid,
  )
  println(
    "verified: " +
    (match report {
      Ok(r) => r.verified.length().to_string()
      Err(_) => "0"
    }),
  )
  // Tamper with the covered content-type header.
  let th = @hsig.OrderedHeaders::new()
  let _ = th.append("content-type", "text/plain")
  let tampered = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    th,
    None,
  ).unwrap()
  let result = @hsig.verify_request(
    tampered,
    signed.signature_input,
    signed.signature,
    resolver,
    policy,
    clock,
    nonces,
    limits,
    @hsig.MultiSignaturePolicy::AnyValid,
  )
  println(
    "after tampering: " +
    (match result {
      Ok(_) => "accepted"
      Err(_) => "rejected"
    }),
  )
}
