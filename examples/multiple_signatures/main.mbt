// multiple_signatures — Two signatures; one verifies, one does not.

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
  let k1 : @hsig.KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("secret-one")),
  }
  let k2 : @hsig.KeyRecord = {
    keyid: "k2",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("secret-two")),
  }
  let p : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: None,
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let o1 : @hsig.SignOptions = {
    label: "sig-a",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Method)],
    parameters: { ..p, keyid: Some("k1") },
    algorithm: "hmac-sha256",
    key: k1,
  }
  let o2 : @hsig.SignOptions = {
    label: "sig-b",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Path)],
    parameters: { ..p, keyid: Some("k2") },
    algorithm: "hmac-sha256",
    key: k2,
  }
  let s1 = @hsig.sign_request(req, o1, @hsig.Limits::default()).unwrap()
  let s2 = @hsig.sign_request(req, o2, @hsig.Limits::default()).unwrap()
  // The verifier knows k1's secret but a WRONG secret for k2.
  let resolver = @hsig.InMemoryKeyResolver::new()
  let _ = resolver.add(k1, @hsig.Limits::default())
  let _ = resolver.add(
    {
      keyid: "k2",
      algorithm: "hmac-sha256",
      material: @hsig.SharedSecret(@utf8.encode("wrong")),
    },
    @hsig.Limits::default(),
  )
  let report = @hsig.verify_request(
    req,
    s1.signature_input + ", " + s2.signature_input,
    s1.signature + ", " + s2.signature,
    resolver,
    @hsig.VerificationPolicy::hmac_only(),
    @hsig.FixedClock::new(1700000000L),
    @hsig.InMemoryNonceStore::new(),
    @hsig.Limits::default(),
    @hsig.MultiSignaturePolicy::AnyValid,
  ).unwrap()
  println(
    "verified: " +
    report.verified.length().to_string() +
    "  rejected: " +
    report.rejected.length().to_string(),
  )
  for r in report.rejected {
    println(
      "  FAIL: " + r.label.unwrap_or("?") + " (" + r.error.kind_name() + ")",
    )
  }
}
