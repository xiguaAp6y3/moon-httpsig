// replay_policy — Nonce-based replay protection.

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
    material: @hsig.SharedSecret(@utf8.encode("secret")),
  }
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: Some("unique-nonce-1"),
    tag: None,
    extensions: Array::new(),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Method)],
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
  let f = @hsig.verify_request(
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
    "first use: " +
    (match f {
      Ok(_) => "accepted"
      Err(_) => "rejected"
    }),
  )
  let s = @hsig.verify_request(
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
    "second use: " +
    (match s {
      Ok(_) => "accepted"
      Err(_) => "rejected"
    }),
  )
  // The same nonce under a different keyid is allowed by the raw store.
  let store = @hsig.InMemoryNonceStore::new()
  let _ = store.check_and_store("k1", "same-nonce", None)
  println(
    "different keyid, same nonce: " +
    (match store.check_and_store("k2", "same-nonce", None) {
      Ok(_) => "allowed"
      Err(_) => "rejected"
    }),
  )
}
