// sign_response — Sign a response including its related request via `req`.

///|
fn main {
  let rh = @hsig.OrderedHeaders::new()
  let _ = rh.append("content-type", "application/json")
  let related = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/order",
    None,
    rh,
    None,
  ).unwrap()
  let response = @hsig.ResponseContext::new_default(
    201,
    rh,
    None,
    Some(related),
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "server-key",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("server-secret")),
  }
  let req_method = @hsig.covered_derived_with_params(
    @hsig.DerivedComponent::Method,
    { sf: false, key: None, bs: false, tr: false, req: true, name: None },
  )
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("server-key"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : @hsig.SignOptions = {
    label: "respsig",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Status),
      req_method,
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_response(response, options, @hsig.Limits::default()).unwrap()
  println(signed.signature_base.text)
  // Tamper with the status: 201 -> 500.
  let tampered = @hsig.ResponseContext::new_default(
    500,
    rh,
    None,
    response.related_request,
  ).unwrap()
  let resolver = @hsig.InMemoryKeyResolver::new()
  let _ = resolver.add(key, @hsig.Limits::default())
  let clock = @hsig.FixedClock::new(1700000000L)
  let nonces = @hsig.InMemoryNonceStore::new()
  let result = @hsig.verify_response(
    tampered,
    signed.signature_input,
    signed.signature,
    resolver,
    @hsig.VerificationPolicy::hmac_only(),
    clock,
    nonces,
    @hsig.Limits::default(),
    @hsig.MultiSignaturePolicy::AnyValid,
  )
  println(
    "tampered status: " +
    (match result {
      Ok(_) => "accepted"
      Err(_) => "rejected"
    }),
  )
}
