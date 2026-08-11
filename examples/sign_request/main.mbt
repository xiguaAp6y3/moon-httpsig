// sign_request — Sign a POST request with HMAC-SHA256.

///|
fn main {
  let body = @utf8.encode("{\"hello\": \"world\"}")
  let h = @hsig.OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append(
    "content-digest",
    "sha-256=:" + @hsig.base64_encode_bytes(@hsig.sha256_raw(body)) + ":",
  )
  let req = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/api/orders",
    Some("source=web"),
    h,
    Some(body),
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "local-key",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("secret")),
  }
  let params : @hsig.SignatureParameters = {
    created: Some(@hsig.SystemClock::new().now_unix_seconds()),
    expires: None,
    keyid: Some("local-key"),
    alg: Some("hmac-sha256"),
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Method),
      @hsig.covered_derived(@hsig.DerivedComponent::TargetUri),
      @hsig.covered_field("content-digest"),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_request(req, options, @hsig.Limits::default()).unwrap()
  println("Signature-Input: " + signed.signature_input)
  println("Signature:       " + signed.signature)
}
