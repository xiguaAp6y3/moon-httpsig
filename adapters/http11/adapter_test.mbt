// adapter_test.mbt — HTTP/1.1 adapter tests.

///|

///|

///|
test "adapter_parse_empty_path" {
  let text = "GET / HTTP/1.1\nHost: example.com\n\n"
  let req = parse_http11_request(text).unwrap()
  inspect(req.path, content="/")
}

///|
test "adapter_parse_no_query_vs_empty_query" {
  let noq = parse_http11_request("GET /p HTTP/1.1\nHost: h\n\n").unwrap()
  inspect(noq.has_query(), content="false")
  let emptyq = parse_http11_request("GET /p? HTTP/1.1\nHost: h\n\n").unwrap()
  inspect(emptyq.has_query(), content="true")
  inspect(emptyq.raw_query(), content="")
}

///|
test "adapter_rejects_malformed_header" {
  match parse_http11_request("GET / HTTP/1.1\nBAD LINE\n\n") {
    Ok(_) => abort("malformed header must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidHeaderName")
  }
}

///|
test "adapter_rejects_non_http" {
  match parse_http11_request("GET / FOO\n\n") {
    Ok(_) => abort("non-HTTP protocol must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidMethod")
  }
}

///|
test "adapter_requires_http11" {
  // HTTP/1.1 is accepted.
  match parse_http11_request("GET / HTTP/1.1\nHost: h\n\n") {
    Ok(req) => inspect(req.method, content="GET")
    Err(_) => abort("HTTP/1.1 must be accepted")
  }
  // HTTP/1.0 is rejected: this adapter only speaks HTTP/1.1.
  match parse_http11_request("GET / HTTP/1.0\nHost: h\n\n") {
    Ok(_) => abort("HTTP/1.0 must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidMethod")
  }
  // HTTP/2 is rejected.
  match parse_http11_request("GET / HTTP/2\nHost: h\n\n") {
    Ok(_) => abort("HTTP/2 must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidMethod")
  }
}

///|

///|

///|

///|
test "adapter_http11_digest_binding" {
  let body = @utf8.encode("hello world")
  let digest = make_sha256_content_digest(body)
  let headers = @hsig.OrderedHeaders::new()
  let _ = headers.append("content-digest", digest)
  let binding = Http11Sha256DigestBinding::new([
    @hsig.covered_field("content-digest"),
  ])
  match binding.validate(headers, body) {
    Ok(_) => ()
    Err(e) => abort("valid digest rejected: " + e.kind_name())
  }
  let tampered = @utf8.encode("tampered")
  match binding.validate(headers, tampered) {
    Ok(_) => abort("tampered body must fail")
    Err(e) => inspect(e.kind_name(), content="ContentDigestInvalid")
  }
}

///|
test "adapter_verify_attached_request" {
  let text = "POST /api HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\nbody"
  let req = parse_http11_request(text).unwrap()
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
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Method),
      @hsig.covered_field("content-type"),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_request(req, options, @hsig.Limits::default()).unwrap()
  let attached = attach_signature_headers(req, signed).unwrap()
  let input_header = get_signature_input_header(attached).unwrap()
  let sig_header = get_signature_header(attached).unwrap()
  let resolver = @hsig.InMemoryKeyResolver::new()
  let _ = resolver.add(key, @hsig.Limits::default())
  let clock = @hsig.FixedClock::new(1700000000L)
  let nonces = @hsig.InMemoryNonceStore::new()
  let report = @hsig.verify_request(
    attached,
    input_header,
    sig_header,
    resolver,
    @hsig.VerificationPolicy::hmac_only(),
    clock,
    nonces,
    @hsig.Limits::default(),
    @hsig.MultiSignaturePolicy::AnyValid,
  ).unwrap()
  inspect(report.verified.length(), content="1")
}
