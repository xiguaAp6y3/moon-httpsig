// signing_test.mbt — Signer end-to-end tests.

///|

///|
test "signing_rfc_b25_exact" {
  let headers = OrderedHeaders::new()
  let _ = headers.append("host", "example.com")
  let _ = headers.append("date", "Tue, 20 Apr 2021 02:07:55 GMT")
  let _ = headers.append("content-type", "application/json")
  let secret = base64_decode_bytes(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==",
  ).unwrap()
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("param=Value&Pet=dog"),
    headers,
    None,
  ).unwrap()
  let key : KeyRecord = {
    keyid: "test-shared-secret",
    algorithm: "hmac-sha256",
    material: SharedSecret(secret),
  }
  let params : SignatureParameters = {
    created: Some(1618884473L),
    expires: None,
    keyid: Some("test-shared-secret"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig-b25",
    components: [
      covered_field("date"),
      covered_derived(Authority),
      covered_field("content-type"),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  inspect(
    signed.signature_input,
    content="sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
  )
  inspect(
    signed.signature,
    content="sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
  )
}

///|

///|

///|
test "signing_unsupported_algorithm" {
  let req = make_minimal_request()
  let key : KeyRecord = {
    keyid: "k1",
    algorithm: "ed25519",
    material: SharedSecret(@utf8.encode("s")),
  }
  let params : SignatureParameters = {
    created: Some(1L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_derived(Method)],
    parameters: params,
    algorithm: "ed25519",
    key,
  }
  match sign_request(req, options, Limits::default()) {
    Ok(_) => abort("ed25519 must not sign")
    Err(e) => inspect(e.kind_name(), content="AlgorithmNotAllowed")
  }
}

///|

///|

///|

///|
test "signing_with_nonce_tag" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: Some(1700003600L),
    keyid: Some("k1"),
    alg: Some("hmac-sha256"),
    nonce: Some("nonce-1"),
    tag: Some("app-tag"),
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_derived(Method)],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  inspect(
    signed.signature_input,
    content="sig1=(\"@method\");created=1700000000;expires=1700003600;keyid=\"k1\";nonce=\"nonce-1\";alg=\"hmac-sha256\";tag=\"app-tag\"",
  )
}
