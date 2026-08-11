// rfc9421_examples_test.mbt — RFC 9421 Appendix B byte-exact tests.
//
// The RFC test-request and test-response messages are reconstructed and the
// signature bases for Appendix B examples B.2.1–B.2.6 are compared
// byte-for-byte. The HMAC example (B.2.5) additionally verifies the exact
// Signature-Input, Signature, and MAC value.

///|
fn rfc_test_request() -> RequestContext {
  let h = OrderedHeaders::new()
  let _ = h.append("host", "example.com")
  let _ = h.append("date", "Tue, 20 Apr 2021 02:07:55 GMT")
  let _ = h.append("content-type", "application/json")
  let _ = h.append(
    "content-digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
  )
  let _ = h.append("content-length", "18")
  let body = @utf8.encode("{\"hello\": \"world\"}")
  match
    RequestContext::new_default(
      "POST",
      "https",
      "example.com",
      "/foo",
      Some("param=Value&Pet=dog"),
      h,
      Some(body),
    ) {
    Ok(r) => r
    Err(_) => abort("request build failed")
  }
}

///|
fn rfc_test_response() -> ResponseContext {
  let h = OrderedHeaders::new()
  let _ = h.append("date", "Tue, 20 Apr 2021 02:07:56 GMT")
  let _ = h.append("content-type", "application/json")
  let _ = h.append(
    "content-digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
  )
  let _ = h.append("content-length", "23")
  let body = @utf8.encode("{\"message\": \"good dog\"}")
  match ResponseContext::new_default(200, h, Some(body), None) {
    Ok(r) => r
    Err(_) => abort("response build failed")
  }
}

///|
fn rfc_params(
  created : Int64,
  keyid : String,
  nonce : String?,
  tag : String?,
) -> SignatureParameters {
  {
    created: Some(created),
    expires: None,
    keyid: Some(keyid),
    alg: None,
    nonce,
    tag,
    extensions: Array::new(),
  }
}

///|
fn entry_of(
  label : String,
  components : Array[CoveredComponent],
  params : SignatureParameters,
) -> SignatureInputEntry {
  { label, covered_components: components, parameters: params }
}

///|
test "rfc_b21_signature_base" {
  let req = rfc_test_request()
  let entry = entry_of(
    "sig-b21",
    Array::new(),
    rfc_params(
      1618884473L,
      "test-key-rsa-pss",
      Some("b3k2pp5k7z-50gnwp.yemd"),
      None,
    ),
  )
  let base = build_request_signature_base(req, entry, Limits::default()).unwrap()
  let expected = "\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\""
  inspect(base.text, content=expected)
  inspect(
    constant_time_equal(base.bytes, @utf8.encode(expected)),
    content="true",
  )
}

///|
test "rfc_b22_signature_base" {
  let req = rfc_test_request()
  let params : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: false,
    name: Some("Pet"),
  }
  let entry = entry_of(
    "sig-b22",
    [
      covered_derived(Authority),
      covered_field("content-digest"),
      covered_derived_with_params(QueryParam("Pet"), params),
    ],
    rfc_params(1618884473L, "test-key-rsa-pss", None, Some("header-example")),
  )
  let base = build_request_signature_base(req, entry, Limits::default()).unwrap()
  let expected = "\"@authority\": example.com\n\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n\"@query-param\";name=\"Pet\": dog\n\"@signature-params\": (\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\");created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\""
  inspect(base.text, content=expected)
  let input_serialized = serialize_signature_input({ entries: [entry] }).unwrap()
  inspect(
    input_serialized,
    content="sig-b22=(\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\");created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\"",
  )
}

///|
test "rfc_b23_signature_base" {
  let req = rfc_test_request()
  let entry = entry_of(
    "sig-b23",
    [
      covered_field("date"),
      covered_derived(Method),
      covered_derived(Path),
      covered_derived(Query),
      covered_derived(Authority),
      covered_field("content-type"),
      covered_field("content-digest"),
      covered_field("content-length"),
    ],
    rfc_params(1618884473L, "test-key-rsa-pss", None, None),
  )
  let base = build_request_signature_base(req, entry, Limits::default()).unwrap()
  let expected = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@query\": ?param=Value&Pet=dog\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-rsa-pss\""
  inspect(base.text, content=expected)
  inspect(
    constant_time_equal(base.bytes, @utf8.encode(expected)),
    content="true",
  )
}

///|
test "rfc_b24_signature_base" {
  let resp = rfc_test_response()
  let entry = entry_of(
    "sig-b24",
    [
      covered_derived(Status),
      covered_field("content-type"),
      covered_field("content-digest"),
      covered_field("content-length"),
    ],
    rfc_params(1618884473L, "test-key-ecc-p256", None, None),
  )
  let base = build_response_signature_base(resp, entry, Limits::default()).unwrap()
  let expected = "\"@status\": 200\n\"content-type\": application/json\n\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n\"content-length\": 23\n\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\""
  inspect(base.text, content=expected)
  inspect(
    constant_time_equal(base.bytes, @utf8.encode(expected)),
    content="true",
  )
}

///|
test "rfc_b25_signature_base_and_hmac" {
  let req = rfc_test_request()
  let entry = entry_of(
    "sig-b25",
    [
      covered_field("date"),
      covered_derived(Authority),
      covered_field("content-type"),
    ],
    rfc_params(1618884473L, "test-shared-secret", None, None),
  )
  let base = build_request_signature_base(req, entry, Limits::default()).unwrap()
  let expected = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n\"content-type\": application/json\n\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\""
  inspect(base.text, content=expected)
  inspect(
    constant_time_equal(base.bytes, @utf8.encode(expected)),
    content="true",
  )
  // RFC 9421 B.2.5: exact MAC.
  let secret = base64_decode_bytes(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==",
  ).unwrap()
  let mac = hmac_sha256(secret, base.bytes)
  inspect(
    base64_encode_bytes(mac),
    content="pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
  )
  // Exact Signature-Input and Signature strings.
  let input_serialized = serialize_signature_input({ entries: [entry] }).unwrap()
  inspect(
    input_serialized,
    content="sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
  )
  inspect(
    base64_encode_bytes(mac),
    content="pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
  )
}

///|
test "rfc_b26_signature_base" {
  let req = rfc_test_request()
  let entry = entry_of(
    "sig-b26",
    [
      covered_field("date"),
      covered_derived(Method),
      covered_derived(Path),
      covered_derived(Authority),
      covered_field("content-type"),
      covered_field("content-length"),
    ],
    rfc_params(1618884473L, "test-key-ed25519", None, None),
  )
  let base = build_request_signature_base(req, entry, Limits::default()).unwrap()
  let expected = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
  inspect(base.text, content=expected)
  inspect(
    constant_time_equal(base.bytes, @utf8.encode(expected)),
    content="true",
  )
}

///|
test "rfc_hmac_sign_and_verify_roundtrip" {
  let req = rfc_test_request()
  let secret = base64_decode_bytes(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==",
  ).unwrap()
  let key : KeyRecord = {
    keyid: "test-shared-secret",
    algorithm: "hmac-sha256",
    material: SharedSecret(secret),
  }
  let params = rfc_params(1618884473L, "test-shared-secret", None, None)
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
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let clock = FixedClock::new(1618884473L)
  let nonces = InMemoryNonceStore::new()
  let report = verify_request(
    req,
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
  inspect(report.verified[0].label, content="sig-b25")
}

///|
test "rfc_signature_input_strings_exact" {
  let _req = rfc_test_request()
  let _resp = rfc_test_response()
  let cases = [
    (
      "sig-b21",
      Array::new(),
      rfc_params(
        1618884473L,
        "test-key-rsa-pss",
        Some("b3k2pp5k7z-50gnwp.yemd"),
        None,
      ),
      "sig-b21=();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
      "request",
    ),
    (
      "sig-b22",
      [
        covered_derived(Authority),
        covered_field("content-digest"),
        covered_derived(QueryParam("Pet")),
      ],
      rfc_params(1618884473L, "test-key-rsa-pss", None, Some("header-example")),
      "sig-b22=(\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\");created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\"",
      "request",
    ),
    (
      "sig-b23",
      [
        covered_field("date"),
        covered_derived(Method),
        covered_derived(Path),
        covered_derived(Query),
        covered_derived(Authority),
        covered_field("content-type"),
        covered_field("content-digest"),
        covered_field("content-length"),
      ],
      rfc_params(1618884473L, "test-key-rsa-pss", None, None),
      "sig-b23=(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "request",
    ),
    (
      "sig-b24",
      [
        covered_derived(Status),
        covered_field("content-type"),
        covered_field("content-digest"),
        covered_field("content-length"),
      ],
      rfc_params(1618884473L, "test-key-ecc-p256", None, None),
      "sig-b24=(\"@status\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"",
      "response",
    ),
    (
      "sig-b25",
      [
        covered_field("date"),
        covered_derived(Authority),
        covered_field("content-type"),
      ],
      rfc_params(1618884473L, "test-shared-secret", None, None),
      "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
      "request",
    ),
    (
      "sig-b26",
      [
        covered_field("date"),
        covered_derived(Method),
        covered_derived(Path),
        covered_derived(Authority),
        covered_field("content-type"),
        covered_field("content-length"),
      ],
      rfc_params(1618884473L, "test-key-ed25519", None, None),
      "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
      "request",
    ),
  ]
  for _, case in cases {
    let (label, components, params, expected, _kind) = case
    let entry : SignatureInputEntry = {
      label,
      covered_components: components,
      parameters: params,
    }
    let serialized = serialize_signature_input({ entries: [entry] }).unwrap()
    inspect(serialized, content=expected)
  }
}
