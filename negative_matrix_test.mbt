// negative_matrix_test.mbt — Negative security matrix.
//
// Each entry forces a distinct failure mode and asserts the expected
// `HsErrorKind`. The `verify_outcome` / `verify_label_outcome` helpers keep
// every case compact; cheap checks run before any cryptographic work.

///|

///|
test "neg_policy_rejects" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let base = make_verify_ctx(key, 1700000000L)
  let keyid_strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    require_keyid: true,
  }
  let tag_strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    expected_tag: Some("t"),
  }
  let reqcomp_strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    required_components: [covered_derived(Path)],
  }
  let unknown_strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    reject_unknown_parameters: true,
  }
  let nonce_strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    require_nonce: true,
  }
  let c1 = (base.0, keyid_strict, base.2, base.3, base.4)
  let c2 = (base.0, tag_strict, base.2, base.3, base.4)
  let c3 = (base.0, reqcomp_strict, base.2, base.3, base.4)
  let c4 = (base.0, unknown_strict, base.2, base.3, base.4)
  let c5 = (base.0, nonce_strict, base.2, base.3, base.4)
  inspect(
    verify_outcome(c1, req, "sig1=(\"@method\");created=1", "sig1=:YWJj:"),
    content="rejected",
  )
  inspect(
    verify_outcome(c5, req, signed.signature_input, signed.signature),
    content="rejected",
  )
  inspect(
    verify_outcome(c2, req, signed.signature_input, signed.signature),
    content="rejected",
  )
  inspect(
    verify_outcome(c3, req, signed.signature_input, signed.signature),
    content="rejected",
  )
  let modified = signed.signature_input.replace(
    old=";keyid=\"k1\"",
    new=";keyid=\"k1\";x-unknown=\"v\"",
  )
  inspect(
    verify_outcome(c4, req, modified, signed.signature),
    content="rejected",
  )
}

///|
test "neg_parse_and_label_rejects" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let cases = [
    (
      "sig1=(\"@method\");created=1700000000;keyid=\"k1\"", "sig-other=:YWJj:", "LabelMismatch",
    ),
    (
      "a=(\"@method\");created=1, a=(\"@path\");created=2", "a=:YQ==:", "InvalidStructuredField",
    ),
    (
      "sig1=(\"@method\");created=1;keyid=\"k1\"", "sig1=:!!!invalid!!!:", "InvalidBase64",
    ),
    ("sig1=(\"@method\"", "sig1=:YWJj:", "UnexpectedEnd"),
    (
      "sig1=(\"@method\");created=1;keyid=\"k1\";alg=\"not-an-algorithm\"", "sig1=:YWJj:",
      "rejected",
    ),
    (
      "sig1=(\"@method\");created=100;expires=50;keyid=\"k1\"", "sig1=:YWJj:", "InvalidTimestamp",
    ),
    (
      "sig1=(\"@method\");created=1;keyid=\"k1\"", "sig1=:AA\nBB:", "InvalidBase64",
    ),
  ]
  for _, case in cases {
    let (inp, sig, kind) = case
    inspect(verify_outcome(ctx, req, inp, sig), content=kind)
  }
}

///|
test "neg_signature_input_missing" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  inspect(
    verify_outcome(ctx, req, "", signed.signature),
    content="LabelMismatch",
  )
}

///|
test "neg_signature_missing" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  inspect(
    verify_outcome(ctx, req, signed.signature_input, ""),
    content="LabelMismatch",
  )
}

///|

///|

///|

///|

///|

///|

///|
test "neg_keyid_too_long" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let long = String::make(3000, 'k')
  inspect(
    verify_outcome(
      ctx,
      req,
      "sig1=(\"@method\");created=1;keyid=\"" + long + "\"",
      "sig1=:YWJj:",
    ),
    content="KeyIdTooLong",
  )
}

///|
test "neg_key_not_found" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let parsed = parse_signature_input(signed.signature_input, Limits::default()).unwrap()
  let sig = parse_signature_field(signed.signature, Limits::default()).unwrap()
  let sb = get_signature(sig, "sig1").unwrap()
  let ctx = make_verify_ctx(make_test_key("different", "secret"), 1700000000L)
  inspect(
    verify_label_outcome(ctx, TargetRequest(req), parsed.entries[0], sb),
    content="KeyNotFound",
  )
}

///|
test "neg_mac_wrong" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let wrong_sig = "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  inspect(
    verify_outcome(ctx, req, signed.signature_input, wrong_sig),
    content="rejected",
  )
}

///|
test "neg_nonce_replay" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: Some("same-nonce"),
    tag: None,
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
  let resolver = InMemoryKeyResolver::new()
  let _ = resolver.add(key, Limits::default())
  let nonces = InMemoryNonceStore::new()
  let ctx = (
    resolver,
    VerificationPolicy::hmac_only(),
    FixedClock::new(1700000000L),
    nonces,
    Limits::default(),
  )
  inspect(
    verify_outcome(ctx, req, signed.signature_input, signed.signature),
    content="ok",
  )
  inspect(
    verify_outcome(ctx, req, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|

///|

///|
test "neg_header_crlf_injection" {
  let h = OrderedHeaders::new()
  match h.append("x-ok", "value\r\nX-Evil: 1") {
    Ok(_) => abort("CRLF injection must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidHeaderValue")
  }
  let h2 = OrderedHeaders::new()
  let _ = h2.append("x-ok", "fine")
  match
    RequestContext::new_default(
      "GET",
      "https",
      "h\r\nX: 1",
      "/",
      None,
      h2,
      None,
    ) {
    Ok(_) => abort("CRLF in authority must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidAuthority")
  }
}

///|

///|
test "neg_oversized_signature_field" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let big = String::make(40000, 'a')
  inspect(verify_outcome(ctx, req, big, "sig1=:YWJj:"), content="InputTooLarge")
}

///|
test "neg_too_many_labels" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let mut input = "s0=(\"@method\");created=1"
  let mut field = "s0=:YQ==:"
  for i = 1; i < 17; i = i + 1 {
    input = input + ", s" + i.to_string() + "=(\"@method\");created=1"
    field = field + ", s" + i.to_string() + "=:YQ==:"
  }
  inspect(verify_outcome(ctx, req, input, field), content="TooManySignatures")
}

///|
test "neg_too_many_components" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let mut components = "(\"@method\""
  for i = 0; i < 70; i = i + 1 {
    components = components + " \"x-h" + i.to_string() + "\""
  }
  components = components + ")"
  inspect(
    verify_outcome(
      ctx,
      req,
      "sig1=" + components + ";created=1;keyid=\"k1\"",
      "sig1=:YWJj:",
    ),
    content="TooManyComponents",
  )
}

///|
test "neg_too_many_parameters" {
  let req = make_minimal_request()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let mut params = ";created=1"
  for i = 0; i < 40; i = i + 1 {
    params = params + ";p" + i.to_string() + "=1"
  }
  inspect(
    verify_outcome(ctx, req, "sig1=(\"@method\")" + params, "sig1=:YWJj:"),
    content="TooManyParameters",
  )
}

///|
test "neg_empty_shared_secret" {
  let req = make_minimal_request()
  let key : KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: SharedSecret(Bytes::new(0)),
  }
  let params : SignatureParameters = {
    created: Some(1700000000L),
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
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "x"), 1700000000L)
  inspect(
    verify_outcome(ctx, req, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_keyid_looks_like_url_no_network" {
  let req = make_minimal_request()
  let signed = sign_test_request(
    [covered_derived(Method)],
    "https://attacker.example/key",
    1700000000L,
  ).unwrap()
  let parsed = parse_signature_input(signed.signature_input, Limits::default()).unwrap()
  let sig = parse_signature_field(signed.signature, Limits::default()).unwrap()
  let sb = get_signature(sig, "sig1").unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "secret"), 1700000000L)
  inspect(
    verify_label_outcome(ctx, TargetRequest(req), parsed.entries[0], sb),
    content="KeyNotFound",
  )
}

///|
test "neg_query_param_modified" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("pet=dog"),
    h,
    None,
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_derived(QueryParam("pet"))],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let mutated = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("pet=cat"),
    h,
    None,
  ).unwrap()
  let ctx = make_verify_ctx(key, 1700000000L)
  inspect(
    verify_outcome(ctx, mutated, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_method_modified" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    None,
    h,
    None,
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
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
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let mutated = RequestContext::new_default(
    "GET",
    "https",
    "example.com",
    "/foo",
    None,
    h,
    None,
  ).unwrap()
  let ctx = make_verify_ctx(key, 1700000000L)
  inspect(
    verify_outcome(ctx, mutated, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_trailer_modified_when_covered" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append_trailer("x-checksum", "abc")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    None,
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let tr_params : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: true,
    req: false,
    name: None,
  }
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_field_with_params("x-checksum", tr_params)],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let h2 = OrderedHeaders::new()
  let _ = h2.append("content-type", "application/json")
  let _ = h2.append_trailer("x-checksum", "XYZ")
  let mutated = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h2,
    None,
  ).unwrap()
  let ctx = make_verify_ctx(key, 1700000000L)
  inspect(
    verify_outcome(ctx, mutated, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_constant_time_length_diff" {
  inspect(
    constant_time_equal(
      @utf8.encode("short"),
      @utf8.encode("a much longer value"),
    ),
    content="false",
  )
}

///|
test "neg_uncovered_header_change_ok" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append("x-uncovered", "a")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    None,
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_field("content-type")],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let h2 = OrderedHeaders::new()
  let _ = h2.append("content-type", "application/json")
  let _ = h2.append("x-uncovered", "b")
  let mutated = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h2,
    None,
  ).unwrap()
  let ctx = make_verify_ctx(key, 1700000000L)
  inspect(
    verify_outcome(ctx, mutated, signed.signature_input, signed.signature),
    content="ok",
  )
}

///|

///|
test "neg_body_digest_policy_rejects_tamper" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let body = @utf8.encode("original")
  let _ = h.append(
    "content-digest",
    "sha-256=:" +
    base64_encode_bytes(sha256_raw(@utf8.encode("original"))) +
    ":",
  )
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    Some(body),
  ).unwrap()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  let options : SignOptions = {
    label: "sig1",
    components: [covered_field("content-digest")],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let mutated = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    Some(@utf8.encode("tampered")),
  ).unwrap()
  let ctx = make_verify_ctx(key, 1700000000L)
  let strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    require_content_digest: true,
  }
  let ctx2 = (ctx.0, strict, ctx.2, ctx.3, ctx.4)
  inspect(
    verify_outcome(ctx2, mutated, signed.signature_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_unknown_param_rejected_by_policy" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000000L)
  let modified_input = signed.signature_input.replace(
    old=";keyid=\"k1\"",
    new=";keyid=\"k1\";x-unknown=\"v\"",
  )
  let strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    reject_unknown_parameters: true,
  }
  let ctx2 = (ctx.0, strict, ctx.2, ctx.3, ctx.4)
  inspect(
    verify_outcome(ctx2, req, modified_input, signed.signature),
    content="rejected",
  )
}

///|
test "neg_signature_expired" {
  let req = make_minimal_request()
  let key = make_test_key("k1", "test-secret")
  let params : SignatureParameters = {
    created: Some(1700000000L),
    expires: Some(1700000100L),
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
    algorithm: "hmac-sha256",
    key,
  }
  let signed = sign_request(req, options, Limits::default()).unwrap()
  let ctx = make_verify_ctx(key, 2000000000L)
  let parsed = parse_signature_input(signed.signature_input, Limits::default()).unwrap()
  let sig = parse_signature_field(signed.signature, Limits::default()).unwrap()
  let sb = get_signature(sig, "sig1").unwrap()
  inspect(
    verify_label_outcome(ctx, TargetRequest(req), parsed.entries[0], sb),
    content="SignatureExpired",
  )
}

///|
test "neg_signature_too_old" {
  let req = make_minimal_request()
  let signed = sign_test_request([covered_derived(Method)], "k1", 1700000000L).unwrap()
  let ctx = make_verify_ctx(make_test_key("k1", "test-secret"), 1700000500L)
  let strict : VerificationPolicy = {
    ..VerificationPolicy::hmac_only(),
    max_signature_age_seconds: Some(100L),
  }
  let ctx2 = (ctx.0, strict, ctx.2, ctx.3, ctx.4)
  let parsed = parse_signature_input(signed.signature_input, Limits::default()).unwrap()
  let sig = parse_signature_field(signed.signature, Limits::default()).unwrap()
  let sb = get_signature(sig, "sig1").unwrap()
  inspect(
    verify_label_outcome(ctx2, TargetRequest(req), parsed.entries[0], sb),
    content="SignatureTooOld",
  )
}
