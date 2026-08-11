// signature_field_test.mbt — Signature field tests.

///|
test "sf_field_parse_single" {
  let parsed = parse_signature_field("sig1=:c2lnbmF0dXJl:", Limits::default()).unwrap()
  inspect(parsed.entries.length(), content="1")
  inspect(parsed.entries[0].label, content="sig1")
  inspect(
    constant_time_equal(parsed.entries[0].value, @utf8.encode("signature")),
    content="true",
  )
}

///|
test "sf_field_parse_multiple" {
  let parsed = parse_signature_field("a=:YQ==:, b=:Yg==:", Limits::default()).unwrap()
  inspect(parsed.entries.length(), content="2")
  let out = serialize_signature_field(parsed).unwrap()
  inspect(out, content="a=:YQ==:, b=:Yg==:")
}

///|
test "sf_field_rejects_non_bytes" {
  match parse_signature_field("a=token", Limits::default()) {
    Ok(_) => abort("token value must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidSignatureField")
  }
}

///|
test "sf_field_get_append" {
  let field = parse_signature_field("a=:YQ==:", Limits::default()).unwrap()
  match get_signature(field, "a") {
    Ok(b) => inspect(b.length(), content="1")
    Err(_) => abort("get existing failed")
  }
  match get_signature(field, "missing") {
    Ok(_) => abort("get missing must fail")
    Err(e) => inspect(e.kind_name(), content="MissingSignature")
  }
}
