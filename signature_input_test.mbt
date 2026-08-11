// signature_input_test.mbt — Signature-Input field tests.

///|

///|
test "si_serialize_roundtrip_table" {
  let cases = [
    "sig1=(\"@method\" \"@target-uri\");created=1618884473;keyid=\"test-shared-secret\"",
    "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
    "sig1=(\"content-type\";sf \"@method\");created=1;alg=\"hmac-sha256\"", "sig1=(\"@query-param\";name=\"pet\");created=1",
    "sig1=(\"content-digest\";tr);created=1;nonce=\"abc\"", "sig1=(\"@method\";req);created=1",
    "sig1=(\"@status\" \"content-type\");created=1618884479;expires=1618885479;keyid=\"k\";tag=\"t\"",
  ]
  for input in cases {
    match parse_signature_input(input, Limits::default()) {
      Ok(parsed) =>
        inspect(serialize_signature_input(parsed).unwrap(), content=input)
      Err(e) => abort("parse failed for [" + input + "]: " + e.kind_name())
    }
  }
}

///|
test "si_parse_rejects_duplicate_label" {
  match
    parse_signature_input(
      "a=(\"@method\");created=1, a=(\"@path\");created=2",
      Limits::default(),
    ) {
    Ok(_) => abort("duplicate label must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidStructuredField")
  }
}

///|

///|
test "si_parse_rejects_bad_params" {
  match
    parse_signature_input("a=(\"@method\");created=\"x\"", Limits::default()) {
    Ok(_) => abort("created as string must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidSignatureInput")
  }
  match parse_signature_input("a=(\"@method\");keyid=5", Limits::default()) {
    Ok(_) => abort("keyid as integer must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidSignatureInput")
  }
  match
    parse_signature_input(
      "a=(\"@method\");created=2;created=3",
      Limits::default(),
    ) {
    Ok(_) => abort("duplicate created must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidStructuredField")
  }
}

///|
