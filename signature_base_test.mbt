// signature_base_test.mbt — Signature base construction tests.

///|

///|

///|
test "base_missing_field_rejected" {
  let h = OrderedHeaders::new()
  let req = RequestContext::new_default("GET", "https", "h", "/", None, h, None).unwrap()
  let entry : SignatureInputEntry = {
    label: "sig1",
    covered_components: [covered_field("x-absent")],
    parameters: SignatureParameters::new(),
  }
  match build_request_signature_base(req, entry, Limits::default()) {
    Ok(_) => abort("missing field must be rejected")
    Err(e) => inspect(e.kind_name(), content="MissingComponent")
  }
}

///|
test "base_max_components" {
  let req = make_minimal_request()
  let components : Array[CoveredComponent] = Array::new()
  for i = 0; i < 65; i = i + 1 {
    components.push(covered_field("x-h" + i.to_string()))
  }
  let entry : SignatureInputEntry = {
    label: "sig1",
    covered_components: components,
    parameters: SignatureParameters::new(),
  }
  match build_request_signature_base(req, entry, Limits::default()) {
    Ok(_) => abort("too many components must be rejected")
    Err(e) => inspect(e.kind_name(), content="TooManyComponents")
  }
}
