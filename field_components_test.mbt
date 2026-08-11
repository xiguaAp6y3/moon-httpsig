// field_components_test.mbt — Field component resolution tests.

///|
fn field_req() -> RequestContext {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append("x-single", "value")
  let _ = h.append("x-multi", "a")
  let _ = h.append("x-multi", "b")
  let _ = h.append("x-ows", "  padded  ")
  let _ = h.append("x-dict", "a=1, b=2;x=1")
  match
    RequestContext::new_default(
      "GET",
      "https",
      "example.com",
      "/p",
      None,
      h,
      None,
    ) {
    Ok(r) => r
    Err(_) => abort("request build failed")
  }
}

///|

///|

///|

///|
test "field_key_member" {
  let req = field_req()
  let target : SignTarget = TargetRequest(req)
  let params : ComponentParameters = {
    sf: true,
    key: Some("b"),
    bs: false,
    tr: false,
    req: false,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-dict", parameters: params }, target).unwrap(),
    content="2;x=1",
  )
  let missing : ComponentParameters = {
    sf: true,
    key: Some("nope"),
    bs: false,
    tr: false,
    req: false,
    name: None,
  }
  match
    resolve_field_component({ name: "x-dict", parameters: missing }, target) {
    Ok(_) => abort("missing key must fail")
    Err(e) => inspect(e.kind_name(), content="MissingComponent")
  }
}

///|
test "field_bs_binary_wrapped" {
  let h = OrderedHeaders::new()
  let _ = h.append("x-bin", "aGVsbG8=")
  let _ = h.append("x-bin", "d29ybGQ=")
  let req = RequestContext::new_default("GET", "https", "h", "/", None, h, None).unwrap()
  let target : SignTarget = TargetRequest(req)
  let params : ComponentParameters = {
    sf: false,
    key: None,
    bs: true,
    tr: false,
    req: false,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-bin", parameters: params }, target).unwrap(),
    content="(:aGVsbG8=: :d29ybGQ=:)",
  )
}

///|
test "field_bs_invalid_base64" {
  let h = OrderedHeaders::new()
  let _ = h.append("x-bin", "not base64!!!")
  let req = RequestContext::new_default("GET", "https", "h", "/", None, h, None).unwrap()
  let target : SignTarget = TargetRequest(req)
  let params : ComponentParameters = {
    sf: false,
    key: None,
    bs: true,
    tr: false,
    req: false,
    name: None,
  }
  match resolve_field_component({ name: "x-bin", parameters: params }, target) {
    Ok(_) => abort("invalid base64 in bs must fail")
    Err(e) => inspect(e.kind_name(), content="InvalidBase64")
  }
}

///|
test "field_trailer_tr_flag" {
  let h = OrderedHeaders::new()
  let _ = h.append("x-t", "header-value")
  let _ = h.append_trailer("x-t", "trailer-value")
  let req = RequestContext::new_default("GET", "https", "h", "/", None, h, None).unwrap()
  let target : SignTarget = TargetRequest(req)
  let params_header : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: false,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-t", parameters: params_header }, target).unwrap(),
    content="header-value",
  )
  let _params_trailer : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: true,
    name: None,
  }
  // req on a request context must fail; use the tr flag instead.
  let params_tr : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: true,
    req: false,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-t", parameters: params_tr }, target).unwrap(),
    content="trailer-value",
  )
}

///|
test "field_req_from_related_request" {
  let h = OrderedHeaders::new()
  let _ = h.append("x-req", "request-value")
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/p",
    None,
    h,
    None,
  ).unwrap()
  let rh = OrderedHeaders::new()
  let _ = rh.append("x-req", "response-value")
  let resp = ResponseContext::new_default(200, rh, None, Some(req)).unwrap()
  let target : SignTarget = TargetResponse(resp)
  let params : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: false,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-req", parameters: params }, target).unwrap(),
    content="response-value",
  )
  let params_req : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: true,
    name: None,
  }
  inspect(
    resolve_field_component({ name: "x-req", parameters: params_req }, target).unwrap(),
    content="request-value",
  )
}

///|
test "field_req_missing_related" {
  let h = OrderedHeaders::new()
  let resp = ResponseContext::new_default(200, h, None, None).unwrap()
  let target : SignTarget = TargetResponse(resp)
  let params_req : ComponentParameters = {
    sf: false,
    key: None,
    bs: false,
    tr: false,
    req: true,
    name: None,
  }
  match
    resolve_field_component({ name: "x-any", parameters: params_req }, target) {
    Ok(_) => abort("req without related request must fail")
    Err(e) => inspect(e.kind_name(), content="MissingComponent")
  }
}
