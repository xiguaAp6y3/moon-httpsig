// derived_components_test.mbt — Derived component resolution tests.

///|

///|

///|

///|

///|
test "derived_query_param_cases" {
  let headers = OrderedHeaders::new()
  let cases = [
    ("a=b&c=d", "a", "b"),
    ("a=b&c=d", "c", "d"),
    ("a=b&c=d", "missing", ""), // missing -> error, tested separately
    ("a&b=2", "a", ""), // no-equals parameter has empty value
    ("a=&b=2", "a", ""),
    ("x=y&a=1&a=2", "a", "1"), // first occurrence wins
    ("a=%20b", "a", "%20b"), // percent-encoding preserved
    ("A=1&a=2", "A", "1"), // case-sensitive names
    ("a=b=c", "a", "b=c"), // value may contain '='
  ]
  for _, case in cases {
    let (query, name, expected) = case
    let req = RequestContext::new_default(
      "GET",
      "https",
      "h",
      "/p",
      Some(query),
      headers,
      None,
    ).unwrap()
    let target : SignTarget = TargetRequest(req)
    if name == "missing" {
      match resolve_derived_component(QueryParam(name), target, false) {
        Ok(_) => abort("missing param must error")
        Err(e) => inspect(e.kind_name(), content="MissingComponent")
      }
    } else {
      inspect(
        resolve_derived_component(QueryParam(name), target, false).unwrap(),
        content=expected,
      )
    }
  }
}

///|

///|
test "derived_status_rejected_on_request" {
  let req = make_minimal_request()
  match resolve_derived_component(Status, TargetRequest(req), false) {
    Ok(_) => abort("@status on a request must fail")
    Err(e) => inspect(e.kind_name(), content="InvalidComponentCombination")
  }
}

///|
test "derived_req_related_request" {
  let headers = OrderedHeaders::new()
  let req = RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/foo",
    Some("a=b"),
    headers,
    None,
  ).unwrap()
  let resp_headers = OrderedHeaders::new()
  let resp = ResponseContext::new_default(200, resp_headers, None, Some(req)).unwrap()
  // Without req: resolving a request-derived component on a response fails.
  match resolve_derived_component(Method, TargetResponse(resp), false) {
    Ok(_) => abort("method on response without req must fail")
    Err(e) => inspect(e.kind_name(), content="InvalidComponentCombination")
  }
  // With req: resolves against the related request.
  inspect(
    resolve_derived_component(Method, TargetResponse(resp), true).unwrap(),
    content="POST",
  )
  inspect(
    resolve_derived_component(Query, TargetResponse(resp), true).unwrap(),
    content="?a=b",
  )
}

///|
test "derived_signature_params_not_resolvable" {
  let req = make_minimal_request()
  match resolve_derived_component(SignatureParams, TargetRequest(req), false) {
    Ok(_) => abort("@signature-params must not resolve as a value")
    Err(e) => inspect(e.kind_name(), content="InvalidComponentCombination")
  }
}
