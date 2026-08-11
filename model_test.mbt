// model_test.mbt — HTTP message model tests.

///|
test "model_request_validation_method" {
  let headers = OrderedHeaders::new()
  let cases = [
    ("", "invalid method rejected"),
    ("GET GET", "method with space rejected"),
    ("GET\tPOST", "method with tab rejected"),
    ("GET", "valid method accepted"),
  ]
  let mut accepted = 0
  for _, case in cases {
    let (method, _desc) = case
    match
      RequestContext::new_default(
        method,
        "https",
        "h",
        "/",
        None,
        headers,
        None,
      ) {
      Ok(_) => accepted = accepted + 1
      Err(_) => ()
    }
  }
  inspect(accepted, content="1")
}

///|
test "model_target_uri_construction" {
  let headers = OrderedHeaders::new()
  let req = RequestContext::new_default(
    "GET",
    "https",
    "www.example.com",
    "/path",
    Some("a=b&c=d"),
    headers,
    None,
  ).unwrap()
  inspect(req.target_uri(), content="https://www.example.com/path?a=b&c=d")
  inspect(req.request_target(), content="GET /path?a=b&c=d")
  inspect(req.query_component(), content="?a=b&c=d")
}

///|
test "model_request_rejects_bad_header" {
  let headers = OrderedHeaders::new()
  match headers.append("bad name", "value") {
    Ok(_) => abort("invalid header name accepted")
    Err(e) => inspect(e.kind_name(), content="InvalidHeaderName")
  }
  match headers.append("x-good", "value\r\ninject") {
    Ok(_) => abort("header value with CRLF accepted")
    Err(e) => inspect(e.kind_name(), content="InvalidHeaderValue")
  }
}

///|
test "model_request_validation_scheme" {
  let headers = OrderedHeaders::new()
  match
    RequestContext::new_default("GET", "1http", "h", "/", None, headers, None) {
    Ok(_) => abort("scheme starting with digit must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidScheme")
  }
  match
    RequestContext::new_default("GET", "https", "h", "/", None, headers, None) {
    Ok(_) => ()
    Err(_) => abort("valid scheme rejected")
  }
}

///|
test "model_request_validation_crlf" {
  let headers = OrderedHeaders::new()
  match
    RequestContext::new_default(
      "GET",
      "https",
      "h\r\nx",
      "/",
      None,
      headers,
      None,
    ) {
    Ok(_) => abort("authority with CRLF must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidAuthority")
  }
}
