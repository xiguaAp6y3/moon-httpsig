// message.mbt — HTTP message model (RequestContext / ResponseContext).
//
// These are *canonicalization* models, not a full HTTP parser. They hold
// exactly the fields RFC 9421's derived components need, in raw form, so that
// `@target-uri`, `@authority`, `@path`, `@query`, and `@request-target` can be
// emitted byte-for-byte without a URL library re-encoding anything.

///|
/// An HTTP request message captured for signature canonicalization.
pub(all) struct RequestContext {
  method : String
  scheme : String
  authority : String
  path : String
  query : String?
  headers : OrderedHeaders
  body : Bytes?
}

///|
/// An HTTP response message captured for signature canonicalization.
///
/// `related_request` is optional and enables the `req` component parameter on
/// response signatures (RFC 9421 §3.2).
pub(all) struct ResponseContext {
  status : Int
  headers : OrderedHeaders
  body : Bytes?
  related_request : RequestContext?
}

///|
/// Validates and constructs a `RequestContext`.
///
/// The constructor performs the full validation suite: method token, scheme
/// grammar, CR/LF hygiene on authority/path/query, header safety, and body
/// size (when a body is present and `limits` is provided).
pub fn RequestContext::new(
  method : String,
  scheme : String,
  authority : String,
  path : String,
  query : String?,
  headers : OrderedHeaders,
  body : Bytes?,
  limits : Limits,
) -> Result[RequestContext, HsError] {
  Ok(
    request_context_build(
      method, scheme, authority, path, query, headers, body, limits,
    ),
  ) catch {
    e => Err(e)
  }
}

///|
/// Internal: validates and builds a request context, raising on failure.
fn request_context_build(
  method : String,
  scheme : String,
  authority : String,
  path : String,
  query : String?,
  headers : OrderedHeaders,
  body : Bytes?,
  limits : Limits,
) -> RequestContext raise HsError {
  check_method(method)
  check_scheme(scheme)
  check_authority(authority)
  check_path(path)
  if query is Some(_) {
    check_query(query.unwrap())
  }
  match body {
    Some(b) => limits.check_body_size_for_digest(b.length())
    None => ()
  }
  { method, scheme, authority, path, query, headers, body }
}

///|
/// Constructs a `RequestContext` using the default limits.
pub fn RequestContext::new_default(
  method : String,
  scheme : String,
  authority : String,
  path : String,
  query : String?,
  headers : OrderedHeaders,
  body : Bytes?,
) -> Result[RequestContext, HsError] {
  RequestContext::new(
    method,
    scheme,
    authority,
    path,
    query,
    headers,
    body,
    Limits::default(),
  )
}

///|
/// Validates and constructs a `ResponseContext`.
///
/// Status codes must be in 100..=999 and header/body rules match requests.
pub fn ResponseContext::new(
  status : Int,
  headers : OrderedHeaders,
  body : Bytes?,
  related_request : RequestContext?,
  limits : Limits,
) -> Result[ResponseContext, HsError] {
  try {
    check_status(status)
    match body {
      Some(b) => limits.check_body_size_for_digest(b.length())
      None => ()
    }
    Ok({ status, headers, body, related_request })
  } catch {
    e => Err(e)
  }
}

///|
/// Constructs a `ResponseContext` using the default limits.
pub fn ResponseContext::new_default(
  status : Int,
  headers : OrderedHeaders,
  body : Bytes?,
  related_request : RequestContext?,
) -> Result[ResponseContext, HsError] {
  ResponseContext::new(
    status,
    headers,
    body,
    related_request,
    Limits::default(),
  )
}

///|
/// Builds the `@target-uri` value: `scheme://authority/path?query`.
///
/// The components are concatenated verbatim. In particular the path is used
/// as-is (including an empty path when the request-target was `*` or
/// `OPTIONS *`); no percent-encoding or normalization is applied.
pub fn RequestContext::target_uri(self : RequestContext) -> String {
  let mut s = self.scheme + "://" + self.authority + self.path
  match self.query {
    Some(q) => if q.is_empty() { s = s + "?" } else { s = s + "?" + q }
    None => ()
  }
  s
}

///|
/// Builds the `@request-target` value: `method SP request-target`.
///
/// The request-target is the origin-form `path?query` (with an empty path
/// represented as empty), preserved verbatim.
pub fn RequestContext::request_target(self : RequestContext) -> String {
  let mut s = self.method + " "
  s = s + self.path
  match self.query {
    Some(q) => if q.is_empty() { s = s + "?" } else { s = s + "?" + q }
    None => ()
  }
  s
}

///|
/// The `@authority` component value (verbatim).
pub fn RequestContext::authority_component(self : RequestContext) -> String {
  self.authority
}

///|
/// The `@path` component value (verbatim).
pub fn RequestContext::path_component(self : RequestContext) -> String {
  self.path
}

///|
/// The raw query string without the leading `?`, or the empty string when the
/// request has no query.
pub fn RequestContext::raw_query(self : RequestContext) -> String {
  match self.query {
    Some(q) => q
    None => ""
  }
}

///|
/// The `@query` component value: the entire query string including the
/// leading `?` (RFC 9421 §2.2.7). When the query is absent, the value is a
/// lone `?`.
pub fn RequestContext::query_component(self : RequestContext) -> String {
  "?" + self.raw_query()
}

///|
/// Returns `true` if the request has a query (including an empty one), which
/// is distinct from "no query" for RFC 9421 `@query` canonicalization.
pub fn RequestContext::has_query(self : RequestContext) -> Bool {
  self.query is Some(_)
}
