// adapter.mbt — HTTP/1.1 text adapter for moon-httpsig.
//
// MoonBit's core library has no HTTP framework, so this adapter works on raw
// HTTP/1.1 message text: it parses a request line, header section, and body
// into the library's `RequestContext`, and formats it back. The RFC 9530
// Content-Digest binding is exposed as a callback-style binding over
// `@hsig.sha256_raw` (the adapter cannot depend on a third-party HTTP
// framework that does not exist in the core distribution).

///|
/// Parses an HTTP/1.1 request message into a `RequestContext`.
///
/// The request line is `METHOD request-target HTTP/1.1`. The request-target
/// is split into path and query at the first `?`. Header lines are
/// `name: value`. An empty line separates the header section from the body.
pub fn parse_http11_request(
  text : String,
) -> Result[@hsig.RequestContext, @hsig.HsError] {
  try {
    let lines = split_lines(text)
    if lines.is_empty() {
      raise @hsig.hs_error(
        @hsig.HsErrorStage::MessageConstruction,
        @hsig.HsErrorKind::InvalidMethod,
        "empty request",
      )
    }
    let request_line = lines[0]
    let parts = request_line.split(" ")
    let mut method = ""
    let mut target = ""
    let mut protocol = ""
    let mut i = 0
    for part in parts {
      if i == 0 {
        method = part.to_owned()
      } else if i == 1 {
        target = part.to_owned()
      } else if i == 2 {
        protocol = part.to_owned()
      }
      i = i + 1
    }
    if !protocol.has_prefix("HTTP/") {
      raise @hsig.hs_error(
        @hsig.HsErrorStage::MessageConstruction,
        @hsig.HsErrorKind::InvalidMethod,
        "not an HTTP request line",
      )
    }
    // Split target into path and query.
    let path = match target.split_once("?") {
      Some((p, _q)) => p.to_owned()
      None => target
    }
    let query : String? = match target.split_once("?") {
      Some((_, q)) => Some(q.to_owned())
      None => None
    }
    // Headers.
    let headers = @hsig.OrderedHeaders::new()
    let mut line_idx = 1
    while line_idx < lines.length() {
      let line = lines[line_idx]
      if line.is_empty() {
        break
      }
      match line.split_once(":") {
        Some((name, value)) => {
          let _ = headers.append(
            name.to_owned(),
            value.trim(chars=" \t").to_owned(),
          )
          line_idx = line_idx + 1
        }
        None =>
          raise @hsig.hs_error(
            @hsig.HsErrorStage::MessageConstruction,
            @hsig.HsErrorKind::InvalidHeaderName,
            "malformed header line",
          )
      }
    }
    // Body is everything after the blank line.
    let mut body : Bytes? = None
    let body_start = find_body_start(lines)
    if body_start >= 0 {
      let mut body_text = ""
      for j = body_start; j < lines.length(); j = j + 1 {
        if j > body_start {
          body_text = body_text + "\n"
        }
        body_text = body_text + lines[j]
      }
      if !body_text.is_empty() {
        body = Some(@utf8.encode(body_text))
      }
    }
    let req = @hsig.RequestContext::new_default(
      method, "https", "example.com", path, query, headers, body,
    )
    match req {
      Ok(r) => Ok(r)
      Err(e) => Err(e)
    }
  } catch {
    e => Err(e)
  }
}

///|
/// Splits a message into lines.
fn split_lines(text : String) -> Array[String] {
  let out : Array[String] = Array::new()
  let mut cur = ""
  for ch in text {
    if ch == '\n' {
      out.push(cur)
      cur = ""
    } else if ch == '\r' {
      ()
    } else {
      cur = cur + ch.to_string()
    }
  }
  if !cur.is_empty() {
    out.push(cur)
  }
  out
}

///|
/// Returns the index of the blank line that separates headers from body.
fn find_body_start(lines : Array[String]) -> Int {
  for i, line in lines {
    if i >= 1 && line.is_empty() {
      return i + 1
    }
  }
  -1
}

///|
/// Formats a `RequestContext` back into an HTTP/1.1 request message.
pub fn format_http11_request(req : @hsig.RequestContext) -> String {
  let mut out = req.method + " " + req.path
  if req.has_query() {
    out = out + "?" + req.raw_query()
  }
  out = out + " HTTP/1.1\n"
  for f in req.headers.entries() {
    if !f.trailer {
      out = out + f.name + ": " + f.value + "\n"
    }
  }
  out = out + "\n"
  match req.body {
    Some(b) =>
      try {
        out = out + @utf8.decode(b)
      } catch {
        _ => ()
      }
    None => ()
  }
  out
}

///|
/// Computes an RFC 9530 `Content-Digest: sha-256=:...:` header value.
pub fn make_sha256_content_digest(body : Bytes) -> String {
  "sha-256=:" + @hsig.base64_encode_bytes(@hsig.sha256_raw(body)) + ":"
}

///|
/// Attaches `Signature-Input` and `Signature` headers to a request.
///
/// The message is not mutated: a copy with the two headers appended is
/// returned.
pub fn attach_signature_headers(
  req : @hsig.RequestContext,
  signed : @hsig.SignedFields,
) -> Result[@hsig.RequestContext, @hsig.HsError] {
  let headers = @hsig.OrderedHeaders::new()
  for f in req.headers.entries() {
    let _ = headers.append_field(f)
  }
  let _ = headers.append("signature-input", signed.signature_input)
  let _ = headers.append("signature", signed.signature)
  @hsig.RequestContext::new_default(
    req.method,
    req.scheme,
    req.authority,
    req.path,
    req.query,
    headers,
    req.body,
  )
}

///|
/// Extracts the `Signature-Input` header value from a request.
pub fn get_signature_input_header(req : @hsig.RequestContext) -> String? {
  req.headers.get_first("signature-input")
}

///|
/// Extracts the `Signature` header value from a request.
pub fn get_signature_header(req : @hsig.RequestContext) -> String? {
  req.headers.get_first("signature")
}

///|
/// A callback-style Content-Digest binding that validates `sha-256`
/// digests against the body bytes (RFC 9530).
pub struct Http11Sha256DigestBinding {
  covered : Array[@hsig.CoveredComponent]
}

///|
/// Constructs an HTTP/1.1 digest binding over the given covered components.
pub fn Http11Sha256DigestBinding::new(
  covered : Array[@hsig.CoveredComponent],
) -> Http11Sha256DigestBinding {
  { covered, }
}

///|
/// Implements the library's `DigestBinding` trait using RFC 9530 sha-256.
pub impl @hsig.DigestBinding for Http11Sha256DigestBinding with fn validate(
  self,
  headers,
  body,
) {
  @hsig.validate_content_digest(
    self.covered,
    headers,
    body,
    @hsig.Limits::default(),
  )
}
