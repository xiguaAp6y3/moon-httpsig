// ascii.mbt — ASCII / HTTP token helpers.
//
// HTTP/1.1 field names, methods, and structured-field tokens are restricted
// ASCII. These helpers centralize the small grammar checks required by
// RFC 9110 (HTTP Semantics) and RFC 9651 (Structured Field Values) so that
// every validation path uses identical rules.
//
// The `check_*` helpers are internal and raise `HsError`; public constructors
// wrap them and convert to `Result`.

///|
/// Returns `true` if the byte is an HTTP `tchar` (RFC 9110 §5.6.2):
/// `!#$%&'*+-.^_`|~` plus alphanumerics.
fn is_tchar_byte(b : Byte) -> Bool {
  let i = b.to_int()
  if i >= 0x30 && i <= 0x39 {
    return true
  }
  if i >= 0x41 && i <= 0x5A {
    return true
  }
  if i >= 0x61 && i <= 0x7A {
    return true
  }
  match i {
    0x21
    | 0x23
    | 0x24
    | 0x25
    | 0x26
    | 0x27
    | 0x2A
    | 0x2B
    | 0x2D
    | 0x2E
    | 0x5E
    | 0x5F
    | 0x60
    | 0x7C
    | 0x7E => true
    _ => false
  }
}

///|
/// Returns `true` if every byte of the string is an HTTP `tchar`.
pub fn is_tchar(s : String) -> Bool {
  if s.is_empty() {
    return false
  }
  for b in @utf8.encode(s) {
    if !is_tchar_byte(b) {
      return false
    }
  }
  true
}

///|
/// Returns `true` if the string is a valid HTTP field name (RFC 9110 §5.1):
/// a non-empty sequence of `tchar` bytes. Field names are ASCII by definition,
/// so any non-ASCII byte fails the check.
pub fn is_valid_field_name(s : String) -> Bool {
  if s.is_empty() {
    return false
  }
  let bytes = @utf8.encode(s)
  if bytes.length() != s.code_units().length() {
    // A field name containing non-ASCII code units is invalid.
    return false
  }
  for b in bytes {
    if !is_tchar_byte(b) {
      return false
    }
  }
  true
}

///|
/// Returns `true` if the string contains a CR (`\r`) or LF (`\n`) byte,
/// which is forbidden in header values and in URI components.
pub fn contains_cr_or_lf(s : String) -> Bool {
  s.contains("\r") || s.contains("\n")
}

///|
/// Returns the string with one optional leading and trailing OWS removed.
/// Per RFC 9110 field value semantics only leading/trailing OWS is trimmed;
/// interior whitespace is preserved byte-for-byte.
pub fn strip_ows(s : String) -> String {
  s.trim(chars=" \t").to_owned()
}

///|
/// Validates a method token. Methods are case-sensitive `tchar` tokens.
/// An empty method or one containing whitespace is rejected.
fn check_method(method : String) -> Unit raise HsError {
  if method.is_empty() {
    raise hs_error(
      MessageConstruction,
      InvalidMethod,
      "method must not be empty",
    )
  }
  if method.contains(" ") || method.contains("\t") || contains_cr_or_lf(method) {
    raise hs_error(
      MessageConstruction,
      InvalidMethod,
      "method contains whitespace or control bytes",
    )
  }
  if !is_tchar(method) {
    raise hs_error(
      MessageConstruction,
      InvalidMethod,
      "method contains non-tchar bytes",
    )
  }
}

///|
/// Validates an authority value: it must not contain CR/LF. Note: we
/// deliberately avoid re-parsing the authority into host/port here because
/// RFC 9421 requires the raw authority component to be used verbatim in
/// `@authority`.
fn check_authority(authority : String) -> Unit raise HsError {
  if contains_cr_or_lf(authority) {
    raise hs_error(
      MessageConstruction,
      InvalidAuthority,
      "authority contains CR/LF",
    )
  }
}

///|
/// Validates a path component: no CR/LF. Percent-encoding is preserved
/// verbatim (RFC 9421 never re-encodes `@path`).
fn check_path(path : String) -> Unit raise HsError {
  if contains_cr_or_lf(path) {
    raise hs_error(MessageConstruction, InvalidPath, "path contains CR/LF")
  }
}

///|
/// Validates a query component: no CR/LF. Ordering, repeated parameters,
/// empty parameters, and equals-less parameters are preserved verbatim.
fn check_query(query : String) -> Unit raise HsError {
  if contains_cr_or_lf(query) {
    raise hs_error(MessageConstruction, InvalidPath, "query contains CR/LF")
  }
}

///|
/// Validates a scheme component: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
/// per RFC 3986 §3.1.
fn check_scheme(scheme : String) -> Unit raise HsError {
  if scheme.is_empty() {
    raise hs_error(
      MessageConstruction,
      InvalidScheme,
      "scheme must not be empty",
    )
  }
  let bytes = @utf8.encode(scheme)
  if bytes.length() != scheme.code_units().length() {
    raise hs_error(MessageConstruction, InvalidScheme, "scheme must be ASCII")
  }
  let first = bytes[0].to_int()
  if !((first >= 0x41 && first <= 0x5A) || (first >= 0x61 && first <= 0x7A)) {
    raise hs_error(
      MessageConstruction,
      InvalidScheme,
      "scheme must start with an ASCII letter",
    )
  }
  for i = 1; i < bytes.length(); i = i + 1 {
    let c = bytes[i].to_int()
    let ok = (c >= 0x41 && c <= 0x5A) ||
      (c >= 0x61 && c <= 0x7A) ||
      (c >= 0x30 && c <= 0x39) ||
      c == 0x2B ||
      c == 0x2D ||
      c == 0x2E
    if !ok {
      raise hs_error(
        MessageConstruction,
        InvalidScheme,
        "scheme contains invalid byte",
      )
    }
  }
}

///|
/// Validates a status code is in the range 100..=999.
fn check_status(status : Int) -> Unit raise HsError {
  if status < 100 || status > 999 {
    raise hs_error(
      MessageConstruction,
      InvalidStatus,
      "status must be 100..999",
    )
  }
}

///|
/// Validates that a header name is a legal HTTP field name, raising
/// `InvalidHeaderName` otherwise.
fn check_header_name(name : String) -> Unit raise HsError {
  if !is_valid_field_name(name) {
    raise hs_error(
      MessageConstruction,
      InvalidHeaderName,
      "invalid header name: " + truncate_context(name),
    )
  }
}

///|
/// Validates that a header value contains no CR or LF bytes.
fn check_header_value(name : String, value : String) -> Unit raise HsError {
  if contains_cr_or_lf(value) {
    raise hs_error(
      MessageConstruction,
      InvalidHeaderValue,
      "header value contains CR/LF: " + truncate_context(name),
    )
  }
}

///|
/// Cuts a string down to a safe diagnostic length.
fn truncate_context(s : String) -> String {
  if s.length() > 64 {
    s[:64].to_owned() + "..."
  } else {
    s
  }
}
