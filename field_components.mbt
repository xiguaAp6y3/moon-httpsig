// field_components.mbt — Resolution of HTTP field components (RFC 9421 §2.1).
//
// A field component canonicalizes one or more HTTP field values. The default
// combination rule joins values with `", "` after trimming OWS (RFC 9110
// §5.2). The `sf`, `key`, `bs`, `tr`, and `req` parameters override the
// value handling as described in RFC 9421 §2.1.

///|
/// Resolves a field component to its canonical string value.
pub fn resolve_field_component(
  component : FieldComponent,
  target : SignTarget,
) -> Result[String, HsError] {
  Ok(resolve_field_component_raise(component, target)) catch {
    e => Err(e)
  }
}

///|
/// Internal: resolves a field component, raising on failure.
fn resolve_field_component_raise(
  component : FieldComponent,
  target : SignTarget,
) -> String raise HsError {
  let p = component.parameters
  let headers = effective_headers(target, p.req)
  let name = component.name.to_lower()
  let values = field_values_for(headers, name, p.tr)
  if values.is_empty() {
    raise hs_error(
      ComponentResolution,
      MissingComponent,
      "no field named: " + name,
    )
  }
  if p.bs {
    resolve_bs_component(values)
  } else {
    let combined = combine_values(values)
    if p.key is Some(k) {
      resolve_key_member(combined, k)
    } else if p.sf {
      resolve_sf_value(combined)
    } else {
      combined
    }
  }
}

///|
/// Returns the header set to resolve from: the request, or the response's
/// related request when `req` is set.
fn effective_headers(
  target : SignTarget,
  use_req : Bool,
) -> OrderedHeaders raise HsError {
  match target {
    TargetRequest(req) => req.headers
    TargetResponse(resp) =>
      if use_req {
        match resp.related_request {
          Some(req) => req.headers
          None =>
            raise hs_error(
              ComponentResolution,
              MissingComponent,
              "req component requested but no related request present",
            )
        }
      } else {
        resp.headers
      }
  }
}

///|
/// Returns the values of a field (headers or trailers per `tr`) in order.
fn field_values_for(
  headers : OrderedHeaders,
  name : String,
  tr : Bool,
) -> Array[String] {
  let out : Array[String] = Array::new()
  for f in headers.entries() {
    if f.name.equal_ignore_ascii_case(name) && f.trailer == tr {
      out.push(f.value)
    }
  }
  out
}

///|
/// Combines multiple field values with `", "` after trimming OWS per value.
fn combine_values(values : Array[String]) -> String {
  if values.length() == 1 {
    return strip_ows(values[0])
  }
  let mut out = strip_ows(values[0])
  for i = 1; i < values.length(); i = i + 1 {
    out = out + ", " + strip_ows(values[i])
  }
  out
}

///|
/// Resolves the `bs` parameter: each value is base64-decoded, wrapped as an
/// sf-byte-sequence, and the resulting sf-list is serialized strictly.
fn resolve_bs_component(values : Array[String]) -> String raise HsError {
  let out = Buffer::Buffer()
  out.write_char_utf8('(')
  for i, v in values {
    if i > 0 {
      out.write_char_utf8(' ')
    }
    let trimmed = strip_ows(v)
    let bytes = match base64_decode_bytes(trimmed) {
      Ok(b) => b
      Err(_) =>
        raise hs_error(
          ComponentResolution,
          InvalidBase64,
          "bs value is not valid base64",
        )
    }
    out.write_string_utf8(":" + base64_encode_bytes(bytes) + ":")
  }
  out.write_char_utf8(')')
  buffer_to_string(out)
}

///|
/// Resolves the `sf` parameter: parse the combined value as a structured
/// field and re-serialize it canonically. Items are tried first, then
/// dictionaries; inner lists alone are handled via the inner-list parser.
fn resolve_sf_value(combined : String) -> String raise HsError {
  let item = match parse_sf_item_string(combined, Limits::default()) {
    Ok(item) => Some(item)
    Err(_) => None
  }
  if item is Some(it) {
    return match serialize_sf_item(it) {
      Ok(s) => s
      Err(e) => raise e
    }
  }
  let inner = match parse_sf_inner_list_string(combined, Limits::default()) {
    Ok(il) => Some(il)
    Err(_) => None
  }
  if inner is Some(il) {
    return match serialize_sf_inner_list(il) {
      Ok(s) => s
      Err(e) => raise e
    }
  }
  let dict = match parse_sf_dictionary_string(combined, Limits::default()) {
    Ok(d) => d
    Err(e) => raise e
  }
  match serialize_sf_dictionary(dict) {
    Ok(s) => s
    Err(e) => raise e
  }
}

///|
/// Resolves the `key` parameter: parse the combined value as a dictionary
/// and serialize the named member strictly.
fn resolve_key_member(combined : String, key : String) -> String raise HsError {
  let dict = match parse_sf_dictionary_string(combined, Limits::default()) {
    Ok(d) => d
    Err(e) => raise e
  }
  for entry in dict {
    if entry.key == key {
      match entry.value {
        ItemMember(item) =>
          match serialize_sf_item(item) {
            Ok(s) => return s
            Err(e) => raise e
          }
        InnerListMember(il) =>
          match serialize_sf_inner_list(il) {
            Ok(s) => return s
            Err(e) => raise e
          }
      }
    }
  }
  raise hs_error(
    ComponentResolution,
    MissingComponent,
    "dictionary member not found: " + key,
  )
}
