// ordered_headers.mbt — Ordered, multi-value HTTP header model.
//
// A `Map[String, String]` cannot represent HTTP messages faithfully: it loses
// duplicate field names, wire order, the header/trailer distinction, and the
// ability to combine multiple field lines according to the correct RFC 9110
// rule per field. This module provides the ordered model used throughout the
// library.

///|
/// A single HTTP field instance (header or trailer line).
pub(all) struct HeaderField {
  name : String
  value : String
  trailer : Bool
}

///|
/// A wire-ordered list of header and trailer fields.
pub(all) struct OrderedHeaders {
  fields : Array[HeaderField]
}

///|
/// Creates an empty header set.
pub fn OrderedHeaders::new() -> OrderedHeaders {
  { fields: Array::new() }
}

///|
/// Appends a normal header field. `trailer` is set to `false`.
pub fn OrderedHeaders::append(
  self : OrderedHeaders,
  name : String,
  value : String,
) -> Result[Unit, HsError] {
  self.append_with_trailer_flag(name, value, false)
}

///|
/// Appends a trailer field (`trailer = true`).
pub fn OrderedHeaders::append_trailer(
  self : OrderedHeaders,
  name : String,
  value : String,
) -> Result[Unit, HsError] {
  self.append_with_trailer_flag(name, value, true)
}

///|
/// Internal: validates and appends a field with an explicit trailer flag.
fn OrderedHeaders::append_with_trailer_flag(
  self : OrderedHeaders,
  name : String,
  value : String,
  trailer : Bool,
) -> Result[Unit, HsError] {
  try {
    check_header_name(name)
    check_header_value(name, value)
    self.fields.push({ name, value, trailer })
    Ok(())
  } catch {
    e => Err(e)
  }
}

///|
/// Appends a field carrying an explicit trailer flag. Callers with raw wire
/// data use this to preserve the header/trailer distinction.
pub fn OrderedHeaders::append_field(
  self : OrderedHeaders,
  field : HeaderField,
) -> Result[Unit, HsError] {
  self.append_with_trailer_flag(field.name, field.value, field.trailer)
}

///|
/// Replaces every field with the given name (case-insensitive) with a single
/// field carrying `value`, preserving its position and the first instance's
/// trailer flag. If no field matches, `value` is appended as a header.
pub fn OrderedHeaders::set(
  self : OrderedHeaders,
  name : String,
  value : String,
) -> Result[Unit, HsError] {
  try {
    check_header_name(name)
    check_header_value(name, value)
    let mut replaced = false
    let mut i = 0
    while i < self.fields.length() {
      if self.fields[i].name.equal_ignore_ascii_case(name) {
        if replaced {
          let _ = self.fields.remove(i)
        } else {
          let f = self.fields[i]
          self.fields[i] = { name: f.name, value, trailer: f.trailer }
          replaced = true
          i = i + 1
        }
      } else {
        i = i + 1
      }
    }
    if !replaced {
      self.fields.push({ name, value, trailer: false })
    }
    Ok(())
  } catch {
    e => Err(e)
  }
}

///|
/// Removes every field with the given name (case-insensitive).
pub fn OrderedHeaders::remove(self : OrderedHeaders, name : String) -> Unit {
  let mut i = 0
  while i < self.fields.length() {
    if self.fields[i].name.equal_ignore_ascii_case(name) {
      let _ = self.fields.remove(i)
    } else {
      i = i + 1
    }
  }
}

///|
/// Returns the first field value with the given name, or `None` if absent.
pub fn OrderedHeaders::get_first(
  self : OrderedHeaders,
  name : String,
) -> String? {
  for f in self.fields {
    if f.name.equal_ignore_ascii_case(name) {
      return Some(f.value)
    }
  }
  None
}

///|
/// Returns all field values with the given name in wire order.
pub fn OrderedHeaders::get_all(
  self : OrderedHeaders,
  name : String,
) -> Array[String] {
  let out = Array::new()
  for f in self.fields {
    if f.name.equal_ignore_ascii_case(name) {
      out.push(f.value)
    }
  }
  out
}

///|
/// Returns `true` if at least one field with the given name exists.
pub fn OrderedHeaders::contains(self : OrderedHeaders, name : String) -> Bool {
  for f in self.fields {
    if f.name.equal_ignore_ascii_case(name) {
      return true
    }
  }
  false
}

///|
/// Returns all fields in wire order (including trailers).
pub fn OrderedHeaders::entries(self : OrderedHeaders) -> Array[HeaderField] {
  let out = Array::new()
  for f in self.fields {
    out.push({ name: f.name, value: f.value, trailer: f.trailer })
  }
  out
}

///|
/// Returns all non-trailer header values keyed by lower-cased name, in wire
/// order, with duplicates preserved.
pub fn OrderedHeaders::header_values(
  self : OrderedHeaders,
) -> Array[(String, String)] {
  let out = Array::new()
  for f in self.fields {
    if !f.trailer {
      out.push((f.name.to_lower(), f.value))
    }
  }
  out
}

///|
/// Returns all trailer values keyed by lower-cased name, in wire order.
pub fn OrderedHeaders::trailer_values(
  self : OrderedHeaders,
) -> Array[(String, String)] {
  let out = Array::new()
  for f in self.fields {
    if f.trailer {
      out.push((f.name.to_lower(), f.value))
    }
  }
  out
}

///|
/// Combines multiple field lines for a single name per RFC 9110 §5.2.
///
/// For most fields, RFC 9110 defines a "combined value" by joining the
/// field values with `", "` — but only when the field is a list-based field
/// whose grammar permits it. Some fields (notably `set-cookie`) must never be
/// combined. This function applies the safe default `", "` and rejects
/// `set-cookie`, which requires an explicit per-field policy.
pub fn OrderedHeaders::combined_value(
  self : OrderedHeaders,
  name : String,
) -> Result[String, HsError] {
  let all = self.get_all(name)
  if all.is_empty() {
    return Err(
      hs_error(MessageConstruction, MissingComponent, "no field named " + name),
    )
  }
  if name.equal_ignore_ascii_case("set-cookie") {
    return Err(
      hs_error(
        MessageConstruction,
        InvalidComponentCombination,
        "set-cookie must not be combined; use a per-field policy",
      ),
    )
  }
  if all.length() == 1 {
    return Ok(all[0])
  }
  let mut out = all[0]
  for i = 1; i < all.length(); i = i + 1 {
    out = out + ", " + all[i]
  }
  Ok(out)
}

///|
/// Combines multiple field lines with the caller-supplied joiner. This is the
/// escape hatch for fields (like `set-cookie`) whose combination rule is not
/// the RFC 9110 default.
pub fn OrderedHeaders::combined_value_with(
  self : OrderedHeaders,
  name : String,
  joiner : String,
) -> Result[String, HsError] {
  let all = self.get_all(name)
  if all.is_empty() {
    return Err(
      hs_error(MessageConstruction, MissingComponent, "no field named " + name),
    )
  }
  if all.length() == 1 {
    return Ok(all[0])
  }
  let mut out = all[0]
  for i = 1; i < all.length(); i = i + 1 {
    out = out + joiner + all[i]
  }
  Ok(out)
}

///|
/// Returns the number of stored fields.
pub fn OrderedHeaders::length(self : OrderedHeaders) -> Int {
  self.fields.length()
}
