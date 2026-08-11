// sf_serializer.mbt — Canonical structured field serialization.
//
// Implements the canonical serialization rules of RFC 9651 §4.2 exactly so
// that a parsed-then-serialized signature field round-trips to the same bytes.
// This byte-exactness is required for RFC 9421 `@signature-params` (the final
// line of every signature base).
//
// Internal serialization functions raise `HsError`; the public entry points
// convert to `Result`.

///|
/// Serializes a string value with escaping.
pub fn serialize_sf_string(v : String) -> Result[String, HsError] {
  Ok(serialize_sf_string_raise(v)) catch {
    e => Err(e)
  }
}

///|
/// Internal: serializes a string with escaping.
fn serialize_sf_string_raise(v : String) -> String raise HsError {
  let out = Buffer::Buffer(size_hint=v.length() + 2)
  out.write_char_utf8('"')
  for ch in v {
    if ch == '"' || ch == '\\' {
      out.write_char_utf8('\\')
    }
    out.write_char_utf8(ch)
  }
  out.write_char_utf8('"')
  buffer_to_string(out)
}

///|
/// Serializes a token value, validating the token grammar.
pub fn serialize_sf_token(v : String) -> Result[String, HsError] {
  try {
    if !is_tchar(v) {
      raise hs_error(
        StructuredFieldParsing,
        InvalidStructuredField,
        "invalid token in serialization",
      )
    }
    Ok(v)
  } catch {
    e => Err(e)
  }
}

///|
/// Serializes an integer in canonical decimal form.
pub fn serialize_sf_integer(v : Int64) -> Result[String, HsError] {
  Ok(v.to_string())
}

///|
/// Serializes a boolean as `?0` or `?1`.
pub fn serialize_sf_boolean(v : Bool) -> Result[String, HsError] {
  if v {
    Ok("?1")
  } else {
    Ok("?0")
  }
}

///|
/// Serializes a byte sequence with standard padded base64.
pub fn serialize_sf_byte_sequence(v : Bytes) -> Result[String, HsError] {
  Ok(":" + base64_encode_bytes(v) + ":")
}

///|
/// Serializes a bare item.
pub fn serialize_sf_bare_item(v : SfBareItem) -> Result[String, HsError] {
  match v {
    SfString(s) => serialize_sf_string(s)
    SfToken(t) => serialize_sf_token(t)
    SfInteger(i) => serialize_sf_integer(i)
    SfByteSequence(b) => serialize_sf_byte_sequence(b)
    SfBoolean(b) => serialize_sf_boolean(b)
  }
}

///|
/// Internal: serializes a bare item, raising on failure.
fn serialize_sf_bare_item_raise(v : SfBareItem) -> String raise HsError {
  match v {
    SfString(s) => serialize_sf_string_raise(s)
    SfToken(t) =>
      if !is_tchar(t) {
        raise hs_error(
          StructuredFieldParsing,
          InvalidStructuredField,
          "invalid token in serialization",
        )
      } else {
        t
      }
    SfInteger(i) => i.to_string()
    SfByteSequence(b) => ":" + base64_encode_bytes(b) + ":"
    SfBoolean(b) => if b { "?1" } else { "?0" }
  }
}

///|
/// Internal: serializes a parameter list. Parameters with a `?1` value
/// serialize as a bare `;name` (RFC 9651 §4.2.5).
fn serialize_sf_parameters_raise(
  parameters : Array[SfParameter],
) -> String raise HsError {
  let out = Buffer::Buffer()
  for p in parameters {
    out.write_char_utf8(';')
    out.write_string_utf8(p.name)
    if !(p.value is SfBoolean(true)) {
      out.write_char_utf8('=')
      out.write_string_utf8(serialize_sf_bare_item_raise(p.value))
    }
  }
  buffer_to_string(out)
}

///|
/// Internal: serializes an item (bare item plus parameters).
fn serialize_sf_item_raise(v : SfItem) -> String raise HsError {
  let base = serialize_sf_bare_item_raise(v.value)
  let params = serialize_sf_parameters_raise(v.parameters)
  base + params
}

///|
/// Internal: serializes an inner list.
fn serialize_sf_inner_list_raise(v : SfInnerList) -> String raise HsError {
  let out = Buffer::Buffer()
  out.write_char_utf8('(')
  for i, item in v.items {
    if i > 0 {
      out.write_char_utf8(' ')
    }
    out.write_string_utf8(serialize_sf_item_raise(item))
  }
  out.write_char_utf8(')')
  out.write_string_utf8(serialize_sf_parameters_raise(v.parameters))
  buffer_to_string(out)
}

///|
/// Internal: serializes a dictionary member with its leading `key=` prefix
/// elided when the value is an implied-true boolean.
fn serialize_sf_member_raise(
  key : String,
  member : SfMember,
) -> String raise HsError {
  match member {
    ItemMember(item) =>
      if item.value is SfBoolean(true) && item.parameters.is_empty() {
        key
      } else {
        key + "=" + serialize_sf_item_raise(item)
      }
    InnerListMember(il) => key + "=" + serialize_sf_inner_list_raise(il)
  }
}

///|
/// Internal: serializes an ordered dictionary.
fn serialize_sf_dictionary_raise(
  entries : Array[SfDictionaryEntry],
) -> String raise HsError {
  let out = Buffer::Buffer()
  for i, entry in entries {
    if i > 0 {
      out.write_string_utf8(", ")
    }
    out.write_string_utf8(serialize_sf_member_raise(entry.key, entry.value))
  }
  buffer_to_string(out)
}

///|
/// Serializes an item.
pub fn serialize_sf_item(v : SfItem) -> Result[String, HsError] {
  Ok(serialize_sf_item_raise(v)) catch {
    e => Err(e)
  }
}

///|
/// Serializes an inner list.
pub fn serialize_sf_inner_list(v : SfInnerList) -> Result[String, HsError] {
  Ok(serialize_sf_inner_list_raise(v)) catch {
    e => Err(e)
  }
}

///|
/// Serializes a dictionary.
pub fn serialize_sf_dictionary(
  entries : Array[SfDictionaryEntry],
) -> Result[String, HsError] {
  Ok(serialize_sf_dictionary_raise(entries)) catch {
    e => Err(e)
  }
}
