// sf_parser.mbt — Structured field parser (RFC 9651 subset).
//
// Implements the grammar subset required by RFC 9421 signature fields:
// dictionary, inner list, item, parameters, string, token, integer,
// byte sequence, and boolean. Decimals are intentionally not supported
// (RFC 9421 signature fields never carry them); encountering one raises
// `InvalidStructuredField`.
//
// All parse functions take an `SfCursor` and advance it past the parsed
// construct. Callers are responsible for checking trailing garbage.

///|
/// Parses a `key` per RFC 9651 §4.2.3.2.
///
/// `key = (lcalpha / "*") *( lcalpha / DIGIT / "_" / "-" / "." / "*")`
fn parse_sf_key(c : SfCursor) -> String raise HsError {
  let start = c.pos()
  let first = c.peek()
  let first_ok = (first >= 'a' && first <= 'z') || first == '*'
  if !first_ok {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      c.pos(),
      "invalid key start",
    )
  }
  c.advance()
  while !c.at_end() {
    let ch = c.peek()
    let ok = (ch >= 'a' && ch <= 'z') ||
      (ch >= '0' && ch <= '9') ||
      ch == '_' ||
      ch == '-' ||
      ch == '.' ||
      ch == '*'
    if !ok {
      break
    }
    c.advance()
  }
  c.slice_from(start)
}

///|
/// Parses a quoted string `"..."` with `\"` and `\\` escapes.
fn parse_sf_string(c : SfCursor) -> String raise HsError {
  let start = c.pos()
  if c.take() != '"' {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      start,
      "expected opening DQUOTE for string",
    )
  }
  let out = Buffer::Buffer()
  while true {
    if c.at_end() {
      raise hs_error_at(
        StructuredFieldParsing,
        UnexpectedEnd,
        c.pos(),
        "unterminated string",
      )
    }
    let ch = c.take()
    if ch == '"' {
      break
    }
    if ch == '\\' {
      if c.at_end() {
        raise hs_error_at(
          StructuredFieldParsing,
          UnexpectedEnd,
          c.pos(),
          "unterminated string escape",
        )
      }
      let esc = c.take()
      if esc == '"' {
        out.write_char_utf8('"')
      } else if esc == '\\' {
        out.write_char_utf8('\\')
      } else {
        raise hs_error_at(
          StructuredFieldParsing,
          InvalidStructuredField,
          c.pos() - 2,
          "invalid string escape",
        )
      }
    } else {
      out.write_char_utf8(ch)
    }
  }
  buffer_to_string(out)
}

///|
/// Parses a token: `tchar *( tchar / ":" / "/" )`.
fn parse_sf_token(c : SfCursor) -> String raise HsError {
  let start = c.pos()
  let first = c.peek()
  if !is_tchar(first.to_string()) {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      start,
      "invalid token start",
    )
  }
  c.advance()
  while !c.at_end() {
    let ch = c.peek()
    if ch == ':' || ch == '/' {
      c.advance()
      continue
    }
    if is_tchar(ch.to_string()) {
      c.advance()
      continue
    }
    break
  }
  c.slice_from(start)
}

///|
/// Parses an integer: `["-"] 1*15DIGIT` fitting in `Int64`.
fn parse_sf_integer(c : SfCursor) -> Int64 raise HsError {
  let mut negative = false
  if !c.at_end() && c.peek() == '-' {
    negative = true
    c.advance()
  }
  if c.at_end() || !(c.peek() >= '0' && c.peek() <= '9') {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidInteger,
      c.pos(),
      "expected digits for integer",
    )
  }
  let mut value : Int64 = 0
  let mut digits = 0
  while !c.at_end() {
    let ch = c.peek()
    if ch < '0' || ch > '9' {
      break
    }
    digits = digits + 1
    if digits > 15 {
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidInteger,
        c.pos(),
        "integer too long",
      )
    }
    value = value * 10L + Int64::from_int(ch.to_int() - '0'.to_int())
    c.advance()
  }
  if negative {
    value = -value
  }
  // A digit followed immediately by '.' is a decimal, which is unsupported.
  if !c.at_end() && c.peek() == '.' {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      c.pos(),
      "sf-decimal is not supported",
    )
  }
  value
}

///|
/// Parses a boolean: `?0` / `?1`.
fn parse_sf_boolean(c : SfCursor) -> Bool raise HsError {
  let start = c.pos()
  if c.take() != '?' {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      start,
      "expected '?' for boolean",
    )
  }
  if c.at_end() {
    raise hs_error_at(
      StructuredFieldParsing,
      UnexpectedEnd,
      c.pos(),
      "unterminated boolean",
    )
  }
  let ch = c.take()
  if ch == '0' {
    false
  } else if ch == '1' {
    true
  } else {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      c.pos() - 1,
      "boolean must be ?0 or ?1",
    )
  }
}

///|
/// Parses a byte sequence: `":" *(base64) ":"`.
fn parse_sf_byte_sequence(c : SfCursor) -> Bytes raise HsError {
  let start = c.pos()
  if c.take() != ':' {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      start,
      "expected ':' for byte sequence",
    )
  }
  let b64_start = c.pos()
  let mut end = -1
  while !c.at_end() {
    if c.peek() == ':' {
      end = c.pos()
      c.advance()
      break
    }
    c.advance()
  }
  if end < 0 {
    raise hs_error_at(
      StructuredFieldParsing,
      UnexpectedEnd,
      c.pos(),
      "unterminated byte sequence",
    )
  }
  let encoded = c.input.sub(start=b64_start, end~).to_owned()
  match base64_decode_bytes(encoded) {
    Ok(b) => b
    Err(_) =>
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidBase64,
        b64_start,
        "invalid base64 in byte sequence",
      )
  }
}

///|
/// Parses zero or more parameters.
///
/// `parameters = *( ";" *SP parameter )`
fn parse_sf_parameters(
  c : SfCursor,
  max_parameter_count : Int,
) -> Array[SfParameter] raise HsError {
  let out : Array[SfParameter] = Array::new()
  while !c.at_end() {
    if c.peek() != ';' {
      break
    }
    c.advance()
    c.skip_sp()
    let name = parse_sf_key(c)
    for p in out {
      if p.name == name {
        raise hs_error_at(
          StructuredFieldParsing,
          InvalidStructuredField,
          c.pos(),
          "duplicate parameter: " + name,
        )
      }
    }
    if out.length() >= max_parameter_count {
      raise hs_error_at(
        StructuredFieldParsing,
        TooManyParameters,
        c.pos(),
        "too many parameters",
      )
    }
    let value = if !c.at_end() && c.peek() == '=' {
      c.advance()
      parse_sf_bare_item(c)
    } else {
      SfBoolean(true)
    }
    out.push({ name, value })
  }
  out
}

///|
/// Parses a bare item (string/token/integer/byte-sequence/boolean).
fn parse_sf_bare_item(c : SfCursor) -> SfBareItem raise HsError {
  let ch = c.peek()
  if ch == '"' {
    SfString(parse_sf_string(c))
  } else if ch == ':' {
    SfByteSequence(parse_sf_byte_sequence(c))
  } else if ch == '?' {
    SfBoolean(parse_sf_boolean(c))
  } else if ch == '-' || (ch >= '0' && ch <= '9') {
    SfInteger(parse_sf_integer(c))
  } else {
    SfToken(parse_sf_token(c))
  }
}

///|
/// Parses a single item: bare item plus parameters.
fn parse_sf_item(
  c : SfCursor,
  max_parameter_count : Int,
) -> SfItem raise HsError {
  let value = parse_sf_bare_item(c)
  let parameters = parse_sf_parameters(c, max_parameter_count)
  { value, parameters }
}

///|
/// Parses an inner list: `"(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")"`.
fn parse_sf_inner_list(
  c : SfCursor,
  max_parameter_count : Int,
  max_members : Int,
) -> SfInnerList raise HsError {
  let start = c.pos()
  if c.take() != '(' {
    raise hs_error_at(
      StructuredFieldParsing,
      InvalidStructuredField,
      start,
      "expected '(' for inner list",
    )
  }
  let items = Array::new()
  c.skip_sp()
  if !c.at_end() && c.peek() != ')' {
    while true {
      items.push(parse_sf_item(c, max_parameter_count))
      if items.length() > max_members {
        raise hs_error_at(
          StructuredFieldParsing,
          TooManyComponents,
          c.pos(),
          "too many inner-list members",
        )
      }
      c.skip_sp()
      if c.at_end() {
        raise hs_error_at(
          StructuredFieldParsing,
          UnexpectedEnd,
          c.pos(),
          "unterminated inner list",
        )
      }
      if c.peek() == ')' {
        break
      }
    }
  }
  if c.at_end() || c.take() != ')' {
    raise hs_error_at(
      StructuredFieldParsing,
      UnexpectedEnd,
      c.pos(),
      "unterminated inner list",
    )
  }
  let parameters = parse_sf_parameters(c, max_parameter_count)
  { items, parameters }
}

///|
/// Parses a dictionary into ordered entries.
///
/// `sf-dictionary = dict-member *( *SP ";" *SP dict-member )`
fn parse_sf_dictionary(
  c : SfCursor,
  max_parameter_count : Int,
  max_entries : Int,
  max_members : Int,
) -> Array[SfDictionaryEntry] raise HsError {
  let out = Array::new()
  c.skip_sp()
  if c.at_end() {
    return out
  }
  while true {
    let key = parse_sf_key(c)
    for e in out {
      if e.key == key {
        raise hs_error_at(
          StructuredFieldParsing,
          InvalidStructuredField,
          c.pos(),
          "duplicate dictionary key: " + key,
        )
      }
    }
    if out.length() >= max_entries {
      raise hs_error_at(
        StructuredFieldParsing,
        TooManySignatures,
        c.pos(),
        "too many dictionary entries",
      )
    }
    let value = if !c.at_end() && c.peek() == '=' {
      c.advance()
      if !c.at_end() && c.peek() == '(' {
        let il = parse_sf_inner_list(c, max_parameter_count, max_members)
        InnerListMember(il)
      } else {
        ItemMember(parse_sf_item(c, max_parameter_count))
      }
    } else {
      ItemMember({ value: SfBoolean(true), parameters: Array::new() })
    }
    out.push({ key, value })
    c.skip_sp()
    if c.at_end() {
      break
    }
    if c.peek() != ',' {
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidStructuredField,
        c.pos(),
        "expected ',' between dictionary members",
      )
    }
    c.advance()
    c.skip_sp()
    if c.at_end() {
      // A trailing ',' must be followed by another dict-member.
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidStructuredField,
        c.pos(),
        "trailing ',' in dictionary",
      )
    }
  }
  out
}

///|
/// Parses a complete dictionary from a string, requiring that no trailing
/// garbage remains. Returns the ordered entries.
pub fn parse_sf_dictionary_string(
  input : String,
  limits : Limits,
) -> Result[Array[SfDictionaryEntry], HsError] {
  try {
    let _ = limits.check_signature_field_size(
      input.length(),
      "structured field",
    )
    let c = SfCursor::new(input)
    let entries = parse_sf_dictionary(
      c,
      limits.max_parameter_count,
      limits.max_signature_count,
      limits.max_components_per_signature,
    )
    c.skip_sp()
    if !c.at_end() {
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidStructuredField,
        c.pos(),
        "trailing garbage after dictionary",
      )
    }
    Ok(entries)
  } catch {
    e => Err(e)
  }
}

///|
/// Parses a single item from a string, requiring no trailing garbage.
pub fn parse_sf_item_string(
  input : String,
  limits : Limits,
) -> Result[SfItem, HsError] {
  try {
    let _ = limits.check_signature_field_size(
      input.length(),
      "structured field",
    )
    let c = SfCursor::new(input)
    let item = parse_sf_item(c, limits.max_parameter_count)
    c.skip_sp()
    if !c.at_end() {
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidStructuredField,
        c.pos(),
        "trailing garbage after item",
      )
    }
    Ok(item)
  } catch {
    e => Err(e)
  }
}

///|
/// Parses a single inner list from a string, requiring no trailing garbage.
pub fn parse_sf_inner_list_string(
  input : String,
  limits : Limits,
) -> Result[SfInnerList, HsError] {
  try {
    let _ = limits.check_signature_field_size(
      input.length(),
      "structured field",
    )
    let c = SfCursor::new(input)
    let il = parse_sf_inner_list(
      c,
      limits.max_parameter_count,
      limits.max_components_per_signature,
    )
    c.skip_sp()
    if !c.at_end() {
      raise hs_error_at(
        StructuredFieldParsing,
        InvalidStructuredField,
        c.pos(),
        "trailing garbage after inner list",
      )
    }
    Ok(il)
  } catch {
    e => Err(e)
  }
}
