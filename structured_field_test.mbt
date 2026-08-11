// structured_field_test.mbt — Structured-field parser/serializer tests.

///|
test "sf_dictionary_roundtrip_table" {
  // (input, canonical expected). Non-canonical inputs normalize on parse.
  let cases = [
    ("a", "a"),
    ("a=?0", "a=?0"),
    ("a=?1", "a"),
    ("a=1", "a=1"),
    ("a=-1", "a=-1"),
    ("a=42", "a=42"),
    ("a=\"string\"", "a=\"string\""),
    ("a=token", "a=token"),
    ("a=:aGk=:", "a=:aGk=:"),
    ("a=1;b=2", "a=1;b=2"),
    ("a=1;b;c=?0", "a=1;b;c=?0"),
    ("a=(b c d)", "a=(b c d)"),
    ("a=(b c d);x=1", "a=(b c d);x=1"),
    ("a, b", "a, b"),
    ("a=1, b=2, c=3", "a=1, b=2, c=3"),
    ("a=1 , b=2", "a=1, b=2"),
    ("a=(b), c=token;sf", "a=(b), c=token;sf"),
    ("x=1;key=\"k\";sf", "x=1;key=\"k\";sf"),
  ]
  for _, case in cases {
    let (input, expected) = case
    match parse_sf_dictionary_string(input, Limits::default()) {
      Ok(entries) =>
        inspect(serialize_sf_dictionary(entries).unwrap(), content=expected)
      Err(e) => abort("parse failed for [" + input + "]: " + e.kind_name())
    }
  }
}

///|
test "sf_item_roundtrip_table" {
  let cases = [
    "42", "-17", "\"hello world\"", "\"esc\\\"aped\"", "token-name", "?1", "?0",
    ":aGVsbG8gd29ybGQ=:", "42;param=1", "token;sf",
  ]
  for input in cases {
    match parse_sf_item_string(input, Limits::default()) {
      Ok(item) => inspect(serialize_sf_item(item).unwrap(), content=input)
      Err(e) => abort("parse failed for [" + input + "]: " + e.kind_name())
    }
  }
}

///|
test "sf_inner_list_roundtrip_table" {
  let cases = [
    "()", "(a)", "(a b)", "(a b c);p=1", "(1 2 3)", "(\"x\" token 42);flag",
  ]
  for input in cases {
    match parse_sf_inner_list_string(input, Limits::default()) {
      Ok(il) => inspect(serialize_sf_inner_list(il).unwrap(), content=input)
      Err(e) => abort("parse failed for [" + input + "]: " + e.kind_name())
    }
  }
}

///|
test "sf_parse_rejects_table" {
  let cases = [
    ("a b", "trailing garbage in dictionary"),
    ("A=1", "uppercase key"),
    ("a==1", "double equals"),
    ("a=1;;b", "double semicolon"),
    ("a=1,", "trailing comma"),
    ("a=1 b=2", "space between members"),
    ("a=1;b=:x:", "byte sequence param on integer"),
    ("a=(1 2", "unterminated inner list"),
    ("a=\"x\"\"y\"", "double close quote"),
    ("a=\"unterminated", "unterminated string"),
    ("a=\"bad\\escape\"", "invalid escape"),
    ("a=:badbase$:", "invalid base64"),
    ("a=1;b=1;b=2", "duplicate parameter"),
    ("(unterminated", "unterminated inner list"),
    ("a=99999999999999999999", "integer overflow"),
    ("a=?2", "bad boolean"),
  ]
  for _, case in cases {
    let (input, desc) = case
    match parse_sf_dictionary_string(input, Limits::default()) {
      Ok(_) => abort("should reject: " + desc + " [" + input + "]")
      Err(_) => ()
    }
  }
}

///|
test "sf_duplicate_dictionary_key" {
  match parse_sf_dictionary_string("a=1, a=2", Limits::default()) {
    Ok(_) => abort("duplicate key must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidStructuredField")
  }
}

///|
test "sf_parameter_limit" {
  // 33 parameters exceeds max_parameter_count = 32.
  let mut input = "a=1"
  for i = 0; i < 33; i = i + 1 {
    input = input + ";p" + i.to_string() + "=1"
  }
  match parse_sf_dictionary_string(input, Limits::default()) {
    Ok(_) => abort("too many parameters must be rejected")
    Err(e) => inspect(e.kind_name(), content="TooManyParameters")
  }
}

///|
test "sf_max_entries" {
  // 17 entries exceeds max_signature_count = 16.
  let mut input = "a0=1"
  for i = 1; i < 17; i = i + 1 {
    input = input + ", a" + i.to_string() + "=1"
  }
  match parse_sf_dictionary_string(input, Limits::default()) {
    Ok(_) => abort("too many entries must be rejected")
    Err(e) => inspect(e.kind_name(), content="TooManySignatures")
  }
}

///|
test "sf_string_escape_serialization" {
  let item = sf_string("a\"b\\c")
  inspect(serialize_sf_item(item).unwrap(), content="\"a\\\"b\\\\c\"")
}

///|
test "sf_boolean_implied_true_serialization" {
  let item = sf_boolean(true)
  inspect(serialize_sf_item(item).unwrap(), content="?1")
  // A dictionary entry with value ?1 serializes as the bare key.
  let entries : Array[SfDictionaryEntry] = [
    { key: "flag", value: ItemMember(sf_boolean(true)) },
  ]
  inspect(serialize_sf_dictionary(entries).unwrap(), content="flag")
}

///|
test "sf_byte_sequence_roundtrip_binary" {
  let data = b"\x00\x01\xfe\xff\x80"
  let item = sf_bytes(data)
  let s = serialize_sf_item(item).unwrap()
  inspect(s, content=":AAH+/4A=:")
  let parsed = parse_sf_item_string(s, Limits::default()).unwrap()
  match parsed.value {
    SfByteSequence(b) => inspect(constant_time_equal(b, data), content="true")
    _ => abort("wrong type")
  }
}

///|
test "sf_integer_boundary" {
  inspect(serialize_sf_integer(0L).unwrap(), content="0")
  inspect(serialize_sf_integer(-1L).unwrap(), content="-1")
  inspect(
    serialize_sf_integer(999999999999999L).unwrap(),
    content="999999999999999",
  )
  // Integers longer than 15 digits are rejected per RFC 9651.
  match parse_sf_item_string("9223372036854775807", Limits::default()) {
    Ok(_) => abort("19-digit integer must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidInteger")
  }
  let parsed = parse_sf_item_string("-999999999999999", Limits::default()).unwrap()
  match parsed.value {
    SfInteger(v) => inspect(v, content="-999999999999999")
    _ => abort("wrong type")
  }
}
