// ordered_headers_test.mbt — OrderedHeaders model tests.

///|

///|

///|

///|

///|
test "ordered_headers_trailer_flag" {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append_trailer("x-checksum", "abc")
  inspect(h.header_values().length(), content="1")
  inspect(h.trailer_values().length(), content="1")
  inspect(h.trailer_values()[0].0, content="x-checksum")
  // get_first searches both headers and trailers.
  inspect(h.get_first("x-checksum").unwrap(), content="abc")
  inspect(h.header_values().length(), content="1")
}

///|
test "ordered_headers_entries_order" {
  let h = OrderedHeaders::new()
  let _ = h.append("b", "1")
  let _ = h.append("a", "2")
  let _ = h.append_trailer("c", "3")
  let entries = h.entries()
  inspect(entries[0].name, content="b")
  inspect(entries[1].name, content="a")
  inspect(entries[2].name, content="c")
  inspect(entries[2].trailer, content="true")
}

///|
test "ordered_headers_header_name_validation_cases" {
  let h = OrderedHeaders::new()
  let invalid = ["", "with space", "with@at", "with:colon", "中文"]
  let mut rejected = 0
  for name in invalid {
    match h.append(name, "v") {
      Ok(_) => ()
      Err(_) => rejected = rejected + 1
    }
  }
  inspect(rejected, content="5")
  let valid = ["x", "X-Frame-Options", "a1_b.c*d"]
  let mut accepted = 0
  for name in valid {
    match h.append(name, "v") {
      Ok(_) => accepted = accepted + 1
      Err(_) => ()
    }
  }
  inspect(accepted, content="3")
}
