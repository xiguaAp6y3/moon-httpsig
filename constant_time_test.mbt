// constant_time_test.mbt — Constant-time comparison tests.

///|
test "constant_time_equal_equal_values" {
  let a = @utf8.encode("abcdef")
  let b = @utf8.encode("abcdef")
  inspect(constant_time_equal(a, b), content="true")
}

///|
test "constant_time_equal_byte_diffs" {
  let a = @utf8.encode("abcdef")
  inspect(constant_time_equal(a, @utf8.encode("bbcdef")), content="false")
  inspect(constant_time_equal(a, @utf8.encode("abcXef")), content="false")
  inspect(constant_time_equal(a, @utf8.encode("abcdeX")), content="false")
}

///|
test "constant_time_equal_different_lengths" {
  inspect(
    constant_time_equal(@utf8.encode("abc"), @utf8.encode("abcdef")),
    content="false",
  )
  inspect(constant_time_equal(Bytes::new(0), Bytes::new(0)), content="true")
}

///|
test "constant_time_equal_binary" {
  let a = b"\x00\xff\x10\x7f\x80"
  inspect(constant_time_equal(a, b"\x00\xff\x10\x7f\x80"), content="true")
  inspect(constant_time_equal(a, b"\x00\xff\x10\x7f\x81"), content="false")
}

///|
test "constant_time_equal_large_input" {
  let big1 = Bytes::make(65536, b'\x41')
  let big2 = Bytes::make(65536, b'\x41')
  inspect(constant_time_equal(big1, big2), content="true")
}
