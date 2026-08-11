// base64_value.mbt — Base64 and hex helpers.
//
// RFC 9651 `sf-bytes` (used by the Signature field and by Content-Digest)
// serializes a byte sequence with standard, padded base64 (RFC 4648 §4).
// The core library exposes `encode`/`decode`, but `decode` raises on
// malformed input. These wrappers present a `Result`-based API that maps
// malformed input onto `HsError` so callers never see a panic.

///|
/// Encodes bytes as standard padded base64 (the `sf-bytes` serialization).
pub fn base64_encode_bytes(bytes : Bytes) -> String {
  @b64.encode(bytes)
}

///|
/// Decodes a standard padded base64 string into bytes.
///
/// Returns `InvalidBase64` with a byte offset on any malformed input,
/// including bad characters, bad padding, and stray whitespace.
pub fn base64_decode_bytes(s : String) -> Result[Bytes, HsError] {
  Ok(@b64.decode(s)) catch {
    _ =>
      Err(
        hs_error(
          StructuredFieldParsing,
          InvalidBase64,
          "invalid base64 byte sequence",
        ),
      )
  }
}

///|
/// Encodes bytes as lowercase hex (used for SHA-256 digests in diagnostics
/// and for the fixture integrity checksum).
pub fn hex_encode_bytes(bytes : Bytes) -> String {
  let b = @buf.Buffer::Buffer(size_hint=bytes.length() * 2)
  for byte in bytes {
    b.write_byte(hex_nibble((byte.to_int() >> 4) & 0x0F))
    b.write_byte(hex_nibble(byte.to_int() & 0x0F))
  }
  // Buffer holds ASCII bytes; decode as UTF-8 (lossless for hex).
  @utf8.decode(b.to_bytes()) catch {
    _ => abort("hex buffer decode failed")
  }
}

///|
/// Returns the lowercase hex nibble for a value in 0..15.
fn hex_nibble(v : Int) -> Byte {
  if v < 10 {
    (b'0'.to_int() + v).to_byte()
  } else {
    (b'a'.to_int() + v - 10).to_byte()
  }
}

///|
/// Converts a UTF-8 byte buffer to a `String`.
///
/// Core's `Buffer::to_string()` interprets the buffer as UTF-16, which is
/// wrong for content written with `write_string_utf8`/`write_char_utf8`.
/// All string-building in this library uses UTF-8, so every conversion must
/// go through `@utf8.decode`. The content we build is always valid UTF-8, so
/// the raise can never fire in practice.
pub fn buffer_to_string(buf : @buf.Buffer) -> String raise HsError {
  @utf8.decode(buf.to_bytes()) catch {
    _ =>
      raise hs_error(
        StructuredFieldParsing,
        SerializationFailure,
        "internal UTF-8 decode failed",
      )
  }
}

///|
/// Decodes a lowercase or uppercase hex string into bytes.
///
/// Returns `InvalidBase64` (reusing the generic base64 kind for byte-decoding
/// failures) when the input length is odd or a character is not hex.
pub fn hex_decode_bytes(s : String) -> Result[Bytes, HsError] {
  if s.length() % 2 != 0 {
    return Err(
      hs_error(StructuredFieldParsing, InvalidBase64, "odd-length hex input"),
    )
  }
  let raw = FixedArray::make(s.length() / 2, b'\x00')
  for i = 0; i < s.length(); i = i + 2 {
    let hi = hex_digit(s.get_char(i))
    let lo = hex_digit(s.get_char(i + 1))
    if hi < 0 || lo < 0 {
      return Err(
        hs_error(StructuredFieldParsing, InvalidBase64, "invalid hex digit"),
      )
    }
    raw[i / 2] = ((hi << 4) | lo).to_byte()
  }
  Ok(Bytes::from_array(raw))
}

///|
/// Returns the numeric value of a hex digit character, or `-1` if absent or
/// not a hex digit.
fn hex_digit(c : Char?) -> Int {
  match c {
    Some(ch) => {
      let i = ch.to_int()
      if i >= '0'.to_int() && i <= '9'.to_int() {
        i - '0'.to_int()
      } else if i >= 'a'.to_int() && i <= 'f'.to_int() {
        i - 'a'.to_int() + 10
      } else if i >= 'A'.to_int() && i <= 'F'.to_int() {
        i - 'A'.to_int() + 10
      } else {
        -1
      }
    }
    None => -1
  }
}
