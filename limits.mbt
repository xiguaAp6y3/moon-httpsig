// limits.mbt — Resource limits for HTTP message signature processing.
//
// RFC 9421 defines no explicit input size limits, but an implementation that
// lets untrusted inputs drive unbounded allocation is not production safe.
// Every public entry point that parses or canonicalizes untrusted data checks
// the applicable limit before doing significant work.

///|
/// Hard resource limits applied while parsing and canonicalizing messages.
pub(all) struct Limits {
  /// Maximum number of header/trailer fields in one message.
  max_header_count : Int
  /// Maximum length (UTF-8 bytes) of a single header name.
  max_header_name_bytes : Int
  /// Maximum length (UTF-8 bytes) of a single header value.
  max_header_value_bytes : Int
  /// Maximum serialized length of a Signature-Input or Signature field.
  max_signature_field_bytes : Int
  /// Maximum number of signature entries in one message.
  max_signature_count : Int
  /// Maximum number of covered components in a single signature.
  max_components_per_signature : Int
  /// Maximum number of parameters on a single item/inner-list/dictionary entry.
  max_parameter_count : Int
  /// Maximum length (UTF-8 bytes) of a keyid string.
  max_keyid_bytes : Int
  /// Maximum length (UTF-8 bytes) of a nonce string.
  max_nonce_bytes : Int
  /// Maximum length (UTF-8 bytes) of a tag string.
  max_tag_bytes : Int
  /// Maximum body size (bytes) that is eligible for Content-Digest binding.
  max_body_bytes_for_digest : Int
}

///|
/// A conservative set of limits intended for production use.
pub fn Limits::default() -> Limits {
  {
    max_header_count: 128,
    max_header_name_bytes: 256,
    max_header_value_bytes: 16384,
    max_signature_field_bytes: 32768,
    max_signature_count: 16,
    max_components_per_signature: 64,
    max_parameter_count: 32,
    max_keyid_bytes: 1024,
    max_nonce_bytes: 256,
    max_tag_bytes: 256,
    max_body_bytes_for_digest: 16 * 1024 * 1024,
  }
}

///|
/// A stricter profile for high-security deployments.
pub fn Limits::strict() -> Limits {
  {
    max_header_count: 64,
    max_header_name_bytes: 256,
    max_header_value_bytes: 8192,
    max_signature_field_bytes: 16384,
    max_signature_count: 8,
    max_components_per_signature: 32,
    max_parameter_count: 16,
    max_keyid_bytes: 256,
    max_nonce_bytes: 128,
    max_tag_bytes: 128,
    max_body_bytes_for_digest: 8 * 1024 * 1024,
  }
}

///|
/// A permissive profile used only by tests and examples. Do not use in
/// production: it deliberately relaxes every bound.
pub fn Limits::permissive_for_tests() -> Limits {
  {
    max_header_count: 512,
    max_header_name_bytes: 4096,
    max_header_value_bytes: 65536,
    max_signature_field_bytes: 262144,
    max_signature_count: 64,
    max_components_per_signature: 256,
    max_parameter_count: 128,
    max_keyid_bytes: 8192,
    max_nonce_bytes: 2048,
    max_tag_bytes: 2048,
    max_body_bytes_for_digest: 256 * 1024 * 1024,
  }
}

///|
/// Checks that a serialized signature field fits within the configured bound.
pub fn Limits::check_signature_field_size(
  self : Limits,
  len : Int,
  what : String,
) -> Unit raise HsError {
  if len > self.max_signature_field_bytes {
    raise hs_error(
      StructuredFieldParsing,
      InputTooLarge,
      what + " too large: " + len.to_string() + " bytes",
    )
  }
}

///|
/// Checks a body size against the Content-Digest bound.
pub fn Limits::check_body_size_for_digest(
  self : Limits,
  len : Int,
) -> Unit raise HsError {
  if len > self.max_body_bytes_for_digest {
    raise hs_error(
      DigestBinding,
      InputTooLarge,
      "body too large for digest binding: " + len.to_string() + " bytes",
    )
  }
}

///|
/// Checks a keyid length against the configured bound.
pub fn Limits::check_keyid_length(
  self : Limits,
  keyid : String,
) -> Unit raise HsError {
  let len = @utf8.encode(keyid).length()
  if len > self.max_keyid_bytes {
    raise hs_error(
      PolicyValidation,
      KeyIdTooLong,
      "keyid too long: " + len.to_string() + " bytes",
    )
  }
}

///|
/// Checks a nonce length against the configured bound.
pub fn Limits::check_nonce_length(
  self : Limits,
  nonce : String,
) -> Unit raise HsError {
  let len = @utf8.encode(nonce).length()
  if len > self.max_nonce_bytes {
    raise hs_error(
      PolicyValidation,
      NonceTooLong,
      "nonce too long: " + len.to_string() + " bytes",
    )
  }
}

///|
/// Checks a tag length against the configured bound.
pub fn Limits::check_tag_length(
  self : Limits,
  tag : String,
) -> Unit raise HsError {
  let len = @utf8.encode(tag).length()
  if len > self.max_tag_bytes {
    raise hs_error(
      PolicyValidation,
      InvalidTag,
      "tag too long: " + len.to_string() + " bytes",
    )
  }
}
