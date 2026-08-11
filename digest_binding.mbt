// digest_binding.mbt — Content-Digest binding (RFC 9530, RFC 9421 §3.2).
//
// An HTTP message signature does not automatically protect the body: it only
// covers the components named in Signature-Input. A body is bound to a
// signature only when the message carries a valid Content-Digest and that
// field is covered by the signature. This module provides pluggable bindings
// rather than a full RFC 9530 implementation.

///|
/// Validates that a message body is bound to the signature via Content-Digest.
pub(open) trait DigestBinding {
  /// Validates the body against the message's Content-Digest headers.
  /// Returns `ContentDigestInvalid` when the digest does not match.
  fn validate(Self, OrderedHeaders, Bytes) -> Result[Unit, HsError]
}

///|
/// A binding that never validates the body. Use when the application has
/// already validated Content-Digest elsewhere or does not need body binding.
pub enum NoDigestBinding {
  NoDigestBinding
}

///|
/// A binding that requires Content-Digest to be present, to match the body,
/// and to be covered by the covered components. Content-Digest values are
/// RFC 9651 Dictionaries (`sha-256=:base64:`); the first recognized digest
/// is checked and must match.
pub struct RequireCoveredContentDigest {
  covered : Array[CoveredComponent]
  limits : Limits
}

///|
/// A binding that delegates validation to a callback.
pub struct CallbackDigestBinding {
  callback : (OrderedHeaders, Bytes) -> Result[Unit, HsError]
}

///|
/// Constructs a `NoDigestBinding`.
pub fn NoDigestBinding::new() -> NoDigestBinding {
  NoDigestBinding
}

///|
/// Constructs a `RequireCoveredContentDigest` over the given covered
/// components.
pub fn RequireCoveredContentDigest::new(
  covered : Array[CoveredComponent],
  limits : Limits,
) -> RequireCoveredContentDigest {
  { covered, limits }
}

///|
/// Constructs a `CallbackDigestBinding`.
pub fn CallbackDigestBinding::new(
  callback : (OrderedHeaders, Bytes) -> Result[Unit, HsError],
) -> CallbackDigestBinding {
  { callback, }
}

///|
/// Implements `DigestBinding` for `NoDigestBinding`.
pub impl DigestBinding for NoDigestBinding with fn validate(
  _self,
  _headers,
  _body,
) {
  Ok(())
}

///|
/// Implements `DigestBinding` for `RequireCoveredContentDigest`.
pub impl DigestBinding for RequireCoveredContentDigest with fn validate(
  self,
  headers,
  body,
) {
  validate_content_digest(self.covered, headers, body, self.limits)
}

///|
/// Implements `DigestBinding` for `CallbackDigestBinding`.
pub impl DigestBinding for CallbackDigestBinding with fn validate(
  self,
  headers,
  body,
) {
  (self.callback)(headers, body)
}

///|
/// Validates that the body matches a Content-Digest header that is covered by
/// `covered`. When `require_covered` is false only the digest validity is
/// checked.
pub fn validate_content_digest(
  covered : Array[CoveredComponent],
  headers : OrderedHeaders,
  body : Bytes,
  limits : Limits,
) -> Result[Unit, HsError] {
  try {
    if limits.max_body_bytes_for_digest >= 0 {
      limits.check_body_size_for_digest(body.length())
    }
    let values = headers.get_all("content-digest")
    if values.is_empty() {
      raise hs_error(
        DigestBinding,
        ContentDigestRequired,
        "Content-Digest header is missing",
      )
    }
    // Content-Digest is an SF Dictionary: sha-256=:base64:, sha-512=:base64:.
    let mut checked = false
    for value in values {
      let dict = match parse_sf_dictionary_string(value, limits) {
        Ok(d) => d
        Err(e) => raise e
      }
      for entry in dict {
        if entry.key == "sha-256" {
          let digest_bytes = match entry.value {
            ItemMember(item) =>
              match item.value {
                SfByteSequence(b) => b
                _ =>
                  raise hs_error(
                    DigestBinding,
                    ContentDigestInvalid,
                    "Content-Digest member must be a byte sequence",
                  )
              }
            InnerListMember(_) =>
              raise hs_error(
                DigestBinding,
                ContentDigestInvalid,
                "Content-Digest member must be a byte sequence",
              )
          }
          checked = true
          if !constant_time_equal(sha256_raw(body), digest_bytes) {
            raise hs_error(
              DigestBinding,
              ContentDigestInvalid,
              "Content-Digest does not match the message body",
            )
          }
        }
        // Unsupported digest algorithms (e.g. sha-512) are ignored per
        // RFC 9530 §3.
      }
    }
    if !checked {
      raise hs_error(
        DigestBinding,
        ContentDigestInvalid,
        "no supported digest algorithm present",
      )
    }
    // The digest must be covered by the signature to bind the body.
    let digest_component = covered_field("content-digest")
    let covered = components_cover(covered, digest_component)
    if !covered {
      raise hs_error(
        DigestBinding,
        ContentDigestNotCovered,
        "Content-Digest is not covered by the signature",
      )
    }
    Ok(())
  } catch {
    e => Err(e)
  }
}
