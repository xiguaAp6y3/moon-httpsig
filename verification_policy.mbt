// verification_policy.mbt — Application verification policy.
//
// RFC 9421 defines how to verify a signature cryptographically; it is up to
// the application to decide which signatures to accept. `VerificationPolicy`
// encodes those application requirements: allowed algorithms, required
// components, time bounds, and the parameters that must be present.

///|
/// Application-level verification requirements.
pub(all) struct VerificationPolicy {
  /// The only algorithms accepted (whitelist). Empty means "reject all".
  allowed_algorithms : Array[String]
  /// Components that every acceptable signature must cover.
  required_components : Array[CoveredComponent]
  /// `created` must be present.
  require_created : Bool
  /// `expires` must be present.
  require_expires : Bool
  /// `keyid` must be present.
  require_keyid : Bool
  /// `nonce` must be present.
  require_nonce : Bool
  /// Reject signatures older than this many seconds (relative to `created`).
  max_signature_age_seconds : Int64?
  /// Permitted clock skew, in seconds, for `created` in the future.
  allowed_clock_skew_seconds : Int64
  /// Reject signatures whose `created` is this far in the future or more.
  max_future_seconds : Int64
  /// The only `tag` value accepted; `None` accepts any (or absent) tag.
  expected_tag : String?
  /// Reject signatures carrying unknown metadata parameters.
  reject_unknown_parameters : Bool
  /// Require a valid Content-Digest for the message body.
  require_content_digest : Bool
  /// Require Content-Digest to be covered by the signature.
  require_content_digest_covered : Bool
}

///|
/// A policy that accepts only `hmac-sha256` with reasonable defaults.
pub fn VerificationPolicy::hmac_only() -> VerificationPolicy {
  {
    allowed_algorithms: ["hmac-sha256"],
    required_components: Array::new(),
    require_created: true,
    require_expires: false,
    require_keyid: true,
    require_nonce: false,
    max_signature_age_seconds: None,
    allowed_clock_skew_seconds: 300L,
    max_future_seconds: 300L,
    expected_tag: None,
    reject_unknown_parameters: true,
    require_content_digest: false,
    require_content_digest_covered: false,
  }
}

///|
/// A permissive policy that imposes no time/keyid/nonce requirements
/// (cryptographic verification still runs and the algorithm whitelist still
/// lists the implemented algorithm). Intended for tests only.
pub fn VerificationPolicy::permissive() -> VerificationPolicy {
  {
    allowed_algorithms: ["hmac-sha256"],
    required_components: Array::new(),
    require_created: false,
    require_expires: false,
    require_keyid: false,
    require_nonce: false,
    max_signature_age_seconds: None,
    allowed_clock_skew_seconds: 0L,
    max_future_seconds: 9223372036854775807L,
    expected_tag: None,
    reject_unknown_parameters: false,
    require_content_digest: false,
    require_content_digest_covered: false,
  }
}

///|
/// Returns `true` if the algorithm is in the whitelist (or the whitelist is
/// empty, which means no algorithm is acceptable).
pub fn VerificationPolicy::allows_algorithm(
  self : VerificationPolicy,
  algorithm : String,
) -> Bool {
  for a in self.allowed_algorithms {
    if a == algorithm {
      return true
    }
  }
  false
}

///|
/// Returns `true` if `component` is covered by the given components.
pub fn components_cover(
  components : Array[CoveredComponent],
  wanted : CoveredComponent,
) -> Bool {
  let wanted_id = wanted.identifier()
  let wanted_str = match wanted.to_component_string() {
    Ok(s) => s
    Err(_) => wanted_id
  }
  for c in components {
    if c.identifier() == wanted_id {
      let cstr = match c.to_component_string() {
        Ok(s) => s
        Err(_) => c.identifier()
      }
      if cstr == wanted_str {
        return true
      }
    }
  }
  false
}
