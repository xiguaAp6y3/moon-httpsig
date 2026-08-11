// verifier.mbt — Verification of requests and responses (RFC 9421 §3.2).
//
// The verifier parses the Signature-Input and Signature fields, matches
// labels, checks policy (algorithm whitelist, time, required components),
// resolves keys, rebuilds the signature base, performs the cryptographic
// check, and enforces Content-Digest and nonce policies. Cheap format and
// policy checks always run before any cryptographic work.

///|
/// A signature that passed every check.
pub(all) struct VerifiedSignature {
  label : String
  keyid : String
  algorithm : String
  covered_components : Array[CoveredComponent]
  created : Int64?
  expires : Int64?
  nonce : String?
  tag : String?
}

///|
/// A signature that was rejected, with the reason.
pub(all) struct RejectedSignature {
  label : String?
  error : HsError
}

///|
/// The aggregate outcome of verifying all labels.
pub(all) struct VerificationReport {
  verified : Array[VerifiedSignature]
  rejected : Array[RejectedSignature]
}

///|
/// How multiple signatures must relate for the overall verification to
/// succeed.
pub(all) enum MultiSignaturePolicy {
  /// At least one signature verifies.
  AnyValid
  /// Every label present must verify.
  AllPresentValid
  /// Only the named label must verify.
  SpecificLabel(String)
}

///|
/// Verifies every signature on a request.
pub fn verify_request(
  request : RequestContext,
  signature_input : String,
  signature : String,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
  multi : MultiSignaturePolicy,
) -> Result[VerificationReport, HsError] {
  verify_target(
    TargetRequest(request),
    signature_input,
    signature,
    resolver,
    policy,
    clock,
    nonce_store,
    limits,
    multi,
  )
}

///|
/// Verifies every signature on a response.
pub fn verify_response(
  response : ResponseContext,
  signature_input : String,
  signature : String,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
  multi : MultiSignaturePolicy,
) -> Result[VerificationReport, HsError] {
  verify_target(
    TargetResponse(response),
    signature_input,
    signature,
    resolver,
    policy,
    clock,
    nonce_store,
    limits,
    multi,
  )
}

///|
/// Verifies every signature on any target message.
pub fn verify_target(
  target : SignTarget,
  signature_input : String,
  signature : String,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
  multi : MultiSignaturePolicy,
) -> Result[VerificationReport, HsError] {
  try {
    let report = verify_all_raise(
      target, signature_input, signature, resolver, policy, clock, nonce_store, limits,
      multi,
    )
    Ok(report)
  } catch {
    e => Err(e)
  }
}

///|
/// Internal: full verification flow, raising only on structural errors
/// (field-level failures) that make the whole message unverifiable.
fn verify_all_raise(
  target : SignTarget,
  signature_input : String,
  signature : String,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
  multi : MultiSignaturePolicy,
) -> VerificationReport raise HsError {
  limits.check_signature_field_size(signature_input.length(), "Signature-Input")
  limits.check_signature_field_size(signature.length(), "Signature")
  let input = match parse_signature_input(signature_input, limits) {
    Ok(i) => i
    Err(e) => raise e
  }
  let field = match parse_signature_field(signature, limits) {
    Ok(f) => f
    Err(e) => raise e
  }
  match validate_signature_input(input, limits) {
    Ok(_) => ()
    Err(e) => raise e
  }
  match validate_signature_labels(input, field) {
    Ok(_) => ()
    Err(e) => raise e
  }
  if input.entries.length() > limits.max_signature_count {
    raise hs_error(PolicyValidation, TooManySignatures, "too many signatures")
  }
  let verified : Array[VerifiedSignature] = Array::new()
  let rejected : Array[RejectedSignature] = Array::new()
  for entry in input.entries {
    let sig = match get_signature(field, entry.label) {
      Ok(b) => b
      Err(e) => {
        rejected.push({ label: Some(entry.label), error: e })
        continue
      }
    }
    try {
      let v = verify_one_label_raise(
        target, entry, sig, resolver, policy, clock, nonce_store, limits,
      )
      verified.push(v)
    } catch {
      e => rejected.push({ label: Some(entry.label), error: e })
    }
  }
  let ok = match multi {
    AnyValid => !verified.is_empty()
    AllPresentValid => verified.length() == input.entries.length()
    SpecificLabel(label) => {
      let mut found = false
      for v in verified {
        if v.label == label {
          found = true
          break
        }
      }
      found
    }
  }
  if !ok {
    raise hs_error(
      PolicyValidation,
      SignatureMismatch,
      "multi-signature policy not satisfied",
    )
  }
  { verified, rejected }
}

///|
/// Verifies a single label, returning its details on success.
pub fn verify_label(
  target : SignTarget,
  entry : SignatureInputEntry,
  signature_bytes : Bytes,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
) -> Result[VerifiedSignature, HsError] {
  Ok(
    verify_one_label_raise(
      target, entry, signature_bytes, resolver, policy, clock, nonce_store, limits,
    ),
  ) catch {
    e => Err(e)
  }
}

///|
/// Internal: verifies one signature, raising on the first failure. Ordering
/// is deliberate: cheap format/policy checks precede key resolution and the
/// cryptographic verification.
fn verify_one_label_raise(
  target : SignTarget,
  entry : SignatureInputEntry,
  signature_bytes : Bytes,
  resolver : InMemoryKeyResolver,
  policy : VerificationPolicy,
  clock : FixedClock,
  nonce_store : InMemoryNonceStore,
  limits : Limits,
) -> VerifiedSignature raise HsError {
  let p = entry.parameters
  // 1. Structural parameter checks.
  if p.created is Some(c) && p.expires is Some(e) {
    if e < c {
      raise hs_error(
        PolicyValidation,
        InvalidTimestamp,
        "expires is earlier than created",
      )
    }
  }
  if policy.require_created && p.created is None {
    raise hs_error(PolicyValidation, InvalidTimestamp, "created is required")
  }
  if policy.require_expires && p.expires is None {
    raise hs_error(PolicyValidation, InvalidTimestamp, "expires is required")
  }
  if policy.require_keyid && p.keyid is None {
    raise hs_error(PolicyValidation, MissingKeyId, "keyid is required")
  }
  if policy.reject_unknown_parameters && !p.extensions.is_empty() {
    raise hs_error(
      PolicyValidation,
      UnsupportedComponentParameter,
      "unknown signature parameters are not allowed",
    )
  }
  if policy.expected_tag is Some(expected) {
    let matches = match p.tag {
      Some(t) => t == expected
      None => false
    }
    if !matches {
      raise hs_error(PolicyValidation, InvalidTag, "tag does not match policy")
    }
  }
  // 2. Required components.
  for wanted in policy.required_components {
    if !components_cover(entry.covered_components, wanted) {
      raise hs_error(
        PolicyValidation,
        MissingRequiredComponent,
        "required component not covered: " + wanted.identifier(),
      )
    }
  }
  // 3. Key resolution.
  let keyid = match p.keyid {
    Some(k) => k
    None => raise hs_error(PolicyValidation, MissingKeyId, "keyid is missing")
  }
  limits.check_keyid_length(keyid)
  let record = match resolver.resolve(keyid) {
    Ok(r) => r
    Err(e) => raise e
  }
  let requested_alg = p.alg
  let algorithm = match requested_alg {
    Some(a) => a
    None => record.algorithm
  }
  if !policy.allows_algorithm(algorithm) {
    raise hs_error(
      PolicyValidation,
      AlgorithmNotAllowed,
      "algorithm not allowed: " + algorithm,
    )
  }
  if requested_alg is Some(a) {
    if record.algorithm != a {
      raise hs_error(
        KeyResolution,
        AlgorithmMismatch,
        "key algorithm does not match requested algorithm",
      )
    }
  }
  // 4. Time checks.
  let now = clock.now_unix_seconds()
  let created = p.created
  if created is Some(c) {
    if c > now + policy.allowed_clock_skew_seconds {
      raise hs_error(
        PolicyValidation,
        CreatedInFuture,
        "signature created in the future",
      )
    }
    // Compare with subtraction to avoid Int64 overflow for unbounded policies.
    if c - now > policy.max_future_seconds {
      raise hs_error(
        PolicyValidation,
        CreatedInFuture,
        "signature created too far in the future",
      )
    }
    if policy.max_signature_age_seconds is Some(limit) {
      if now - c > limit {
        raise hs_error(
          PolicyValidation,
          SignatureTooOld,
          "signature is too old",
        )
      }
    }
  }
  if p.expires is Some(e) {
    if now > e + policy.allowed_clock_skew_seconds {
      raise hs_error(
        PolicyValidation,
        SignatureExpired,
        "signature has expired",
      )
    }
  }
  // 5. Build the signature base.
  let base = match build_signature_base(target, entry, limits) {
    Ok(b) => b
    Err(e) => raise e
  }
  // 6. Cryptographic verification.
  let provider = algorithm_provider(algorithm)
  let valid = match
    provider.verify(base.bytes, signature_bytes, record.material) {
    Ok(v) => v
    Err(e) => raise e
  }
  if !valid {
    raise hs_error(
      CryptographicVerification,
      SignatureMismatch,
      "signature does not match",
    )
  }
  // 7. Nonce policy.
  if p.nonce is Some(nonce) {
    limits.check_nonce_length(nonce)
    match nonce_store.check_and_store(keyid, nonce, p.expires) {
      Ok(_) => ()
      Err(e) => raise e
    }
  } else if policy.require_nonce {
    raise hs_error(PolicyValidation, NonceRequired, "nonce is required")
  }
  // 8. Content-Digest binding.
  if policy.require_content_digest || policy.require_content_digest_covered {
    let headers = match target {
      TargetRequest(req) => req.headers
      TargetResponse(resp) => resp.headers
    }
    let body = match target {
      TargetRequest(req) => req.body.unwrap_or(Bytes::new(0))
      TargetResponse(resp) => resp.body.unwrap_or(Bytes::new(0))
    }
    let binding = RequireCoveredContentDigest::new(
      entry.covered_components,
      limits,
    )
    match binding.validate(headers, body) {
      Ok(_) => ()
      Err(e) => raise e
    }
  }
  {
    label: entry.label,
    keyid,
    algorithm,
    covered_components: entry.covered_components,
    created: p.created,
    expires: p.expires,
    nonce: p.nonce,
    tag: p.tag,
  }
}

///|
/// Convenience: an empty verification report.
pub fn empty_report() -> VerificationReport {
  { verified: Array::new(), rejected: Array::new() }
}
