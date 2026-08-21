// signer.mbt — Signing requests and responses (RFC 9421 §3.1).
//
// The signer builds the Signature-Input entry, constructs the signature base,
// invokes the algorithm, and produces the two header field values. It never
// mutates the request or response it was given.

///|
/// Options for producing one signature.
pub(all) struct SignOptions {
  /// The signature label.
  label : String
  /// The ordered covered components.
  components : Array[CoveredComponent]
  /// The signature metadata parameters.
  parameters : SignatureParameters
  /// The requested algorithm name (e.g. `hmac-sha256`).
  algorithm : String
  /// The key record whose material is used to sign.
  key : KeyRecord
}

///|
/// The produced signature fields.
pub(all) struct SignedFields {
  /// The value for the `Signature-Input` header.
  signature_input : String
  /// The value for the `Signature` header.
  signature : String
  /// The exact signature base that was signed.
  signature_base : SignatureBase
}

///|
/// Signs a request message.
pub fn sign_request(
  request : RequestContext,
  options : SignOptions,
  limits : Limits,
) -> Result[SignedFields, HsError] {
  sign_target(TargetRequest(request), options, limits)
}

///|
/// Signs a response message.
pub fn sign_response(
  response : ResponseContext,
  options : SignOptions,
  limits : Limits,
) -> Result[SignedFields, HsError] {
  sign_target(TargetResponse(response), options, limits)
}

///|
/// Signs any target message.
pub fn sign_target(
  target : SignTarget,
  options : SignOptions,
  limits : Limits,
) -> Result[SignedFields, HsError] {
  try {
    let fields = sign_target_raise(target, options, limits)
    Ok(fields)
  } catch {
    e => Err(e)
  }
}

///|
/// Internal: signs a target, raising on failure.
fn sign_target_raise(
  target : SignTarget,
  options : SignOptions,
  limits : Limits,
) -> SignedFields raise HsError {
  validate_sign_options(options, limits)
  if options.components.length() > limits.max_components_per_signature {
    raise hs_error(Signing, TooManyComponents, "too many covered components")
  }
  let entry : SignatureInputEntry = {
    label: options.label,
    covered_components: options.components,
    parameters: options.parameters,
  }
  let base = match build_signature_base(target, entry, limits) {
    Ok(b) => b
    Err(e) => raise e
  }
  let provider = algorithm_provider(options.algorithm)
  let signature = match
    SignatureAlgorithm::sign(provider, base.bytes, options.key.material) {
    Ok(sig) => sig
    Err(e) => raise e
  }
  let input_field = match serialize_signature_input({ entries: [entry] }) {
    Ok(s) => s
    Err(e) => raise e
  }
  let sig_field = match
    serialize_signature_field({
      entries: [{ label: options.label, value: signature }],
    }) {
    Ok(s) => s
    Err(e) => raise e
  }
  { signature_input: input_field, signature: sig_field, signature_base: base }
}

///|
/// Validates signer options: non-empty label, non-empty components, and a
/// key whose algorithm matches the requested algorithm.
fn validate_sign_options(
  options : SignOptions,
  limits : Limits,
) -> Unit raise HsError {
  if options.label.is_empty() {
    raise hs_error(Signing, InvalidSignatureInput, "label must not be empty")
  }
  if options.components.is_empty() {
    raise hs_error(Signing, InvalidCoveredComponent, "no covered components")
  }
  limits.check_keyid_length(options.key.keyid)
  if options.key.algorithm != options.algorithm {
    raise hs_error(
      Signing,
      AlgorithmMismatch,
      "key algorithm " +
      options.key.algorithm +
      " does not match requested " +
      options.algorithm,
    )
  }
}

///|
/// Builds an algorithm provider for a name. `hmac-sha256` is implemented;
/// every other registered name resolves to `UnsupportedAlgorithm`, which
/// refuses to sign rather than producing a fake signature.
pub fn algorithm_provider(algorithm : String) -> SignatureAlgorithmProvider {
  if algorithm == "hmac-sha256" {
    Hmac(HmacSha256)
  } else {
    Unsupported(UnsupportedAlgorithm::new(algorithm))
  }
}
