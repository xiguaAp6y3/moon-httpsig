// signature_base.mbt — Signature base construction (RFC 9421 §2.5).
//
// The signature base is the exact byte sequence that is signed. It is one
// line per covered component in order, each of the form
// `"component-id": value` followed by LF, then the final
// `"@signature-params": (...)`. There is no trailing LF. The @signature-params
// value must be byte-identical to the Signature-Input field serialization.

///|
/// The constructed signature base.
pub(all) struct SignatureBase {
  /// The exact bytes that are fed to the signature algorithm.
  bytes : Bytes
  /// The signature base as a UTF-8 string.
  text : String
  /// The individual lines (including the @signature-params line).
  lines : Array[String]
}

///|
/// Builds a signature base for a request.
pub fn build_request_signature_base(
  request : RequestContext,
  entry : SignatureInputEntry,
  limits : Limits,
) -> Result[SignatureBase, HsError] {
  build_signature_base(TargetRequest(request), entry, limits)
}

///|
/// Builds a signature base for a response.
pub fn build_response_signature_base(
  response : ResponseContext,
  entry : SignatureInputEntry,
  limits : Limits,
) -> Result[SignatureBase, HsError] {
  build_signature_base(TargetResponse(response), entry, limits)
}

///|
/// Builds a signature base for any target message.
pub fn build_signature_base(
  target : SignTarget,
  entry : SignatureInputEntry,
  limits : Limits,
) -> Result[SignatureBase, HsError] {
  Ok(build_signature_base_raise(target, entry, limits)) catch {
    e => Err(e)
  }
}

///|
/// Internal: builds the signature base, raising on failure.
fn build_signature_base_raise(
  target : SignTarget,
  entry : SignatureInputEntry,
  limits : Limits,
) -> SignatureBase raise HsError {
  if entry.covered_components.length() > limits.max_components_per_signature {
    raise hs_error(
      SignatureBaseConstruction,
      TooManyComponents,
      "too many covered components",
    )
  }
  let lines : Array[String] = Array::new()
  let seen : Array[String] = Array::new()
  for cc in entry.covered_components {
    let component_id = covered_component_string_raise(cc)
    for s in seen {
      if s == component_id {
        raise hs_error(
          SignatureBaseConstruction,
          InvalidComponentCombination,
          "duplicate component in signature base: " + component_id,
        )
      }
    }
    seen.push(component_id)
    let value = match resolve_component(cc, target) {
      Ok(v) => v
      Err(e) => raise e
    }
    lines.push(component_id + ": " + value)
  }
  let sig_params = serialize_entry_inner_list_raise(entry)
  let final_line = "\"@signature-params\": " + sig_params
  lines.push(final_line)
  let mut text = ""
  for i, line in lines {
    if i < lines.length() - 1 {
      text = text + line + "\n"
    } else {
      text = text + line
    }
  }
  let bytes = @utf8.encode(text)
  { bytes, text, lines }
}
