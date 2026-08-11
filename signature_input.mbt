// signature_input.mbt — The Signature-Input HTTP field (RFC 9421 §4.1).
//
// Signature-Input is a Dictionary Structured Field. Each member key is a
// signature label; each member value is an Inner List of covered component
// strings plus the signature metadata parameters. Parsing preserves order
// everywhere because the signature base depends on it.

///|
/// A single signature's metadata from the Signature-Input field.
pub(all) struct SignatureInputEntry {
  label : String
  covered_components : Array[CoveredComponent]
  parameters : SignatureParameters
}

///|
/// The parsed Signature-Input field: one entry per signature label.
pub(all) struct SignatureInput {
  entries : Array[SignatureInputEntry]
}

///|
/// Creates an empty Signature-Input field.
pub fn SignatureInput::new() -> SignatureInput {
  { entries: Array::new() }
}

///|
/// Parses a raw Signature-Input field value into a `SignatureInput`.
///
/// The dictionary order, inner-list order, and parameter order are all
/// preserved. Duplicate labels are rejected. Each label must be a valid
/// dictionary key.
pub fn parse_signature_input(
  input : String,
  limits : Limits,
) -> Result[SignatureInput, HsError] {
  try {
    let entries = parse_signature_input_raise(input, limits)
    Ok({ entries, })
  } catch {
    e => Err(e)
  }
}

///|
/// Internal: parses Signature-Input, raising on violation.
fn parse_signature_input_raise(
  input : String,
  limits : Limits,
) -> Array[SignatureInputEntry] raise HsError {
  limits.check_signature_field_size(input.length(), "Signature-Input")
  let dict = match parse_sf_dictionary_string(input, limits) {
    Ok(d) => d
    Err(e) => raise e
  }
  let entries : Array[SignatureInputEntry] = Array::new()
  let seen : Array[String] = Array::new()
  for entry in dict {
    for s in seen {
      if s == entry.key {
        raise hs_error(
          SignatureInputParsing,
          DuplicateLabel,
          "duplicate signature label: " + entry.key,
        )
      }
    }
    seen.push(entry.key)
    let il = match entry.value {
      InnerListMember(il) => il
      ItemMember(_) =>
        raise hs_error(
          SignatureInputParsing,
          InvalidSignatureInput,
          "Signature-Input member must be an Inner List",
        )
    }
    let components = match
      parse_covered_components(il.items, limits.max_components_per_signature) {
      Ok(cs) => cs
      Err(e) => raise e
    }
    let parameters = match parse_signature_parameters(il.parameters) {
      Ok(p) => p
      Err(e) => raise e
    }
    entries.push({
      label: entry.key,
      covered_components: components,
      parameters,
    })
  }
  entries
}

///|
/// Serializes a Signature-Input field back to its canonical form.
pub fn serialize_signature_input(
  input : SignatureInput,
) -> Result[String, HsError] {
  Ok(serialize_signature_input_raise(input)) catch {
    e => Err(e)
  }
}

///|
/// Internal: serializes a Signature-Input field, raising on failure.
fn serialize_signature_input_raise(
  input : SignatureInput,
) -> String raise HsError {
  let out = Buffer::Buffer()
  for i, entry in input.entries {
    if i > 0 {
      out.write_string_utf8(", ")
    }
    out.write_string_utf8(entry.label)
    out.write_char_utf8('=')
    out.write_string_utf8(serialize_entry_inner_list_raise(entry))
  }
  buffer_to_string(out)
}

///|
/// Internal: serializes one entry's inner list (covered components plus
/// signature parameters), raising on failure.
fn serialize_entry_inner_list_raise(
  entry : SignatureInputEntry,
) -> String raise HsError {
  let items : Array[SfItem] = Array::new()
  for cc in entry.covered_components {
    items.push(covered_component_to_sf_item(cc))
  }
  let parameters : Array[SfParameter] = Array::new()
  signature_parameters_to_sf_params(entry.parameters, parameters)
  let il = { items, parameters }
  serialize_sf_inner_list_raise(il)
}

///|
/// Appends signature parameters as SF parameters (for serialization).
fn signature_parameters_to_sf_params(
  params : SignatureParameters,
  out : Array[SfParameter],
) -> Unit {
  if params.created is Some(v) {
    out.push({ name: "created", value: SfInteger(v) })
  }
  if params.expires is Some(v) {
    out.push({ name: "expires", value: SfInteger(v) })
  }
  if params.keyid is Some(v) {
    out.push({ name: "keyid", value: SfString(v) })
  }
  if params.nonce is Some(v) {
    out.push({ name: "nonce", value: SfString(v) })
  }
  if params.alg is Some(v) {
    out.push({ name: "alg", value: SfString(v) })
  }
  if params.tag is Some(v) {
    out.push({ name: "tag", value: SfString(v) })
  }
  for e in params.extensions {
    out.push({ name: e.name, value: e.value })
  }
}

///|
/// Returns the entry with the given label, or `MissingSignatureInput`.
pub fn get_signature_input(
  input : SignatureInput,
  label : String,
) -> Result[SignatureInputEntry, HsError] {
  for entry in input.entries {
    if entry.label == label {
      return Ok(entry)
    }
  }
  Err(
    hs_error(
      SignatureInputParsing,
      MissingSignatureInput,
      "no Signature-Input entry for label: " + label,
    ),
  )
}

///|
/// Appends an entry, rejecting a duplicate label.
pub fn append_signature_input(
  input : SignatureInput,
  entry : SignatureInputEntry,
) -> Result[SignatureInput, HsError] {
  for e in input.entries {
    if e.label == entry.label {
      return Err(
        hs_error(
          SignatureInputParsing,
          DuplicateLabel,
          "duplicate signature label: " + entry.label,
        ),
      )
    }
  }
  let entries = input.entries
  entries.push(entry)
  Ok({ entries, })
}

///|
/// Validates a parsed Signature-Input against RFC 9421 structural rules and
/// the configured limits:
/// - label uniqueness (already enforced at parse time);
/// - `expires` must not be earlier than `created`;
/// - `keyid`/`nonce`/`tag` length limits;
/// - signature count limit.
pub fn validate_signature_input(
  input : SignatureInput,
  limits : Limits,
) -> Result[Unit, HsError] {
  try {
    if input.entries.length() > limits.max_signature_count {
      raise hs_error(
        SignatureInputParsing,
        TooManySignatures,
        "too many signatures",
      )
    }
    for entry in input.entries {
      let p = entry.parameters
      if p.created is Some(c) && p.expires is Some(e) {
        if e < c {
          raise hs_error(
            SignatureInputParsing,
            InvalidTimestamp,
            "expires is earlier than created for label: " + entry.label,
          )
        }
      }
      if p.keyid is Some(k) {
        limits.check_keyid_length(k)
      }
      if p.nonce is Some(n) {
        limits.check_nonce_length(n)
      }
      if p.tag is Some(t) {
        limits.check_tag_length(t)
      }
    }
    Ok(())
  } catch {
    e => Err(e)
  }
}
