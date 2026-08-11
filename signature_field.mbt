// signature_field.mbt — The Signature HTTP field (RFC 9421 §4.2).
//
// Signature is a Dictionary Structured Field. Each member key is a signature
// label; each member value is a Byte Sequence holding the raw signature
// bytes. Signatures are compared byte-wise with `constant_time_equal`; they
// are never converted to UTF-8 text.

///|
/// A single signature value: label plus raw signature bytes.
pub(all) struct SignatureEntry {
  label : String
  value : Bytes
}

///|
/// The parsed Signature field: one entry per signature label.
pub(all) struct SignatureField {
  entries : Array[SignatureEntry]
}

///|
/// Creates an empty Signature field.
pub fn SignatureField::new() -> SignatureField {
  { entries: Array::new() }
}

///|
/// Parses a raw Signature field value into a `SignatureField`.
///
/// Each member value must be a Byte Sequence; the raw bytes are preserved.
/// Duplicate labels are rejected. Base64 decoding errors surface as
/// `InvalidBase64`.
pub fn parse_signature_field(
  input : String,
  limits : Limits,
) -> Result[SignatureField, HsError] {
  try {
    let entries = parse_signature_field_raise(input, limits)
    Ok({ entries, })
  } catch {
    e => Err(e)
  }
}

///|
/// Internal: parses a Signature field, raising on violation.
fn parse_signature_field_raise(
  input : String,
  limits : Limits,
) -> Array[SignatureEntry] raise HsError {
  limits.check_signature_field_size(input.length(), "Signature")
  let dict = match parse_sf_dictionary_string(input, limits) {
    Ok(d) => d
    Err(e) => raise e
  }
  let entries : Array[SignatureEntry] = Array::new()
  let seen : Array[String] = Array::new()
  for entry in dict {
    for s in seen {
      if s == entry.key {
        raise hs_error(
          SignatureFieldParsing,
          DuplicateLabel,
          "duplicate signature label: " + entry.key,
        )
      }
    }
    seen.push(entry.key)
    let bytes = match entry.value {
      ItemMember(item) =>
        match item.value {
          SfByteSequence(b) => b
          _ =>
            raise hs_error(
              SignatureFieldParsing,
              InvalidSignatureField,
              "Signature member must be a Byte Sequence",
            )
        }
      InnerListMember(_) =>
        raise hs_error(
          SignatureFieldParsing,
          InvalidSignatureField,
          "Signature member must be a Byte Sequence",
        )
    }
    entries.push({ label: entry.key, value: bytes })
  }
  entries
}

///|
/// Serializes a Signature field back to its canonical form.
pub fn serialize_signature_field(
  field : SignatureField,
) -> Result[String, HsError] {
  try {
    let out = Buffer::Buffer()
    for i, entry in field.entries {
      if i > 0 {
        out.write_string_utf8(", ")
      }
      out.write_string_utf8(entry.label)
      out.write_char_utf8('=')
      out.write_string_utf8(":" + base64_encode_bytes(entry.value) + ":")
    }
    Ok(buffer_to_string(out))
  } catch {
    e => Err(e)
  }
}

///|
/// Returns the signature bytes for the given label, or `MissingSignature`.
pub fn get_signature(
  field : SignatureField,
  label : String,
) -> Result[Bytes, HsError] {
  for entry in field.entries {
    if entry.label == label {
      return Ok(entry.value)
    }
  }
  Err(
    hs_error(
      SignatureFieldParsing,
      MissingSignature,
      "no Signature entry for label: " + label,
    ),
  )
}

///|
/// Appends a signature entry, rejecting a duplicate label.
pub fn append_signature(
  field : SignatureField,
  entry : SignatureEntry,
) -> Result[SignatureField, HsError] {
  for e in field.entries {
    if e.label == entry.label {
      return Err(
        hs_error(
          SignatureFieldParsing,
          DuplicateLabel,
          "duplicate signature label: " + entry.label,
        ),
      )
    }
  }
  let entries = field.entries
  entries.push({ label: entry.label, value: entry.value })
  Ok({ entries, })
}

///|
/// Validates that the Signature and Signature-Input labels match exactly:
/// every label present in one field must be present in the other. The first
/// mismatched label is reported as `LabelMismatch`.
pub fn validate_signature_labels(
  input : SignatureInput,
  field : SignatureField,
) -> Result[Unit, HsError] {
  for entry in input.entries {
    let mut found = false
    for e in field.entries {
      if e.label == entry.label {
        found = true
        break
      }
    }
    if !found {
      return Err(
        hs_error(
          SignatureFieldParsing,
          LabelMismatch,
          "Signature missing label present in Signature-Input: " + entry.label,
        ),
      )
    }
  }
  for e in field.entries {
    let mut found = false
    for entry in input.entries {
      if entry.label == e.label {
        found = true
        break
      }
    }
    if !found {
      return Err(
        hs_error(
          SignatureInputParsing,
          LabelMismatch,
          "Signature-Input missing label present in Signature: " + e.label,
        ),
      )
    }
  }
  Ok(())
}

///|
/// Returns the number of entries.
pub fn SignatureField::length(self : SignatureField) -> Int {
  self.entries.length()
}
