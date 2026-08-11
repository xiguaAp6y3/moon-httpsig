// accept_signature.mbt — The Accept-Signature field (RFC 9421 §5.1).
//
// Accept-Signature is a Dictionary whose members request future signatures:
// the key is the desired label, the value is an Inner List of desired covered
// components plus signature metadata parameters. Unlike Signature-Input,
// `created` and `expires` appear here as bare request flags (no value).
// This module only parses and serializes the negotiation content; it does not
// implement automatic HTTP client negotiation.

///|
/// The signature-request parameters of one Accept-Signature entry.
pub(all) struct AcceptSignatureRequest {
  /// `created` was requested (bare flag, no value).
  request_created : Bool
  /// `expires` was requested (bare flag, no value).
  request_expires : Bool
  /// `keyid` — the requested key identifier.
  keyid : String?
  /// `alg` — the requested algorithm.
  alg : String?
  /// `nonce` — the requested nonce value.
  nonce : String?
  /// `tag` — the requested tag value.
  tag : String?
  /// Unknown/extension parameters, preserved in order.
  extensions : Array[SfParameter]
}

///|
/// A single Accept-Signature entry.
pub(all) struct AcceptSignatureEntry {
  label : String
  covered_components : Array[CoveredComponent]
  request : AcceptSignatureRequest
}

///|
/// The parsed Accept-Signature field.
pub(all) struct AcceptSignature {
  entries : Array[AcceptSignatureEntry]
}

///|
/// Creates an empty Accept-Signature field.
pub fn AcceptSignature::new() -> AcceptSignature {
  { entries: Array::new() }
}

///|
/// Parses a raw Accept-Signature field value.
pub fn parse_accept_signature(
  input : String,
  limits : Limits,
) -> Result[AcceptSignature, HsError] {
  Ok(parse_accept_signature_raise(input, limits)) catch {
    e => Err(e)
  }
}

///|
/// Internal: parses Accept-Signature, raising on violation.
fn parse_accept_signature_raise(
  input : String,
  limits : Limits,
) -> AcceptSignature raise HsError {
  limits.check_signature_field_size(input.length(), "Accept-Signature")
  let dict = match parse_sf_dictionary_string(input, limits) {
    Ok(d) => d
    Err(e) => raise e
  }
  let entries : Array[AcceptSignatureEntry] = Array::new()
  let seen : Array[String] = Array::new()
  for entry in dict {
    for s in seen {
      if s == entry.key {
        raise hs_error(
          StructuredFieldParsing,
          DuplicateLabel,
          "duplicate label in Accept-Signature: " + entry.key,
        )
      }
    }
    seen.push(entry.key)
    let il = match entry.value {
      InnerListMember(il) => il
      ItemMember(_) =>
        raise hs_error(
          StructuredFieldParsing,
          InvalidAcceptSignature,
          "Accept-Signature member must be an Inner List",
        )
    }
    let components = match
      parse_covered_components(il.items, limits.max_components_per_signature) {
      Ok(cs) => cs
      Err(e) => raise e
    }
    let request = match parse_accept_request_parameters(il.parameters) {
      Ok(r) => r
      Err(e) => raise e
    }
    entries.push({ label: entry.key, covered_components: components, request })
  }
  { entries, }
}

///|
/// Parses the request parameters of one Accept-Signature entry. `created` and
/// `expires` are accepted as bare booleans (request flags) or integers.
pub fn parse_accept_request_parameters(
  params : Array[SfParameter],
) -> Result[AcceptSignatureRequest, HsError] {
  try {
    let mut request_created = false
    let mut request_expires = false
    let mut keyid : String? = None
    let mut alg : String? = None
    let mut nonce : String? = None
    let mut tag : String? = None
    let extensions : Array[SfParameter] = Array::new()
    for p in params {
      match p.name {
        "created" =>
          match p.value {
            SfBoolean(true) => request_created = true
            SfBoolean(false) => ()
            SfInteger(_) => request_created = true
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "created must be a bare flag",
              )
          }
        "expires" =>
          match p.value {
            SfBoolean(true) => request_expires = true
            SfBoolean(false) => ()
            SfInteger(_) => request_expires = true
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "expires must be a bare flag",
              )
          }
        "keyid" =>
          match p.value {
            SfString(v) => keyid = Some(v)
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "keyid must be a string",
              )
          }
        "alg" =>
          match p.value {
            SfString(v) => alg = Some(v)
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "alg must be a string",
              )
          }
        "nonce" =>
          match p.value {
            SfString(v) => nonce = Some(v)
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "nonce must be a string",
              )
          }
        "tag" =>
          match p.value {
            SfString(v) => tag = Some(v)
            _ =>
              raise hs_error(
                StructuredFieldParsing,
                InvalidAcceptSignature,
                "tag must be a string",
              )
          }
        _ => extensions.push({ name: p.name, value: p.value })
      }
    }
    Ok({ request_created, request_expires, keyid, alg, nonce, tag, extensions })
  } catch {
    e => Err(e)
  }
}

///|
/// Serializes an Accept-Signature field back to its canonical form.
pub fn serialize_accept_signature(
  accept : AcceptSignature,
) -> Result[String, HsError] {
  try {
    let out = Buffer::Buffer()
    for i, entry in accept.entries {
      if i > 0 {
        out.write_string_utf8(", ")
      }
      out.write_string_utf8(entry.label)
      out.write_char_utf8('=')
      let items : Array[SfItem] = Array::new()
      for cc in entry.covered_components {
        items.push(covered_component_to_sf_item(cc))
      }
      let parameters : Array[SfParameter] = Array::new()
      let r = entry.request
      if r.request_created {
        parameters.push({ name: "created", value: SfBoolean(true) })
      }
      if r.request_expires {
        parameters.push({ name: "expires", value: SfBoolean(true) })
      }
      if r.keyid is Some(v) {
        parameters.push({ name: "keyid", value: SfString(v) })
      }
      if r.alg is Some(v) {
        parameters.push({ name: "alg", value: SfString(v) })
      }
      if r.nonce is Some(v) {
        parameters.push({ name: "nonce", value: SfString(v) })
      }
      if r.tag is Some(v) {
        parameters.push({ name: "tag", value: SfString(v) })
      }
      for e in r.extensions {
        parameters.push({ name: e.name, value: e.value })
      }
      let il = { items, parameters }
      out.write_string_utf8(serialize_sf_inner_list_raise(il))
    }
    Ok(buffer_to_string(out))
  } catch {
    e => Err(e)
  }
}
