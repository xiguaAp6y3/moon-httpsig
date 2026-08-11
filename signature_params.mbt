// signature_params.mbt — Signature metadata parameters (RFC 9421 §2.3).
//
// `created`, `expires`, `keyid`, `alg`, `nonce`, and `tag` are the defined
// signature metadata parameters. Unknown parameters are preserved as
// `extensions` so that a parser/serializer round-trip keeps them intact; a
// `VerificationPolicy` decides whether to accept them.

///|
/// The signature metadata parameters of one signature.
pub(all) struct SignatureParameters {
  /// `created` — UNIX timestamp of signature creation (Integer).
  created : Int64?
  /// `expires` — UNIX timestamp after which the signature is invalid.
  expires : Int64?
  /// `keyid` — identifier for the key material (String).
  keyid : String?
  /// `alg` — the signature algorithm name (String).
  alg : String?
  /// `nonce` — a unique value for replay protection (String).
  nonce : String?
  /// `tag` — an application-specific tag (String).
  tag : String?
  /// Unknown/extension parameters, preserved in order.
  extensions : Array[SfParameter]
}

///|
/// An empty parameter set.
pub fn SignatureParameters::new() -> SignatureParameters {
  {
    created: None,
    expires: None,
    keyid: None,
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
}

///|
/// Parses a parameter list into `SignatureParameters`.
///
/// Unknown parameters are stored in `extensions` (in order). Duplicate
/// defined parameters are rejected. `created`/`expires` must be integers;
/// `keyid`/`alg`/`nonce`/`tag` must be strings.
pub fn parse_signature_parameters(
  params : Array[SfParameter],
) -> Result[SignatureParameters, HsError] {
  Ok(parse_signature_parameters_raise(params)) catch {
    e => Err(e)
  }
}

///|
/// Internal: parses signature parameters, raising on violation.
fn parse_signature_parameters_raise(
  params : Array[SfParameter],
) -> SignatureParameters raise HsError {
  let mut created : Int64? = None
  let mut expires : Int64? = None
  let mut keyid : String? = None
  let mut alg : String? = None
  let mut nonce : String? = None
  let mut tag : String? = None
  let extensions : Array[SfParameter] = Array::new()
  for p in params {
    match p.name {
      "created" =>
        match p.value {
          SfInteger(v) =>
            if created is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate created parameter",
              )
            } else {
              created = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "created must be an integer",
            )
        }
      "expires" =>
        match p.value {
          SfInteger(v) =>
            if expires is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate expires parameter",
              )
            } else {
              expires = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "expires must be an integer",
            )
        }
      "keyid" =>
        match p.value {
          SfString(v) =>
            if keyid is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate keyid parameter",
              )
            } else {
              keyid = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "keyid must be a string",
            )
        }
      "alg" =>
        match p.value {
          SfString(v) =>
            if alg is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate alg parameter",
              )
            } else {
              alg = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "alg must be a string",
            )
        }
      "nonce" =>
        match p.value {
          SfString(v) =>
            if nonce is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate nonce parameter",
              )
            } else {
              nonce = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "nonce must be a string",
            )
        }
      "tag" =>
        match p.value {
          SfString(v) =>
            if tag is Some(_) {
              raise hs_error(
                SignatureInputParsing,
                InvalidSignatureInput,
                "duplicate tag parameter",
              )
            } else {
              tag = Some(v)
            }
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidSignatureInput,
              "tag must be a string",
            )
        }
      _ => extensions.push({ name: p.name, value: p.value })
    }
  }
  { created, expires, keyid, alg, nonce, tag, extensions }
}

///|
/// Serializes signature parameters canonically in the order
/// `created`, `expires`, `keyid`, `nonce`, `alg`, `tag`, then extensions.
/// This order reproduces every RFC 9421 Appendix B example byte-for-byte.
pub fn serialize_signature_parameters(
  params : SignatureParameters,
) -> Result[String, HsError] {
  Ok(serialize_signature_parameters_raise(params)) catch {
    e => Err(e)
  }
}

///|
/// Internal: canonical serialization, raising on failure.
fn serialize_signature_parameters_raise(
  params : SignatureParameters,
) -> String raise HsError {
  let out = Buffer::Buffer()
  if params.created is Some(v) {
    out.write_string_utf8(";created=" + v.to_string())
  }
  if params.expires is Some(v) {
    out.write_string_utf8(";expires=" + v.to_string())
  }
  if params.keyid is Some(v) {
    out.write_string_utf8(";keyid=" + serialize_sf_string_raise(v))
  }
  if params.nonce is Some(v) {
    out.write_string_utf8(";nonce=" + serialize_sf_string_raise(v))
  }
  if params.alg is Some(v) {
    out.write_string_utf8(";alg=" + serialize_sf_string_raise(v))
  }
  if params.tag is Some(v) {
    out.write_string_utf8(";tag=" + serialize_sf_string_raise(v))
  }
  for p in params.extensions {
    out.write_char_utf8(';')
    out.write_string_utf8(p.name)
    out.write_char_utf8('=')
    out.write_string_utf8(serialize_sf_bare_item_raise(p.value))
  }
  buffer_to_string(out)
}
