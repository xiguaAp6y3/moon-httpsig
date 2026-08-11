// main.mbt — httpsig-tool command-line entry point.
//
// Subcommands: parse-input, parse-signature, parse-accept, build-base,
// sign-hmac, verify-hmac, inspect, check-policy, rfc-example, plus --help and
// --version. Every command emits stable JSON and never unwraps external input.

///|
/// Builds a request from CLI flags for build-base / sign-hmac / verify-hmac.
fn request_from_flags(
  m : Map[String, String],
) -> Result[@hsig.RequestContext, @hsig.HsError] {
  let method = get_flag(m, "method", "GET")
  let scheme = get_flag(m, "scheme", "https")
  let authority = get_flag(m, "authority", "example.com")
  let path = get_flag(m, "path", "/")
  let query : String? = match get_flag_opt(m, "query") {
    Some(q) => Some(q)
    None => None
  }
  let headers = @hsig.OrderedHeaders::new()
  let first_header = match m.get("header") {
    Some(line) => line
    None => ""
  }
  if !first_header.is_empty() {
    append_header_line(headers, first_header)
  }
  let mut i = 1
  while true {
    let key = "header" + i.to_string()
    match m.get(key) {
      Some(line) => {
        append_header_line(headers, line)
        i = i + 1
      }
      None => break
    }
  }
  @hsig.RequestContext::new_default(
    method,
    scheme,
    authority,
    path,
    query,
    headers,
    None,
  )
}

///|
/// Appends a `name=value` header line to the header set.
fn append_header_line(headers : @hsig.OrderedHeaders, line : String) -> Unit {
  match line.split_once("=") {
    Some((name, value)) => {
      let _ = headers.append(name.to_owned(), value.to_owned())
    }
    None => {
      let _ = headers.append(line, "")
    }
  }
}

///|
/// Builds the signature parameters for sign-hmac.
fn params_from_flags(m : Map[String, String]) -> @hsig.SignatureParameters {
  let created = get_flag_i64(m, "created")
  let expires = get_flag_i64(m, "expires")
  let keyid = get_flag_opt(m, "keyid")
  let nonce = get_flag_opt(m, "nonce")
  let tag = get_flag_opt(m, "tag")
  {
    created,
    expires,
    keyid,
    alg: Some("hmac-sha256"),
    nonce,
    tag,
    extensions: Array::new(),
  }
}

///|
/// Reads a hex secret from a flag and returns the key record.
fn key_from_flags(
  m : Map[String, String],
  keyid : String,
) -> Result[@hsig.KeyRecord, @hsig.HsError] {
  let secret_hex = get_flag(m, "secret-hex", "")
  match @hsig.hex_decode_bytes(secret_hex) {
    Ok(bytes) =>
      Ok({ keyid, algorithm: "hmac-sha256", material: SharedSecret(bytes) })
    Err(e) => Err(e)
  }
}

///|
/// Maps a component name to a CoveredComponent.
fn component_from_string(name : String) -> @hsig.CoveredComponent {
  match name {
    "@method" => @hsig.covered_derived(@hsig.DerivedComponent::Method)
    "@target-uri" => @hsig.covered_derived(@hsig.DerivedComponent::TargetUri)
    "@authority" => @hsig.covered_derived(@hsig.DerivedComponent::Authority)
    "@scheme" => @hsig.covered_derived(@hsig.DerivedComponent::Scheme)
    "@path" => @hsig.covered_derived(@hsig.DerivedComponent::Path)
    "@query" => @hsig.covered_derived(@hsig.DerivedComponent::Query)
    "@request-target" =>
      @hsig.covered_derived(@hsig.DerivedComponent::RequestTarget)
    _ => @hsig.covered_field(name)
  }
}

///|
/// Parses the `--component` flags into covered components.
fn parse_components_flag(
  m : Map[String, String],
) -> Array[@hsig.CoveredComponent] {
  let components : Array[@hsig.CoveredComponent] = Array::new()
  let first = match m.get("component") {
    Some(name) => name
    None => ""
  }
  if !first.is_empty() {
    components.push(component_from_string(first))
  }
  let mut i = 1
  while true {
    match m.get("component" + i.to_string()) {
      Some(name) => {
        components.push(component_from_string(name))
        i = i + 1
      }
      None => break
    }
  }
  if components.is_empty() {
    components.push(@hsig.covered_derived(@hsig.DerivedComponent::Method))
  }
  components
}

///|
/// Command: parse Signature-Input.
fn cmd_parse_input(m : Map[String, String]) -> String {
  let input = get_flag(m, "signature-input", "")
  match @hsig.parse_signature_input(input, @hsig.Limits::default()) {
    Ok(parsed) => {
      let labels : Array[Json] = Array::new()
      for entry in parsed.entries {
        labels.push(Json::string(entry.label))
      }
      ok_json([("labels", Json::array(labels))])
    }
    Err(e) => error_json(e)
  }
}

///|
/// Command: parse Signature.
fn cmd_parse_signature(m : Map[String, String]) -> String {
  let input = get_flag(m, "signature", "")
  match @hsig.parse_signature_field(input, @hsig.Limits::default()) {
    Ok(parsed) => {
      let labels : Array[Json] = Array::new()
      for entry in parsed.entries {
        labels.push(Json::string(entry.label))
      }
      ok_json([("labels", Json::array(labels))])
    }
    Err(e) => error_json(e)
  }
}

///|
/// Command: parse Accept-Signature.
fn cmd_parse_accept(m : Map[String, String]) -> String {
  let input = get_flag(m, "accept-signature", "")
  match @hsig.parse_accept_signature(input, @hsig.Limits::default()) {
    Ok(parsed) => {
      let labels : Array[Json] = Array::new()
      for entry in parsed.entries {
        labels.push(Json::string(entry.label))
      }
      ok_json([("labels", Json::array(labels))])
    }
    Err(e) => error_json(e)
  }
}

///|
/// Command: build a signature base.
fn cmd_build_base(m : Map[String, String]) -> String {
  match request_from_flags(m) {
    Err(e) => error_json(e)
    Ok(req) => {
      let input_str = get_flag(m, "signature-input", "")
      match @hsig.parse_signature_input(input_str, @hsig.Limits::default()) {
        Err(e) => error_json(e)
        Ok(parsed) =>
          if parsed.entries.is_empty() {
            error_json(
              @hsig.hs_error(
                @hsig.HsErrorStage::SignatureInputParsing,
                @hsig.HsErrorKind::MissingSignatureInput,
                "no signature entry",
              ),
            )
          } else {
            let entry = parsed.entries[0]
            match
              @hsig.build_request_signature_base(
                req,
                entry,
                @hsig.Limits::default(),
              ) {
              Err(e) => error_json(e)
              Ok(base) =>
                ok_json([
                  ("label", Json::string(entry.label)),
                  ("base", Json::string(base.text)),
                  (
                    "base_sha256",
                    Json::string(
                      @hsig.hex_encode_bytes(@hsig.sha256_raw(base.bytes)),
                    ),
                  ),
                ])
            }
          }
      }
    }
  }
}

///|
/// Command: sign an HMAC-SHA256 request.
fn cmd_sign_hmac(m : Map[String, String]) -> String {
  let label = get_flag(m, "label", "sig1")
  let keyid = get_flag(m, "keyid", "test-key")
  match key_from_flags(m, keyid) {
    Err(e) => error_json(e)
    Ok(key) =>
      match request_from_flags(m) {
        Err(e) => error_json(e)
        Ok(req) => {
          let components = parse_components_flag(m)
          let params = params_from_flags(m)
          let options : @hsig.SignOptions = {
            label,
            components,
            parameters: params,
            algorithm: "hmac-sha256",
            key,
          }
          match @hsig.sign_request(req, options, @hsig.Limits::default()) {
            Err(e) => error_json(e)
            Ok(signed) =>
              ok_json([
                ("label", Json::string(label)),
                ("algorithm", Json::string("hmac-sha256")),
                ("keyid", Json::string(keyid)),
                ("signature_input", Json::string(signed.signature_input)),
                ("signature", Json::string(signed.signature)),
              ])
          }
        }
      }
  }
}

///|
/// Command: verify an HMAC-SHA256 request.
fn cmd_verify_hmac(m : Map[String, String]) -> String {
  let keyid = get_flag(m, "keyid", "test-key")
  let now = get_flag_i64(m, "now").unwrap_or(0L)
  match key_from_flags(m, keyid) {
    Err(e) => error_json(e)
    Ok(key) =>
      match request_from_flags(m) {
        Err(e) => error_json(e)
        Ok(req) => {
          let input_str = get_flag(m, "signature-input", "")
          let sig_str = get_flag(m, "signature", "")
          let resolver = @hsig.InMemoryKeyResolver::new()
          let _ = resolver.add(key, @hsig.Limits::default())
          let clock = @hsig.FixedClock::new(now)
          let nonces = @hsig.InMemoryNonceStore::new()
          match
            @hsig.verify_request(
              req,
              input_str,
              sig_str,
              resolver,
              @hsig.VerificationPolicy::hmac_only(),
              clock,
              nonces,
              @hsig.Limits::default(),
              @hsig.MultiSignaturePolicy::AnyValid,
            ) {
            Err(e) => error_json(e)
            Ok(report) => {
              let labels : Array[Json] = Array::new()
              for v in report.verified {
                labels.push(Json::string(v.label))
              }
              ok_json([
                ("verified", Json::array(labels)),
                (
                  "rejected_count",
                  Json::number(
                    report.rejected.length().to_double(),
                    repr=report.rejected.length().to_string(),
                  ),
                ),
              ])
            }
          }
        }
      }
  }
}

///|
/// Command: inspect (parse only, no verification).
fn cmd_inspect(m : Map[String, String]) -> String {
  let input_str = get_flag(m, "signature-input", "")
  match @hsig.parse_signature_input(input_str, @hsig.Limits::default()) {
    Err(e) => error_json(e)
    Ok(parsed) => {
      let entries : Array[Json] = Array::new()
      for entry in parsed.entries {
        entries.push(
          json_object([
            ("label", Json::string(entry.label)),
            ("covered_components", components_json(entry.covered_components)),
          ]),
        )
      }
      ok_json([("signatures", Json::array(entries))])
    }
  }
}

///|
/// Command: check-policy (parse + policy checks without key resolution).
fn cmd_check_policy(m : Map[String, String]) -> String {
  let input_str = get_flag(m, "signature-input", "")
  match @hsig.parse_signature_input(input_str, @hsig.Limits::default()) {
    Err(e) => error_json(e)
    Ok(parsed) => {
      let mut valid = true
      for entry in parsed.entries {
        let p = entry.parameters
        if p.created is Some(c) && p.expires is Some(e) {
          if e < c {
            valid = false
          }
        }
        if p.keyid is None {
          valid = false
        }
        match get_flag_opt(m, "required-component") {
          Some(rc) => {
            let wanted = component_from_string(rc)
            if !@hsig.components_cover(entry.covered_components, wanted) {
              valid = false
            }
          }
          None => ()
        }
      }
      ok_json([("valid", Json::boolean(valid))])
    }
  }
}

///|
/// Command: run the RFC 9421 B.2.5 HMAC example.
fn cmd_rfc_example() -> String {
  match
    @hsig.base64_decode_bytes(
      "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==",
    ) {
    Err(e) => error_json(e)
    Ok(secret_bytes) => {
      let base = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n\"content-type\": application/json\n\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\""
      let mac = @hsig.hmac_sha256(secret_bytes, @utf8.encode(base))
      let expected = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="
      let actual = @hsig.base64_encode_bytes(mac)
      ok_json([
        ("example", Json::string("rfc-9421-b.2.5")),
        ("algorithm", Json::string("hmac-sha256")),
        ("mac", Json::string(actual)),
        ("expected", Json::string(expected)),
        ("match", Json::boolean(actual == expected)),
      ])
    }
  }
}

///|
/// Prints usage text.
fn cmd_help() -> String {
  ok_json([
    (
      "help",
      Json::string("httpsig-tool — RFC 9421 HTTP Message Signatures CLI"),
    ),
    (
      "commands",
      Json::string(
        "parse-input, parse-signature, parse-accept, build-base, sign-hmac, verify-hmac, inspect, check-policy, rfc-example",
      ),
    ),
  ])
}

///|
/// The command dispatch table.
fn dispatch(args : Array[String]) -> String {
  if args.is_empty() {
    return cmd_help()
  }
  let first = args[0]
  match first {
    "--help" | "help" => cmd_help()
    "--version" | "version" =>
      ok_json([
        ("version", Json::string(@hsig.library_version())),
        ("name", Json::string("httpsig-tool")),
      ])
    "parse-input" => cmd_parse_input(parse_flags(arg_tail(args)))
    "parse-signature" => cmd_parse_signature(parse_flags(arg_tail(args)))
    "parse-accept" => cmd_parse_accept(parse_flags(arg_tail(args)))
    "build-base" => cmd_build_base(parse_flags(arg_tail(args)))
    "sign-hmac" => cmd_sign_hmac(parse_flags(arg_tail(args)))
    "verify-hmac" => cmd_verify_hmac(parse_flags(arg_tail(args)))
    "inspect" => cmd_inspect(parse_flags(arg_tail(args)))
    "check-policy" => cmd_check_policy(parse_flags(arg_tail(args)))
    "rfc-example" => cmd_rfc_example()
    _ =>
      error_json(
        @hsig.hs_error(
          @hsig.HsErrorStage::StructuredFieldParsing,
          @hsig.HsErrorKind::InvalidStructuredField,
          "unknown command: " + first,
        ),
      )
  }
}

///|
fn main {
  let args = @env.args()
  println(dispatch(arg_tail(args)))
}
