// component_params.mbt — Covered-component parameter parsing/serialization.
//
// RFC 9421 §3.1.2 defines the component parameters `sf`, `key`, `name`,
// `bs`, `req`, and `tr`. They appear both in the covered-components inner
// list (as item parameters) and in the signature base component identifier.
// This module parses a parameter list into a `ComponentParameters` and
// serializes it back canonically, enforcing RFC 9421 combination rules.
//
// Internal functions raise `HsError`; public wrappers convert to `Result`.

///|
/// Parses item parameters into `ComponentParameters`, enforcing RFC 9421
/// §3.1.2 rules:
/// - unknown parameters are rejected;
/// - `sf`/`bs`/`req`/`tr` must be booleans;
/// - `key`/`name` must be strings;
/// - `name` is only valid on `@query-param` (checked by the caller).
pub fn parse_component_parameters(
  params : Array[SfParameter],
) -> Result[ComponentParameters, HsError] {
  Ok(parse_component_parameters_raise(params)) catch {
    e => Err(e)
  }
}

///|
/// Internal: parses item parameters, raising on violation.
fn parse_component_parameters_raise(
  params : Array[SfParameter],
) -> ComponentParameters raise HsError {
  let mut sf = false
  let mut key : String? = None
  let mut bs = false
  let mut tr = false
  let mut req = false
  let mut name : String? = None
  for p in params {
    match p.name {
      "sf" =>
        match p.value {
          SfBoolean(v) => sf = v
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "sf parameter must be a boolean",
            )
        }
      "key" =>
        match p.value {
          SfString(v) => key = Some(v)
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "key parameter must be a string",
            )
        }
      "bs" =>
        match p.value {
          SfBoolean(v) => bs = v
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "bs parameter must be a boolean",
            )
        }
      "tr" =>
        match p.value {
          SfBoolean(v) => tr = v
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "tr parameter must be a boolean",
            )
        }
      "req" =>
        match p.value {
          SfBoolean(v) => req = v
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "req parameter must be a boolean",
            )
        }
      "name" =>
        match p.value {
          SfString(v) => name = Some(v)
          _ =>
            raise hs_error(
              SignatureInputParsing,
              InvalidCoveredComponent,
              "name parameter must be a string",
            )
        }
      _ =>
        raise hs_error(
          SignatureInputParsing,
          UnsupportedComponentParameter,
          "unsupported component parameter: " + p.name,
        )
    }
  }
  { sf, key, bs, tr, req, name }
}

///|
/// Serializes component parameters canonically: boolean-true parameters as
/// bare `;name`, other values as `;name=value`.
pub fn serialize_component_parameters(
  params : ComponentParameters,
) -> Result[String, HsError] {
  Ok(serialize_component_parameters_raise(params)) catch {
    e => Err(e)
  }
}

///|
/// Internal: serializes component parameters, raising on failure.
fn serialize_component_parameters_raise(
  params : ComponentParameters,
) -> String raise HsError {
  let out = Buffer::Buffer()
  if params.sf {
    out.write_string_utf8(";sf")
  }
  if params.key is Some(_) {
    out.write_string_utf8(
      ";key=" + serialize_sf_string_raise(params.key.unwrap()),
    )
  }
  if params.bs {
    out.write_string_utf8(";bs")
  }
  if params.tr {
    out.write_string_utf8(";tr")
  }
  if params.req {
    out.write_string_utf8(";req")
  }
  if params.name is Some(_) {
    out.write_string_utf8(
      ";name=" + serialize_sf_string_raise(params.name.unwrap()),
    )
  }
  buffer_to_string(out)
}

///|
/// Validates a parsed covered component against the RFC 9421 combination
/// rules that depend only on the component itself:
///
/// 1. `name` is only allowed on `@query-param`;
/// 2. `key` requires `sf` on a field component (dictionary semantics);
/// 3. `sf` and `bs` are mutually exclusive.
fn validate_component_combination(
  component : CoveredComponent,
) -> Result[Unit, HsError] {
  match component {
    Field(f) => {
      let p = f.parameters
      if p.name is Some(_) {
        return Err(
          hs_error(
            SignatureInputParsing,
            InvalidComponentCombination,
            "name parameter is only valid on @query-param",
          ),
        )
      }
      if p.key is Some(_) && !p.sf {
        return Err(
          hs_error(
            SignatureInputParsing,
            InvalidComponentCombination,
            "key parameter requires sf",
          ),
        )
      }
      if p.sf && p.bs {
        return Err(
          hs_error(
            SignatureInputParsing,
            InvalidComponentCombination,
            "sf and bs are mutually exclusive",
          ),
        )
      }
      Ok(())
    }
    Derived(QueryParam(name), _) =>
      if name.is_empty() {
        Err(
          hs_error(
            SignatureInputParsing,
            InvalidComponentCombination,
            "@query-param requires a non-empty name",
          ),
        )
      } else {
        Ok(())
      }
    Derived(_, _) => Ok(())
  }
}

///|
/// Parses a single covered component from an `SfItem`.
///
/// Per RFC 9421 §2.5 the component identifier is an sf-string; we also accept
/// an unquoted token for lenience. Identifiers starting with `@` denote
/// derived components, everything else is a field component.
pub fn parse_covered_component(
  item : SfItem,
) -> Result[CoveredComponent, HsError] {
  let token = match item.value {
    SfString(s) => s
    SfToken(t) => t
    _ =>
      return Err(
        hs_error(
          SignatureInputParsing,
          InvalidCoveredComponent,
          "covered component must be a string",
        ),
      )
  }
  let params = match parse_component_parameters(item.parameters) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  if token.has_prefix("@") {
    // Derived components: only @query-param carries parameters; all others
    // must have none.
    match token {
      "@method" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Method, params),
        )
      "@target-uri" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(TargetUri, params),
        )
      "@authority" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Authority, params),
        )
      "@scheme" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Scheme, params),
        )
      "@request-target" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(RequestTarget, params),
        )
      "@path" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Path, params),
        )
      "@query" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Query, params),
        )
      "@status" =>
        ok_derived_params(
          item,
          token,
          covered_derived_with_params(Status, params),
        )
      "@signature-params" =>
        ok_derived_params(item, token, covered_derived(SignatureParams))
      "@query-param" =>
        match params.name {
          Some(qpname) => {
            let cc = covered_derived_with_params(QueryParam(qpname), params)
            match validate_component_combination(cc) {
              Ok(_) => Ok(cc)
              Err(e) => Err(e)
            }
          }
          None =>
            Err(
              hs_error(
                SignatureInputParsing,
                InvalidComponentCombination,
                "@query-param requires a name parameter",
              ),
            )
        }
      _ =>
        Err(
          hs_error(
            SignatureInputParsing,
            UnsupportedDerivedComponent,
            "unsupported derived component: " + token,
          ),
        )
    }
  } else {
    // Field component.
    let field = { name: token, parameters: params }
    let cc = Field(field)
    match validate_component_combination(cc) {
      Ok(_) => Ok(cc)
      Err(e) => Err(e)
    }
  }
}

///|
/// Returns the given derived component if its parameters are limited to the
/// allowed `req` flag; otherwise raises `InvalidCoveredComponent`.
fn ok_derived_params(
  item : SfItem,
  token : String,
  component : CoveredComponent,
) -> Result[CoveredComponent, HsError] {
  for p in item.parameters {
    if p.name != "req" {
      return Err(
        hs_error(
          SignatureInputParsing,
          InvalidCoveredComponent,
          token + " does not support parameter: " + p.name,
        ),
      )
    }
  }
  Ok(component)
}

///|
/// Reconstructs an `SfItem` for a covered component (used when serializing a
/// Signature-Input or signature base). The item value is the sf-string of the
/// component name; component parameters are mapped back to SF parameters.
pub fn covered_component_to_sf_item(component : CoveredComponent) -> SfItem {
  match component {
    Derived(QueryParam(name), params) => {
      let parameters : Array[SfParameter] = Array::new()
      parameters.push({ name: "name", value: SfString(name) })
      if params.req {
        parameters.push({ name: "req", value: SfBoolean(true) })
      }
      { value: SfString("@query-param"), parameters }
    }
    Derived(d, params) => {
      let parameters : Array[SfParameter] = Array::new()
      if params.req {
        parameters.push({ name: "req", value: SfBoolean(true) })
      }
      { value: SfString(derived_component_name(d)), parameters }
    }
    Field(f) => {
      let p = f.parameters
      let parameters : Array[SfParameter] = Array::new()
      if p.sf {
        parameters.push({ name: "sf", value: SfBoolean(true) })
      }
      if p.key is Some(k) {
        parameters.push({ name: "key", value: SfString(k) })
      }
      if p.bs {
        parameters.push({ name: "bs", value: SfBoolean(true) })
      }
      if p.tr {
        parameters.push({ name: "tr", value: SfBoolean(true) })
      }
      if p.req {
        parameters.push({ name: "req", value: SfBoolean(true) })
      }
      if p.name is Some(n) {
        parameters.push({ name: "name", value: SfString(n) })
      }
      { value: SfString(f.name), parameters }
    }
  }
}

///|
/// Parses a covered-components inner list into an ordered array.
pub fn parse_covered_components(
  items : Array[SfItem],
  max_components : Int,
) -> Result[Array[CoveredComponent], HsError] {
  if items.length() > max_components {
    return Err(
      hs_error(
        SignatureInputParsing,
        TooManyComponents,
        "too many covered components",
      ),
    )
  }
  let out : Array[CoveredComponent] = Array::new()
  for item in items {
    match parse_covered_component(item) {
      Ok(cc) => out.push(cc)
      Err(e) => return Err(e)
    }
  }
  Ok(out)
}
