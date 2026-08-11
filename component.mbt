// component.mbt — Covered component identifiers (RFC 9421 §4.1).
//
// A "covered component" names a piece of the HTTP message that is signed.
// Components are either derived (computed from the message, prefixed with
// `@`) or field components (named after an HTTP header/trailer). The set of
// covered components, in order, plus the signature parameters, form the
// signature base.

///|
/// A derived component computed from the message. `QueryParam` carries the
/// parameter name from its `name` parameter.
pub(all) enum DerivedComponent {
  /// `@signature-params` — the parameters of this signature itself.
  SignatureParams
  /// `@method` — the HTTP request method.
  Method
  /// `@target-uri` — scheme://authority/path?query (verbatim).
  TargetUri
  /// `@authority` — the authority portion verbatim.
  Authority
  /// `@scheme` — the URI scheme.
  Scheme
  /// `@request-target` — method SP request-target.
  RequestTarget
  /// `@path` — the path component verbatim.
  Path
  /// `@query` — the query component verbatim.
  Query
  /// `@query-param` — one query parameter by name.
  QueryParam(String)
  /// `@status` — the response status code (responses only).
  Status
}

///|
/// A field component: an HTTP header/trailer name plus its parameters.
pub(all) struct FieldComponent {
  name : String
  parameters : ComponentParameters
}

///|
/// Component parameters attached to a covered component.
pub(all) struct ComponentParameters {
  /// `sf` — the field value is a structured field value (RFC 9651).
  sf : Bool
  /// `key` — dictionary member key (only with `sf` on a dictionary field).
  key : String?
  /// `bs` — the field value is a base64-encoded byte sequence.
  bs : Bool
  /// `tr` — the component is taken from the trailer section.
  tr : Bool
  /// `req` — the component refers to the related request (responses only).
  req : Bool
  /// `name` — parameter name for `@query-param`.
  name : String?
}

///|
/// A covered component: derived or field.
///
/// Derived components carry their parameters so that `req` (and `name` for
/// `@query-param`) survives parsing and is emitted in the signature base
/// (RFC 9421 §2.4).
pub(all) enum CoveredComponent {
  Derived(DerivedComponent, ComponentParameters)
  Field(FieldComponent)
}

///|
/// The default component parameters (all unset).
pub fn ComponentParameters::default() -> ComponentParameters {
  { sf: false, key: None, bs: false, tr: false, req: false, name: None }
}

///|
/// Constructs a derived covered component with default parameters.
pub fn covered_derived(d : DerivedComponent) -> CoveredComponent {
  Derived(d, ComponentParameters::default())
}

///|
/// Constructs a derived covered component with explicit parameters.
pub fn covered_derived_with_params(
  d : DerivedComponent,
  parameters : ComponentParameters,
) -> CoveredComponent {
  Derived(d, parameters)
}

///|
/// Constructs a field covered component with default parameters.
pub fn covered_field(name : String) -> CoveredComponent {
  Field({ name, parameters: ComponentParameters::default() })
}

///|
/// Constructs a field covered component with explicit parameters.
pub fn covered_field_with_params(
  name : String,
  parameters : ComponentParameters,
) -> CoveredComponent {
  Field({ name, parameters })
}

///|
/// Returns the canonical component identifier string used in the signature
/// base (RFC 9421 §2.5). Every component name is serialized as an sf-string,
/// so the identifier is double-quoted; parameters follow the quotes.
/// Examples: `"@method"`, `"content-type";sf`, `"@query-param";name="foo"`.
pub fn CoveredComponent::to_component_string(
  self : CoveredComponent,
) -> Result[String, HsError] {
  Ok(covered_component_string_raise(self)) catch {
    e => Err(e)
  }
}

///|
/// Returns the bare (unquoted) identifier used for internal matching, e.g.
/// `@method`, `content-type`, `@query-param`.
pub fn CoveredComponent::identifier(self : CoveredComponent) -> String {
  match self {
    Derived(d, _) => derived_component_name(d)
    Field(f) => f.name
  }
}

///|
/// Returns the canonical quoted string for a derived component including its
/// parameters (`;req` and `;name` for `@query-param`).
fn derived_component_string(
  d : DerivedComponent,
  parameters : ComponentParameters,
) -> String raise HsError {
  let base = match d {
    SignatureParams => "\"@signature-params\""
    Method => "\"@method\""
    TargetUri => "\"@target-uri\""
    Authority => "\"@authority\""
    Scheme => "\"@scheme\""
    RequestTarget => "\"@request-target\""
    Path => "\"@path\""
    Query => "\"@query\""
    QueryParam(name) =>
      "\"@query-param\";name=" + serialize_sf_string_raise(name)
    Status => "\"@status\""
  }
  let mut out = base
  if parameters.req {
    out = out + ";req"
  }
  out
}

///|
/// Returns the bare derived component name (unquoted).
fn derived_component_name(d : DerivedComponent) -> String {
  match d {
    SignatureParams => "@signature-params"
    Method => "@method"
    TargetUri => "@target-uri"
    Authority => "@authority"
    Scheme => "@scheme"
    RequestTarget => "@request-target"
    Path => "@path"
    Query => "@query"
    QueryParam(_) => "@query-param"
    Status => "@status"
  }
}

///|
/// Internal: canonical component string, raising on failure.
fn covered_component_string_raise(
  component : CoveredComponent,
) -> String raise HsError {
  match component {
    Derived(d, params) => derived_component_string(d, params)
    Field(f) =>
      "\"" + f.name + "\"" + serialize_component_parameters_raise(f.parameters)
  }
}

///|
/// Returns the parameters of the component if it is a field component.
pub fn CoveredComponent::field_parameters(
  self : CoveredComponent,
) -> ComponentParameters? {
  match self {
    Field(f) => Some(f.parameters)
    Derived(_, _) => None
  }
}

///|
/// Returns the query-param name if this is `@query-param`, else `None`.
pub fn CoveredComponent::query_param_name(self : CoveredComponent) -> String? {
  match self {
    Derived(QueryParam(name), _) => Some(name)
    _ => None
  }
}

///|
/// Returns the derived component if this is a derived component.
pub fn CoveredComponent::as_derived(
  self : CoveredComponent,
) -> DerivedComponent? {
  match self {
    Derived(d, _) => Some(d)
    Field(_) => None
  }
}

///|
/// Returns the field component if this is a field component.
pub fn CoveredComponent::as_field(self : CoveredComponent) -> FieldComponent? {
  match self {
    Field(f) => Some(f)
    Derived(_, _) => None
  }
}
