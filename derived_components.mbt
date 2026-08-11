// derived_components.mbt — Resolution of derived components (RFC 9421 §2.2).
//
// Derived components are computed from the message (request or response)
// rather than read from header fields. All values are emitted verbatim:
// percent-encoding, query order, repeated parameters, and empty parameters
// are preserved exactly as they appear.

///|
/// The message being signed.
pub(all) enum SignTarget {
  /// A request message.
  TargetRequest(RequestContext)
  /// A response message (may carry a related request for `req`).
  TargetResponse(ResponseContext)
}

///|
/// Resolves any covered component (derived or field) to its canonical value.
pub fn resolve_component(
  component : CoveredComponent,
  target : SignTarget,
) -> Result[String, HsError] {
  match component {
    Derived(d, params) => resolve_derived_component(d, target, params.req)
    Field(f) => resolve_field_component(f, target)
  }
}

///|
/// Resolves a derived component to its canonical string value.
///
/// `use_req` indicates the `req` parameter: when the target is a response,
/// the component is resolved against the related request instead.
pub fn resolve_derived_component(
  component : DerivedComponent,
  target : SignTarget,
  use_req : Bool,
) -> Result[String, HsError] {
  Ok(resolve_derived_component_raise(component, target, use_req)) catch {
    e => Err(e)
  }
}

///|
/// Internal: resolves a derived component, raising on failure.
fn resolve_derived_component_raise(
  component : DerivedComponent,
  target : SignTarget,
  use_req : Bool,
) -> String raise HsError {
  match component {
    SignatureParams =>
      raise hs_error(
        ComponentResolution,
        InvalidComponentCombination,
        "@signature-params cannot be resolved as a covered component value",
      )
    Method => effective_request(target, use_req).method
    TargetUri => effective_request(target, use_req).target_uri()
    Authority => effective_request(target, use_req).authority_component()
    Scheme => effective_request(target, use_req).scheme
    RequestTarget => effective_request(target, use_req).request_target()
    Path => effective_request(target, use_req).path_component()
    Query => effective_request(target, use_req).query_component()
    QueryParam(name) =>
      resolve_query_param(effective_request(target, use_req).raw_query(), name)
    Status => resolve_status(target)
  }
}

///|
/// Returns the effective request for resolution: the target when it is a
/// request, or the related request when `use_req` is set on a response.
fn effective_request(
  target : SignTarget,
  use_req : Bool,
) -> RequestContext raise HsError {
  match target {
    TargetRequest(req) => req
    TargetResponse(resp) =>
      if use_req {
        match resp.related_request {
          Some(req) => req
          None =>
            raise hs_error(
              ComponentResolution,
              MissingComponent,
              "req component requested but no related request present",
            )
        }
      } else {
        raise hs_error(
          ComponentResolution,
          InvalidComponentCombination,
          "request-derived component used on a response without req",
        )
      }
  }
}

///|
/// Returns the response status code as a decimal string.
fn resolve_status(target : SignTarget) -> String raise HsError {
  match target {
    TargetResponse(resp) => resp.status.to_string()
    TargetRequest(_) =>
      raise hs_error(
        ComponentResolution,
        InvalidComponentCombination,
        "@status is only valid on a response",
      )
  }
}

///|
/// Resolves `@query-param;name="name"` to the percent-encoded value of the
/// named query parameter.
///
/// The query is split on `&`; each part is split on the first `=`. Both the
/// parameter name in the component identifier and the query parameter names
/// are compared in their raw (percent-encoded) form, so no decoding is
/// applied and order/repetition semantics are preserved.
fn resolve_query_param(query : String, name : String) -> String raise HsError {
  let parts = query.split("&")
  for part in parts {
    let s = part.to_owned()
    let (pname, pvalue) = match s.split_once("=") {
      Some((n, v)) => (n.to_owned(), v.to_owned())
      None => (s, "")
    }
    if pname == name {
      return pvalue
    }
  }
  raise hs_error(
    ComponentResolution,
    MissingComponent,
    "query parameter not found: " + name,
  )
}
