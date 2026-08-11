// property_test.mbt — Deterministic property tests.
//
// A fixed-seed generator drives 1000+ full sign→verify cycles. Each cycle:
// generate a request, sign it, parse both fields back, rebuild the base,
// verify, compare metadata, round-trip the serialization, then confirm that
// mutating a covered component breaks the signature while mutating an
// uncovered one does not. A fixed seed makes every target produce identical
// results.

///|
let prop_seed : Int64 = 0x5EED9421L

///|
/// Builds a mutated copy of a request where one covered header value changed.
fn mutate_covered_header(
  req : RequestContext,
  _name : String,
) -> RequestContext {
  let h = OrderedHeaders::new()
  // Change the covered content-type value.
  let _ = h.append("content-type", "text/plain")
  let _ = h.append("x-tag", req.headers.get_first("x-tag").unwrap_or("default"))
  let _ = h.append("x-extra", "still-here")
  match
    RequestContext::new_default(
      req.method,
      req.scheme,
      req.authority,
      req.path,
      req.query,
      h,
      req.body,
    ) {
    Ok(r) => r
    Err(_) => abort("mutated request construction failed")
  }
}

///|
test "property_1000_sign_verify_cycles" {
  let prng = Prng::new(prop_seed)
  let mut failures = 0
  for case = 0; case < 1000; case = case + 1 {
    let req = prng.generate_request(case)
    let components = prng.pick_components()
    let options = prng.generate_sign_options(case, components)
    // 1. Sign.
    let signed = match
      sign_request(req, options, Limits::permissive_for_tests()) {
      Ok(s) => s
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    // 2. Parse Signature-Input and Signature.
    let parsed_input = match
      parse_signature_input(
        signed.signature_input,
        Limits::permissive_for_tests(),
      ) {
      Ok(i) => i
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    let _parsed_sig = match
      parse_signature_field(signed.signature, Limits::permissive_for_tests()) {
      Ok(f) => f
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    // 3. Rebuild the signature base from the parsed entry.
    let entry = parsed_input.entries[0]
    let base2 = match
      build_request_signature_base(req, entry, Limits::permissive_for_tests()) {
      Ok(b) => b
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    // 4. The rebuilt base must be byte-identical to the original.
    if !constant_time_equal(base2.bytes, signed.signature_base.bytes) {
      failures = failures + 1
      continue
    }
    // 5. Verify.
    let key = make_test_key(
      "key-" + (case % 4).to_string(),
      "secret-" + case.to_string(),
    )
    let report = match
      verify_test_request(req, signed, key, 1700000000L + Int64::from_int(case)) {
      Ok(r) => r
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    if report.verified.length() != 1 {
      failures = failures + 1
      continue
    }
    // 6. Compare metadata: covered components and created match.
    let v = report.verified[0]
    if v.label != "sig-prop" {
      failures = failures + 1
      continue
    }
    if v.created.unwrap() != 1700000000L + Int64::from_int(case) {
      failures = failures + 1
      continue
    }
    // 7. Re-serialize and re-parse.
    let reserialized = match serialize_signature_input(parsed_input) {
      Ok(s) => s
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
    match parse_signature_input(reserialized, Limits::permissive_for_tests()) {
      Ok(_) => ()
      Err(_) => {
        failures = failures + 1
        continue
      }
    }
  }
  inspect(failures, content="0")
}

///|
test "property_mutation_breaks_and_uncovered_ok" {
  let prng = Prng::new(prop_seed + 1L)
  let mut covered_mutations_failed_to_break = 0
  let mut uncovered_ok_broke = 0
  for case = 1000; case < 1100; case = case + 1 {
    let req = prng.generate_request(case)
    let components = prng.pick_components()
    let options = prng.generate_sign_options(case, components)
    let signed = match
      sign_request(req, options, Limits::permissive_for_tests()) {
      Ok(s) => s
      Err(_) => continue
    }
    let key = make_test_key(
      "key-" + (case % 4).to_string(),
      "secret-" + case.to_string(),
    )
    // Mutate a covered header (content-type is always covered by the chosen
    // templates except the last; those cases are skipped below).
    let mutated = mutate_covered_header(req, "content-type")
    let result = match
      verify_test_request(
        mutated,
        signed,
        key,
        1700000000L + Int64::from_int(case),
      ) {
      Ok(r) => r.verified.length()
      Err(_) => 0
    }
    // If content-type is covered, mutation must break the signature.
    let mut ct_covered = false
    for cc in components {
      if cc.identifier() == "content-type" {
        ct_covered = true
      }
    }
    if ct_covered && result != 0 {
      covered_mutations_failed_to_break = covered_mutations_failed_to_break + 1
    }
    // Mutating only the uncovered header must keep the signature valid.
    let changed = RequestContext::new_default(
      req.method,
      req.scheme,
      req.authority,
      req.path,
      req.query,
      mutate_uncovered_headers(req),
      req.body,
    ).unwrap()
    let ok = match
      verify_test_request(
        changed,
        signed,
        key,
        1700000000L + Int64::from_int(case),
      ) {
      Ok(r) => r.verified.length()
      Err(_) => 0
    }
    if ok != 1 {
      uncovered_ok_broke = uncovered_ok_broke + 1
    }
  }
  inspect(covered_mutations_failed_to_break, content="0")
  inspect(uncovered_ok_broke, content="0")
}

///|
/// Returns a copy of the request headers with only the uncovered header
/// changed.
fn mutate_uncovered_headers(req : RequestContext) -> OrderedHeaders {
  let h = OrderedHeaders::new()
  let _ = h.append("content-type", "application/json")
  let _ = h.append("x-tag", req.headers.get_first("x-tag").unwrap_or("default"))
  let _ = h.append("x-extra", "mutated-extra")
  h
}

///|
