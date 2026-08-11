// test_generator.mbt — Deterministic test-case generator.
//
// A small LCG with a fixed seed produces the same sequence on every run and
// on every target, which is what makes the property tests reproducible.
// The generator produces realistic HTTP messages and signing inputs.

///|
/// A deterministic pseudo-random generator (LCG).
pub struct Prng {
  mut state : Int64
}

///|
/// Constructs a generator from a seed.
pub fn Prng::new(seed : Int64) -> Prng {
  { state: seed }
}

///|
/// Advances the generator and returns a 32-bit pseudo-random value.
pub fn Prng::next_u32(self : Prng) -> Int {
  self.state = self.state * 6364136223846793005L + 1442695040888963407L
  let v = (self.state >> 33) & 0x7FFFFFFF
  v.to_int()
}

///|
/// Returns a value in `0..bound`.
pub fn Prng::next_int(self : Prng, bound : Int) -> Int {
  if bound <= 0 {
    return 0
  }
  self.next_u32() % bound
}

///|
/// Returns a random boolean.
pub fn Prng::next_bool(self : Prng) -> Bool {
  self.next_u32() % 2 == 0
}

///|
/// Picks a random element from a list.
pub fn Prng::pick(self : Prng, choices : Array[String]) -> String {
  let i = self.next_int(choices.length())
  choices[i]
}

///|
/// Picks one of several covered-component templates.
pub fn Prng::pick_components(self : Prng) -> Array[CoveredComponent] {
  let choice = self.next_int(4)
  match choice {
    0 => [covered_derived(Method), covered_field("content-type")]
    1 =>
      [covered_derived(Method), covered_derived(Path), covered_field("x-tag")]
    2 => [covered_field("content-type"), covered_derived(Query)]
    3 =>
      [
        covered_derived(Method),
        covered_derived(Path),
        covered_field("content-type"),
        covered_field("x-tag"),
      ]
    _ => [covered_derived(Method)]
  }
}

///|
/// Generates a request message for a property-test case.
pub fn Prng::generate_request(self : Prng, case : Int) -> RequestContext {
  let methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
  let paths = ["/", "/a", "/foo/bar", "/a%2Fb", "/path with space"]
  let queries : Array[String?] = [
    None,
    Some(""),
    Some("a=1"),
    Some("a=1&b=2"),
    Some("pet=dog"),
    Some("x=%20"),
  ]
  let method = self.pick(methods)
  let path = self.pick(paths)
  let query = queries[self.next_int(queries.length())]
  let headers = OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let _ = headers.append("x-tag", "case-" + case.to_string())
  let _ = headers.append(
    "x-extra",
    "not-covered-" + self.next_int(100).to_string(),
  )
  let body : Bytes? = if self.next_bool() {
    Some(@utf8.encode("body-" + case.to_string()))
  } else {
    None
  }
  match
    RequestContext::new_default(
      method, "https", "example.com", path, query, headers, body,
    ) {
    Ok(r) => r
    Err(_) =>
      abort("property request construction failed at case " + case.to_string())
  }
}

///|
/// Generates signing options for a property-test case.
pub fn Prng::generate_sign_options(
  _self : Prng,
  case : Int,
  components : Array[CoveredComponent],
) -> SignOptions {
  let keyid = "key-" + (case % 4).to_string()
  let secret = "secret-" + case.to_string()
  let key = make_test_key(keyid, secret)
  let created = 1700000000L + Int64::from_int(case)
  let params : SignatureParameters = {
    created: Some(created),
    expires: None,
    keyid: Some(keyid),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array::new(),
  }
  {
    label: "sig-prop",
    components,
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
}
