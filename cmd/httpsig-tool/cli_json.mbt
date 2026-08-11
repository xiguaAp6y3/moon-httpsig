// cli_json.mbt — Stable JSON output for the httpsig-tool.
//
// Successful output is `{"ok": true, ...}`; failures are
// `{"ok": false, "error": {"stage", "kind", "offset", "context"}}`.
// Secrets never appear in output or logs.

///|
/// Builds a JSON object from pairs.
fn json_object(pairs : Array[(String, Json)]) -> Json {
  Json::object(Map::Map(pairs))
}

///|
/// Builds a success JSON object with extra fields.
fn ok_json(extra : Array[(String, Json)]) -> String {
  let all : Array[(String, Json)] = Array::new()
  all.push(("ok", Json::boolean(true)))
  for _, pair in extra {
    all.push(pair)
  }
  json_object(all).stringify()
}

///|
/// Converts an HsError into its JSON representation.
fn error_object(e : @hsig.HsError) -> Json {
  json_object([
    ("stage", Json::string(e.stage_name())),
    ("kind", Json::string(e.kind_name())),
    (
      "offset",
      Json::number(e.offset().to_double(), repr=e.offset().to_string()),
    ),
    ("context", Json::string(e.context())),
  ])
}

///|
/// Builds an error JSON object from an HsError.
fn error_json(e : @hsig.HsError) -> String {
  json_object([("ok", Json::boolean(false)), ("error", error_object(e))]).stringify()
}

///|
/// Converts a covered component to a JSON string.
fn component_json(cc : @hsig.CoveredComponent) -> Json {
  Json::string(cc.identifier())
}

///|
/// Converts a component list to JSON.
fn components_json(components : Array[@hsig.CoveredComponent]) -> Json {
  let arr : Array[Json] = Array::new()
  for c in components {
    arr.push(component_json(c))
  }
  Json::array(arr)
}
