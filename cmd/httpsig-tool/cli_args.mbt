// cli_args.mbt — Command-line argument handling for httpsig-tool.
//
// Arguments are `--name value` pairs. Unknown flags are ignored. No external
// input is unwrapped; every lookup is safe.

///|
/// Parses `--name value` pairs from an argument list into a map.
///
/// Repeating a flag (e.g. `--component a --component b`) stores the values
/// under `name0`, `name1`, ... so that ordered lists survive.
fn parse_flags(args : Array[String]) -> Map[String, String] {
  let m : Map[String, String] = Map::Map([])
  let counts : Map[String, Int] = Map::Map([])
  let mut i = 0
  while i < args.length() {
    let a = args[i]
    if a.length() > 2 && a[:2] == "--" {
      let name = a[2:].to_owned()
      if i + 1 < args.length() {
        let count = match counts.get(name) {
          Some(c) => c
          None => 0
        }
        let key = if count == 0 { name } else { name + count.to_string() }
        m.set(key, args[i + 1])
        counts.set(name, count + 1)
        i = i + 2
      } else {
        m.set(name, "")
        i = i + 1
      }
    } else {
      i = i + 1
    }
  }
  m
}

///|
/// Looks up a flag value, returning the default when absent.
fn get_flag(m : Map[String, String], name : String, default : String) -> String {
  match m.get(name) {
    Some(v) => v
    None => default
  }
}

///|
/// Looks up an optional flag value.
fn get_flag_opt(m : Map[String, String], name : String) -> String? {
  m.get(name)
}

///|
/// Parses an Int64 flag, returning `None` on invalid input.
fn get_flag_i64(m : Map[String, String], name : String) -> Int64? {
  match m.get(name) {
    Some(v) => @hsig.parse_int64_cli(v)
    None => None
  }
}

///|
/// Returns the argument list excluding the program name.
fn arg_tail(args : Array[String]) -> Array[String] {
  let out : Array[String] = Array::new()
  for i = 1; i < args.length(); i = i + 1 {
    out.push(args[i])
  }
  out
}
