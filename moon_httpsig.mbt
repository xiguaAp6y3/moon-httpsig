// moon_httpsig.mbt — Module entry point.
//
// moon-httpsig is a from-scratch, local-only implementation of RFC 9421
// (HTTP Message Signatures) for MoonBit. It provides the HTTP message model,
// the structured-field subset, covered-component resolution, exact signature
// base construction, an HMAC-SHA256 algorithm provider, verification policy,
// replay protection, and Content-Digest binding.
//
// The library is deliberately not a JWT library, HTTP server/client, TLS
// implementation, or general cryptography library. It never fetches keys
// over the network, never resolves keyid URLs, and never produces a fake
// success for an unimplemented algorithm.

///|
/// The library version, mirrored in `moon.mod`.
pub fn library_version() -> String {
  "0.1.0-dev"
}

///|
/// Parses a decimal string into an Int64, returning `None` on invalid input.
/// Used by the CLI so that external input never panics.
pub fn parse_int64_cli(s : String) -> Int64? {
  Some(@string.parse_int64(s)) catch {
    _ => None
  }
}
