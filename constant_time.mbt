// constant_time.mbt — Constant-time byte comparison for MACs.
//
// MACs must never be compared with `==`: a byte-by-byte comparison that
// short-circuits leaks, through timing, how many leading bytes matched, which
// is enough to forge a signature incrementally. `constant_time_equal` always
// scans the full length of both inputs and never short-circuits.

///|
/// Compares two byte buffers in constant time.
///
/// The comparison always iterates over the maximum length of the two inputs
/// (padding mismatched positions with the `0xFF` marker so no branch reveals
/// which byte differed). Length differences are folded into the accumulator,
/// so the timing depends only on the longest input, never on the content.
pub fn constant_time_equal(a : Bytes, b : Bytes) -> Bool {
  let len_a = a.length()
  let len_b = b.length()
  let max_len = if len_a > len_b { len_a } else { len_b }
  let mut diff : Int = 0
  for i = 0; i < max_len; i = i + 1 {
    let ba = if i < len_a { a[i].to_int() } else { 0xFF }
    let bb = if i < len_b { b[i].to_int() } else { 0xFF }
    diff = diff | (ba ^ bb)
  }
  diff == 0
}
