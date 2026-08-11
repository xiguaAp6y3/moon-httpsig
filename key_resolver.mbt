// key_resolver.mbt — Key resolution (RFC 9421 §3.1.1).
//
// A `keyid` in the signature parameters identifies the key material. The
// library never fetches keys over the network, never parses `file://` URLs,
// never resolves JWKS/DID pointers, and never treats a `keyid` as a trusted
// identity: it is only a lookup identifier into a caller-supplied resolver.

///|
/// A resolved key record.
pub(all) struct KeyRecord {
  /// The key identifier (must match the Signature-Input `keyid`).
  keyid : String
  /// The algorithm name the key is valid for.
  algorithm : String
  /// The key material.
  material : KeyMaterial
}

///|
/// The resolver interface: maps a `keyid` to a `KeyRecord`.
pub(open) trait KeyResolver {
  /// Resolves `keyid` to a key record, or fails with `KeyNotFound`.
  fn resolve(Self, String) -> Result[KeyRecord, HsError]
}

///|
/// An in-memory key resolver backed by an ordered list of records.
pub struct InMemoryKeyResolver {
  keys : Array[KeyRecord]
}

///|
/// Constructs an empty in-memory resolver.
pub fn InMemoryKeyResolver::new() -> InMemoryKeyResolver {
  { keys: Array::new() }
}

///|
/// Adds or replaces a key record.
///
/// A keyid longer than `limits.max_keyid_bytes` is rejected.
pub fn InMemoryKeyResolver::add(
  self : InMemoryKeyResolver,
  record : KeyRecord,
  limits : Limits,
) -> Result[Unit, HsError] {
  try {
    limits.check_keyid_length(record.keyid)
    let mut found = false
    for i, k in self.keys {
      if k.keyid == record.keyid {
        self.keys[i] = record
        found = true
        break
      }
    }
    if !found {
      self.keys.push(record)
    }
    Ok(())
  } catch {
    e => Err(e)
  }
}

///|
/// Removes a key by keyid.
pub fn InMemoryKeyResolver::remove(
  self : InMemoryKeyResolver,
  keyid : String,
) -> Unit {
  let mut i = 0
  while i < self.keys.length() {
    if self.keys[i].keyid == keyid {
      let _ = self.keys.remove(i)
    } else {
      i = i + 1
    }
  }
}

///|
/// Returns the key record for a keyid, or `None`.
pub fn InMemoryKeyResolver::get(
  self : InMemoryKeyResolver,
  keyid : String,
) -> KeyRecord? {
  for k in self.keys {
    if k.keyid == keyid {
      return Some({
        keyid: k.keyid,
        algorithm: k.algorithm,
        material: k.material,
      })
    }
  }
  None
}

///|
/// Returns the number of stored keys.
pub fn InMemoryKeyResolver::length(self : InMemoryKeyResolver) -> Int {
  self.keys.length()
}

///|
/// Implements `KeyResolver` for `InMemoryKeyResolver`.
pub impl KeyResolver for InMemoryKeyResolver with fn resolve(self, keyid) {
  match self.get(keyid) {
    Some(record) => Ok(record)
    None => Err(hs_error(KeyResolution, KeyNotFound, "key not found: " + keyid))
  }
}

///|
/// Validates that the algorithm implied by a key matches the requested
/// algorithm, raising `AlgorithmMismatch` otherwise.
pub fn check_key_algorithm(
  record : KeyRecord,
  requested_algorithm : String?,
) -> Result[Unit, HsError] {
  match requested_algorithm {
    Some(alg) =>
      if record.algorithm != alg {
        Err(
          hs_error(
            KeyResolution,
            AlgorithmMismatch,
            "key algorithm " +
            record.algorithm +
            " does not match requested " +
            alg,
          ),
        )
      } else {
        Ok(())
      }
    None =>
      if record.algorithm.is_empty() {
        Err(hs_error(KeyResolution, AlgorithmMissing, "key has no algorithm"))
      } else {
        Ok(())
      }
  }
}
