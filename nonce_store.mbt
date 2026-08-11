// nonce_store.mbt — Replay-protection nonce store.
//
// A nonce binds a signature to a single use: once `(keyid, nonce)` has been
// recorded, a second presentation is rejected as `DuplicateNonce`. The
// in-memory store is for single-process use (tests, examples); production
// deployments must use a shared store (Redis, database) as documented in
// docs/security.md.

///|
/// The nonce store interface.
pub(open) trait NonceStore {
  /// Records `nonce` for `keyid` unless it was already seen, optionally
  /// honoring an `expires` time. Returns `Ok(())` on first use and
  /// `DuplicateNonce` on replay.
  fn check_and_store(Self, keyid : String, nonce : String, expires : Int64?) -> Result[
    Unit,
    HsError,
  ]
}

///|
/// A recorded nonce with an optional expiration.
struct NonceEntry {
  keyid : String
  nonce : String
  expires : Int64?
}

///|
/// An in-memory nonce store. Not safe for multi-process use.
pub struct InMemoryNonceStore {
  entries : Array[NonceEntry]
}

///|
/// Constructs an empty in-memory nonce store.
pub fn InMemoryNonceStore::new() -> InMemoryNonceStore {
  { entries: Array::new() }
}

///|
/// Removes entries whose `expires` time is in the past (relative to `now`).
/// Returns the number of entries removed.
pub fn InMemoryNonceStore::prune(self : InMemoryNonceStore, now : Int64) -> Int {
  let mut removed = 0
  let mut i = 0
  while i < self.entries.length() {
    let e = self.entries[i]
    if e.expires is Some(t) && t < now {
      let _ = self.entries.remove(i)
      removed = removed + 1
    } else {
      i = i + 1
    }
  }
  removed
}

///|
/// Returns the number of stored nonces.
pub fn InMemoryNonceStore::length(self : InMemoryNonceStore) -> Int {
  self.entries.length()
}

///|
/// Implements `NonceStore` for `InMemoryNonceStore`.
pub impl NonceStore for InMemoryNonceStore with fn check_and_store(
  self,
  keyid,
  nonce,
  expires,
) {
  for e in self.entries {
    if e.keyid == keyid && e.nonce == nonce {
      return Err(
        hs_error(
          ReplayProtection,
          DuplicateNonce,
          "nonce already used: " + nonce,
        ),
      )
    }
  }
  self.entries.push({ keyid, nonce, expires })
  Ok(())
}
