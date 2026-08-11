// hmac_sha256.mbt — HMAC-SHA256 provider (RFC 2104) built on a mature
// SHA-256 dependency (gmlewis/sha256, Apache-2.0).
//
// The SHA-256 primitive is provided by the gmlewis/sha256 package; HMAC
// construction follows RFC 2104 exactly (64-byte block, ipad 0x36, opad
// 0x5c, key hashing when longer than the block). MAC comparisons use
// `constant_time_equal`.

///|
/// The HMAC-SHA256 algorithm provider.
pub enum HmacSha256 {
  HmacSha256
}

///|
/// Constructs the HMAC-SHA256 provider.
pub fn HmacSha256::new() -> HmacSha256 {
  HmacSha256
}

///|
/// Returns the registered algorithm name.
pub fn HmacSha256::algorithm_name(_self : HmacSha256) -> String {
  "hmac-sha256"
}

///|
/// The SHA-256 block size in bytes.
let hmac_block_size = 64

///|
/// Computes the raw 32-byte SHA-256 digest of `data`.
///
/// The `gmlewis/sha256` package exposes a streaming digest whose `check_sum`
/// returns lowercase hex; we decode it back to raw bytes.
pub fn sha256_raw(data : Bytes) -> Bytes {
  let d = @sha256.Digest::new()
  for b in data {
    d.write(b)
  }
  match hex_decode_bytes(d.check_sum()) {
    Ok(b) => b
    Err(_) => abort("sha256 hex decode failed")
  }
}

///|
/// Computes HMAC-SHA256 of `message` under `key` per RFC 2104.
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  // If key is longer than the block size, hash it first.
  let mut effective = key
  if key.length() > hmac_block_size {
    effective = sha256_raw(key)
  }
  // Pad the key to the block size with trailing zero bytes.
  let padded = FixedArray::make(hmac_block_size, b'\x00')
  for i = 0; i < effective.length(); i = i + 1 {
    padded[i] = effective[i]
  }
  let ipad = FixedArray::make(hmac_block_size, b'\x00')
  let opad = FixedArray::make(hmac_block_size, b'\x00')
  for i = 0; i < hmac_block_size; i = i + 1 {
    ipad[i] = (padded[i].to_int() ^ 0x36).to_byte()
    opad[i] = (padded[i].to_int() ^ 0x5C).to_byte()
  }
  // inner = SHA256( (key XOR ipad) || message )
  let inner_buf = Buffer::Buffer(size_hint=hmac_block_size + message.length())
  inner_buf.write_bytes(Bytes::from_array(ipad))
  inner_buf.write_bytes(message)
  let inner = sha256_raw(inner_buf.to_bytes())
  // outer = SHA256( (key XOR opad) || inner )
  let outer_buf = Buffer::Buffer(size_hint=hmac_block_size + 32)
  outer_buf.write_bytes(Bytes::from_array(opad))
  outer_buf.write_bytes(inner)
  sha256_raw(outer_buf.to_bytes())
}

///|
/// Signs a message with a shared secret.
pub fn HmacSha256::sign_hmac(
  _self : HmacSha256,
  message : Bytes,
  key : Bytes,
) -> Bytes {
  hmac_sha256(key, message)
}

///|
/// Verifies a MAC with a shared secret in constant time.
pub fn HmacSha256::verify_hmac(
  _self : HmacSha256,
  message : Bytes,
  signature : Bytes,
  key : Bytes,
) -> Bool {
  let expected = hmac_sha256(key, message)
  constant_time_equal(expected, signature)
}

///|
/// Implements `SignatureAlgorithm` for `HmacSha256`.
pub impl SignatureAlgorithm for HmacSha256 with fn name(_self) {
  "hmac-sha256"
}

///|
/// Implements `sign` for `HmacSha256`.
pub impl SignatureAlgorithm for HmacSha256 with fn sign(_self, message, key) {
  match key {
    SharedSecret(secret) => Ok(hmac_sha256(secret, message))
    ExternalKey(_) =>
      Err(
        hs_error(
          KeyResolution,
          InvalidKeyMaterial,
          "hmac-sha256 requires a shared secret",
        ),
      )
  }
}

///|
/// Implements `verify` for `HmacSha256`.
pub impl SignatureAlgorithm for HmacSha256 with fn verify(
  _self,
  message,
  signature,
  key,
) {
  match key {
    SharedSecret(secret) =>
      Ok(constant_time_equal(hmac_sha256(secret, message), signature))
    ExternalKey(_) =>
      Err(
        hs_error(
          KeyResolution,
          InvalidKeyMaterial,
          "hmac-sha256 requires a shared secret",
        ),
      )
  }
}
