// algorithm.mbt — Algorithm abstraction (RFC 9421 §6.1).
//
// Signature algorithms are pluggable. The built-in provider is HMAC-SHA256.
// Additional algorithms (rsa-pss-sha512, rsa-v1_5-sha256, ecdsa-p256-sha256,
// ecdsa-p384-sha384, ed25519) are recognized by name but deliberately NOT
// implemented: any attempt to use them returns `AlgorithmNotAllowed` rather
// than a fake success.

///|
/// Key material for a signature algorithm.
pub(all) enum KeyMaterial {
  /// A symmetric shared secret (HMAC and MAC algorithms).
  SharedSecret(Bytes)
  /// An external key reference whose interpretation is provider-specific
  /// (e.g. a JWK string for a future asymmetric provider).
  ExternalKey(String)
}

///|
/// The interface every signature algorithm must implement.
pub(open) trait SignatureAlgorithm {
  /// The canonical algorithm name from the HTTP Signature Algorithms registry
  /// (e.g. `hmac-sha256`).
  fn name(Self) -> String
  /// Computes the signature over `message`.
  fn sign(Self, Bytes, KeyMaterial) -> Result[Bytes, HsError]
  /// Verifies `signature` over `message`.
  fn verify(Self, Bytes, Bytes, KeyMaterial) -> Result[Bool, HsError]
}

///|
/// A provider that returns `AlgorithmNotAllowed` for every unimplemented
/// algorithm name. Using this provider is safer than returning success.
pub struct UnsupportedAlgorithm {
  algorithm : String
}

///|
/// Constructs an `UnsupportedAlgorithm` marker for the given name.
pub fn UnsupportedAlgorithm::new(algorithm : String) -> UnsupportedAlgorithm {
  { algorithm, }
}

///|
/// The algorithm name the marker stands for.
pub fn UnsupportedAlgorithm::algorithm_name(
  self : UnsupportedAlgorithm,
) -> String {
  self.algorithm
}

///|
/// Returns `AlgorithmNotAllowed` for signing (unimplemented algorithm).
pub fn UnsupportedAlgorithm::sign(
  self : UnsupportedAlgorithm,
  _message : Bytes,
  _key : KeyMaterial,
) -> Result[Bytes, HsError] {
  Err(
    hs_error(
      CryptographicVerification,
      AlgorithmNotAllowed,
      "algorithm not implemented: " + self.algorithm,
    ),
  )
}

///|
/// Returns `AlgorithmNotAllowed` for verification (unimplemented algorithm).
pub fn UnsupportedAlgorithm::verify(
  self : UnsupportedAlgorithm,
  _message : Bytes,
  _signature : Bytes,
  _key : KeyMaterial,
) -> Result[Bool, HsError] {
  Err(
    hs_error(
      CryptographicVerification,
      AlgorithmNotAllowed,
      "algorithm not implemented: " + self.algorithm,
    ),
  )
}

///|
/// Implements `SignatureAlgorithm` for `UnsupportedAlgorithm`.
pub impl SignatureAlgorithm for UnsupportedAlgorithm with fn name(self) {
  self.algorithm
}

///|
/// Implements `sign` for `UnsupportedAlgorithm`.
pub impl SignatureAlgorithm for UnsupportedAlgorithm with fn sign(
  self,
  message,
  key,
) {
  self.sign(message, key)
}

///|
/// Implements `verify` for `UnsupportedAlgorithm`.
pub impl SignatureAlgorithm for UnsupportedAlgorithm with fn verify(
  self,
  message,
  signature,
  key,
) {
  self.verify(message, signature, key)
}

///|
/// A concrete, owned algorithm provider (either a built-in or an
/// unsupported-algorithm marker). This is what the signer/verifier carry
/// around so the `SignatureAlgorithm` trait can be used without lifetimes.
pub(all) enum SignatureAlgorithmProvider {
  Hmac(HmacSha256)
  Unsupported(UnsupportedAlgorithm)
}

///|
/// Implements `SignatureAlgorithm` for `SignatureAlgorithmProvider`.
pub impl SignatureAlgorithm for SignatureAlgorithmProvider with fn name(self) {
  match self {
    Hmac(h) => SignatureAlgorithm::name(h)
    Unsupported(u) => SignatureAlgorithm::name(u)
  }
}

///|
/// Implements `sign` for `SignatureAlgorithmProvider`.
pub impl SignatureAlgorithm for SignatureAlgorithmProvider with fn sign(
  self,
  message,
  key,
) {
  match self {
    Hmac(h) => SignatureAlgorithm::sign(h, message, key)
    Unsupported(u) => u.sign(message, key)
  }
}

///|
/// Implements `verify` for `SignatureAlgorithmProvider`.
pub impl SignatureAlgorithm for SignatureAlgorithmProvider with fn verify(
  self,
  message,
  signature,
  key,
) {
  match self {
    Hmac(h) => SignatureAlgorithm::verify(h, message, signature, key)
    Unsupported(u) => u.verify(message, signature, key)
  }
}
