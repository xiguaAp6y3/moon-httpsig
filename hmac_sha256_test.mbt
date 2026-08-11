// hmac_sha256_test.mbt — HMAC-SHA256 and SHA-256 tests.

///|

///|

///|

///|

///|

///|
test "sha256_known_vectors" {
  let abc = sha256_raw(@utf8.encode("abc"))
  inspect(
    hex_encode_bytes(abc),
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  let empty = sha256_raw(Bytes::new(0))
  inspect(
    hex_encode_bytes(empty),
    content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  let hello = sha256_raw(@utf8.encode("hello world"))
  inspect(
    hex_encode_bytes(hello),
    content="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  )
}

///|
test "hmac_unsupported_algorithm" {
  let provider = UnsupportedAlgorithm::new("ed25519")
  inspect(provider.algorithm_name(), content="ed25519")
  match provider.sign(@utf8.encode("m"), SharedSecret(@utf8.encode("k"))) {
    Ok(_) => abort("unsupported algorithm must not sign")
    Err(e) => inspect(e.kind_name(), content="AlgorithmNotAllowed")
  }
  match
    provider.verify(
      @utf8.encode("m"),
      @utf8.encode("s"),
      SharedSecret(@utf8.encode("k")),
    ) {
    Ok(_) => abort("unsupported algorithm must not verify true")
    Err(e) => inspect(e.kind_name(), content="AlgorithmNotAllowed")
  }
}

///|
test "algorithm_provider_dispatch" {
  let h = algorithm_provider("hmac-sha256")
  inspect(h.name(), content="hmac-sha256")
  let u = algorithm_provider("ecdsa-p256-sha256")
  inspect(u.name(), content="ecdsa-p256-sha256")
  match u.sign(@utf8.encode("m"), SharedSecret(@utf8.encode("k"))) {
    Ok(_) => abort("ecdsa must not sign")
    Err(e) => inspect(e.kind_name(), content="AlgorithmNotAllowed")
  }
}
