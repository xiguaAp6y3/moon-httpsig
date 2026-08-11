// accept_signature_test.mbt — Accept-Signature field tests.

///|

///|

///|

///|

///|

///|
test "as_rejects_bad_param_type" {
  match parse_accept_signature("a=(\"@method\");keyid=5", Limits::default()) {
    Ok(_) => abort("keyid as integer must be rejected")
    Err(e) => inspect(e.kind_name(), content="InvalidAcceptSignature")
  }
}
