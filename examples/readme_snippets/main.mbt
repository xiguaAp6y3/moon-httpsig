// readme_snippets — README.md 中四段 MoonBit 片段的完整、可编译版本。
//
// 每段都是自包含的（变量都在片段内定义），可以直接复制到自己的包里使用。
// `moon run examples/readme_snippets` 会打印每段的执行结果；CI 会编译并运行
// 本包，因此一旦公开 API 变化，README 中的示例会立刻暴露出来。

///|
/// README「请求签名」：用 HMAC-SHA256 给一个请求签名。
fn demo_sign_request() -> String {
  let headers = @hsig.OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let request = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/api/orders",
    None,
    headers,
    None,
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("shared-secret")),
  }
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: Some("hmac-sha256"),
    nonce: None,
    tag: None,
    extensions: Array(capacity=0),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Method),
      @hsig.covered_field("content-type"),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_request(request, options, @hsig.Limits::default()).unwrap()
  // signed.signature_input / signed.signature / signed.signature_base
  "signature=" + signed.signature
}

///|
/// README「请求验签」：校验上面那个签名，并演示篡改后被拒绝。
fn demo_verify_request() -> String {
  let headers = @hsig.OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let request = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/api/orders",
    None,
    headers,
    None,
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("shared-secret")),
  }
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("k1"),
    alg: Some("hmac-sha256"),
    nonce: None,
    tag: None,
    extensions: Array(capacity=0),
  }
  let options : @hsig.SignOptions = {
    label: "sig1",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Method),
      @hsig.covered_field("content-type"),
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_request(request, options, @hsig.Limits::default()).unwrap()
  let resolver = @hsig.InMemoryKeyResolver::new() // 生产环境应替换为共享存储
  let _ = resolver.add(key, @hsig.Limits::default())
  let policy = @hsig.VerificationPolicy::hmac_only()
  let clock = @hsig.FixedClock::new(1700000000L) // 或 SystemClock::new()
  let nonces = @hsig.InMemoryNonceStore::new()
  let report = @hsig.verify_request(
    request,
    signed.signature_input,
    signed.signature,
    resolver,
    policy,
    clock,
    nonces,
    @hsig.Limits::default(),
    @hsig.MultiSignaturePolicy::AnyValid,
  ).unwrap()
  // report.verified / report.rejected
  let accepted = report.verified.length().to_string()
  // 篡改被覆盖的 content-type 后必须被拒绝。
  let tampered_headers = @hsig.OrderedHeaders::new()
  let _ = tampered_headers.append("content-type", "text/plain")
  let tampered = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/api/orders",
    None,
    tampered_headers,
    None,
  ).unwrap()
  let tampered_verdict = match
    @hsig.verify_request(
      tampered,
      signed.signature_input,
      signed.signature,
      resolver,
      policy,
      clock,
      @hsig.InMemoryNonceStore::new(),
      @hsig.Limits::default(),
      @hsig.MultiSignaturePolicy::AnyValid,
    ) {
    Ok(_) => "accepted"
    Err(_) => "rejected"
  }
  "verified=" + accepted + " tampered=" + tampered_verdict
}

///|
/// README「响应签名」：给响应签名，并用 `req` 参数把相关请求的方法绑进来。
fn demo_sign_response() -> String {
  let headers = @hsig.OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let related = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/order",
    None,
    headers,
    None,
  ).unwrap()
  let response = @hsig.ResponseContext::new_default(
    201,
    headers,
    None,
    Some(related),
  ).unwrap()
  let key : @hsig.KeyRecord = {
    keyid: "server-key",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("server-secret")),
  }
  let req_component = @hsig.covered_derived_with_params(
    @hsig.DerivedComponent::Method,
    { sf: false, key: None, bs: false, tr: false, req: true, name: None, },
  )
  let params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: Some("server-key"),
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array(capacity=0),
  }
  let options : @hsig.SignOptions = {
    label: "respsig",
    components: [
      @hsig.covered_derived(@hsig.DerivedComponent::Status),
      req_component,
    ],
    parameters: params,
    algorithm: "hmac-sha256",
    key,
  }
  let signed = @hsig.sign_response(response, options, @hsig.Limits::default()).unwrap()
  // 相关请求被 `req` 绑定后，签名基里会出现 `"@method";req`。
  let base_has_req = signed.signature_base.text.contains("\"@method\";req")
  "signature=" +
  signed.signature +
  " base_binds_req=" +
  base_has_req.to_string()
}

///|
/// README「多签名」：两个标签，k1 的密钥正确、k2 的密钥错误，对比三种
/// `MultiSignaturePolicy` 的判定结果。
fn demo_multi_signature() -> String {
  let headers = @hsig.OrderedHeaders::new()
  let _ = headers.append("content-type", "application/json")
  let request = @hsig.RequestContext::new_default(
    "POST",
    "https",
    "example.com",
    "/api/orders",
    None,
    headers,
    None,
  ).unwrap()
  let k1 : @hsig.KeyRecord = {
    keyid: "k1",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("secret-one")),
  }
  let k2 : @hsig.KeyRecord = {
    keyid: "k2",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("secret-two")),
  }
  let base_params : @hsig.SignatureParameters = {
    created: Some(1700000000L),
    expires: None,
    keyid: None,
    alg: None,
    nonce: None,
    tag: None,
    extensions: Array(capacity=0),
  }
  let o1 : @hsig.SignOptions = {
    label: "sig1",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Method)],
    parameters: { ..base_params, keyid: Some("k1"), },
    algorithm: "hmac-sha256",
    key: k1,
  }
  let o2 : @hsig.SignOptions = {
    label: "sig-b",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Path)],
    parameters: { ..base_params, keyid: Some("k2"), },
    algorithm: "hmac-sha256",
    key: k2,
  }
  let s1 = @hsig.sign_request(request, o1, @hsig.Limits::default()).unwrap()
  let s2 = @hsig.sign_request(request, o2, @hsig.Limits::default()).unwrap()
  // 验证方只掌握 k1 的正确密钥，k2 用的是错的。
  let resolver = @hsig.InMemoryKeyResolver::new()
  let _ = resolver.add(k1, @hsig.Limits::default())
  let _ = resolver.add(
    {
      keyid: "k2",
      algorithm: "hmac-sha256",
      material: @hsig.SharedSecret(@utf8.encode("wrong-secret")),
    },
    @hsig.Limits::default(),
  )
  let combined_input = s1.signature_input + ", " + s2.signature_input
  let combined_signature = s1.signature + ", " + s2.signature
  let policy = @hsig.VerificationPolicy::hmac_only()
  let clock = @hsig.FixedClock::new(1700000000L)
  let judge = fn(multi : @hsig.MultiSignaturePolicy) -> String {
    let result = @hsig.verify_request(
      request,
      combined_input,
      combined_signature,
      resolver,
      policy,
      clock,
      @hsig.InMemoryNonceStore::new(),
      @hsig.Limits::default(),
      multi,
    )
    match result {
      Ok(report) =>
        "ok(" +
        report.verified.length().to_string() +
        "/" +
        report.rejected.length().to_string() +
        ")"
      Err(e) => "err(" + e.kind_name() + ")"
    }
  }
  "AnyValid=" +
  judge(@hsig.MultiSignaturePolicy::AnyValid) +
  " AllPresentValid=" +
  judge(@hsig.MultiSignaturePolicy::AllPresentValid) +
  " SpecificLabel(sig1)=" +
  judge(@hsig.MultiSignaturePolicy::SpecificLabel("sig1"))
}

///|
fn main {
  println("[1] sign_request   " + demo_sign_request())
  println("[2] verify_request " + demo_verify_request())
  println("[3] sign_response  " + demo_sign_response())
  println("[4] multi_sig      " + demo_multi_signature())
}
