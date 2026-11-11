# moon-httpsig

RFC 9421 HTTP Message Signatures canonicalization, HMAC signing, verification,
and policy toolkit for MoonBit.

> **Project/module**: `xiguaAp6y3/moon-httpsig`
> **Repository**: https://github.com/xiguaAp6y3/moon-httpsig
> **Version**: 0.1.1
> **License**: Apache-2.0

## 中文项目介绍

`moon-httpsig` 是使用 MoonBit 从零实现的 [RFC 9421]（HTTP Message
Signatures）工具库。它提供：

- **HTTP 消息模型**：保序、可含同名多值、区分 Header/Trailer 的请求与响应模型；
- **Structured Field 子集**：RFC 9651 的 Dictionary / Inner List / Item /
  Parameters 解析与规范序列化；
- **组件解析**：`@method`、`@target-uri`、`@authority`、`@scheme`、
  `@request-target`、`@path`、`@query`、`@query-param`、`@status` 等派生组件，
  以及普通 Header / Trailer / related request 字段组件（含 `sf`、`bs`、
  `key`、`tr`、`req` 参数）；
- **签名基**：按 RFC 9421 §2.5 逐字节构造签名基；
- **算法**：内置 `hmac-sha256`（基于成熟 SHA-256 依赖，按 RFC 2104 构造），
  其余算法名只预留、不实现、不返回假的验签成功；
- **验证策略**：算法白名单、时间（created/expires/最大年龄/时钟偏移）、
  required components、keyid、nonce、tag、Content-Digest 绑定、多签名策略；
- **CLI**：`httpsig-tool`，输出稳定 JSON；
- **可执行示例**：签名/验签/响应签名/多签名/防重放/Content-Digest 绑定，
  以及本文档 4 段用法示例的完整可运行版本（`examples/readme_snippets`）；
- **HTTP/1.1 文本适配器**：`adapters/http11`。

## English Summary

`moon-httpsig` is a from-scratch MoonBit implementation of
[RFC 9421] (HTTP Message Signatures). It covers the HTTP message model, an
RFC 9651 structured-field subset, covered-component resolution, byte-exact
signature-base construction, an HMAC-SHA256 provider built on a mature
SHA-256 dependency, verification policy, replay protection, and RFC 9530
Content-Digest binding. It is **not** a JWT library, HTTP server/client, TLS
implementation, general cryptography library, or the legacy Cavage draft.

## RFC 9421 简介

RFC 9421 定义了“HTTP 消息签名”：签名方选择 HTTP 消息中若干“覆盖组件”
（covered components），按规范格式逐行拼接成签名基，再对签名基做密码学运算，
把元数据写入 `Signature-Input` 字段、把签名值写入 `Signature` 字段。
`Accept-Signature` 用于协商签名请求。本项目的实现以 RFC 9421 及已核实的
勘误为准，并参考 RFC 9530（Digest Fields）、RFC 9651（Structured Field
Values）、RFC 9110（HTTP Semantics）。

## 项目价值

- 为 MoonBit 提供 RFC 9421 的标准能力，作为 API/Webhook 消息完整性基础件；
- 签名基逐字节与 RFC Appendix B 测试向量比对；
- 结构化错误（`HsErrorStage`/`HsErrorKind`/offset/context），便于自动化处理；
- 默认安全：算法白名单、时间校验、防重放、Content-Digest 绑定；
- 不联网解析 keyid，不把 keyid 当作可信身份。

## 功能支持矩阵

| 功能 | 状态 |
| --- | --- |
| HTTP 消息模型（请求/响应/Header/Trailer） | 已实现并测试 |
| RFC 9651 子集解析与序列化 | 已实现并测试 |
| 派生组件解析（含 @query-param、@status、req） | 已实现并测试 |
| 字段组件解析（sf/bs/key/tr/req） | 已实现并测试 |
| 签名基构造（逐字节） | 已实现并测试 |
| HMAC-SHA256 签名/验签 | 已实现并测试 |
| 常量时间比较 | 已实现并测试 |
| 验证策略（白名单/时间/required/keyid/nonce/tag） | 已实现并测试 |
| 防重放（NonceStore） | 已实现并测试 |
| Content-Digest 绑定 | 已实现并测试 |
| 多签名策略 | 已实现并测试 |
| CLI `httpsig-tool` | 已实现并测试 |
| 7 个可执行示例 | 已实现并测试 |
| HTTP/1.1 文本适配器 | 已实现并测试 |
| rsa-pss-sha512 / ecdsa-* / ed25519 | 未实现（返回 `AlgorithmNotAllowed`） |
| 远程 Key Resolver / JWKS / DID | 不支持（按设计禁止） |

## 不支持内容

本项目**不是**：

- JWT 库；
- HTTP 服务器或客户端；
- TLS 实现；
- 通用密码学库；
- 身份认证/授权平台；
- 旧版 Cavage HTTP Signatures Draft 实现。

## 本地使用方式

环境要求：MoonBit（含 `wasm` / `wasm-gc` / `js` / `native` 目标）、Python 3。

```sh
git clone https://github.com/xiguaAp6y3/moon-httpsig.git
cd moon-httpsig
moon add gmlewis/sha256          # 已写入 moon.mod，无需重复执行
moon test                        # 运行全部测试（默认目标）
moon run cmd/httpsig-tool help
```

四目标严格验证：

```sh
moon check --target all --deny-warn
moon build --target all
moon test --target all --deny-warn
```

一键验证脚本：

```sh
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1
```

### 已验证的工具链

以下版本经 `moon version --all` 确认，并完成了本文档列出的全部检查、构建与测试
（验证日期 2026-11-11）：

```
moon 0.1.20261104 (940aa18 2026-11-04)
moonc v0.10.20+65efd5b93 (2026-11-05)
moonrun 0.1.20261104 (940aa18 2026-11-04)

Feature flags enabled: rr_moon_mod, rr_moon_pkg
```

该工具链不早于 MoonBit 官方更新页当时最新的公告版本（v0.10.19，2026-11-05），
因此无需再额外升级。安装与更新方式见 <https://www.moonbitlang.com/download/>；
`moon upgrade` 需要交互式终端，在 CI 或非 TTY 环境下请改用官方安装脚本。

### 工具链兼容性说明

为适配上文已验证的工具链，源码做了下列改动。它们全部由编译器与官方格式化器
验证，**不改变公开 API 与签名/验签行为**：

| 改动 | 处数 | 原因 |
| --- | --- | --- |
| `Array::new()` → `Array(capacity=0)` | 66 | `Array::new()` 已标记 deprecated（E0020） |
| `StringView::sub(...)` → `exact_view(...)` | 2 | `sub` 已标记 deprecated（E0020） |
| 跨 `impl` 的隐式方法提升改为显式 `pub extend` | 10 | `implicit_impl_as_method`（E0079），该隐式行为将被移除 |
| `Int` → `Int32`、结构体字面量补尾逗号 | 52 个文件 | `moon fmt` 在新工具链下的格式要求 |
| 移除未使用的 `moonbitlang/core/strconv` 导入 | 1 | `unused_package`（E0029） |

其中 `UnsupportedAlgorithm` 的 `sign`/`verify` 已有同名固有方法，若一并提升会触发
E4056 重复定义，因此只提升 `name`。

另有两条告警在 `moon.mod` 的 `warnings` 中显式关闭。它们针对的是本库**有意采用
的设计**，而不是待修复的缺陷：

- `result_error_return`（E0078，81 处）：本库公开 API 把 `Result[T, HsError]` 当作
  **普通数据**返回——“签名不匹配 / 策略拒绝”是正常业务结果，调用方需要读取结构化
  的 `VerificationReport`，而不是用异常中断流程。改为 `raise` 既会让 0.1.1 的公开
  API 发生破坏性变化，也与该告警自身描述（仅在失败必须作为数据表示时才用 `Result`）
  相悖。
- `test_unqualified_package`（E0025，670 处）：测试文件依赖包内 API 的隐式导入。
  逐处改写为 `@moon-httpsig.xxx` 是纯机械改动，会显著降低测试可读性且不影响行为。
  **后续风险**：若工具链真正移除该隐式导入，需要一次性完成这次迁移。

`-reserved_keyword` 仍然保留：RFC 9421 要求字段组件名写作 `method`。

### 支持范围与限制

- 后端：`wasm`、`wasm-gc`、`js`、`native` 四个目标均已通过 `check`/`build`/`test`；
  不承诺其他后端（如 `wasm-1`、`wasm-gc-reactor` 等）可用。
- 密码学：仅实现 `hmac-sha256`；其余算法名只被识别，调用时返回
  `AlgorithmNotAllowed`，不会返回假的验签成功。
- 远程 Key Resolver / JWKS / DID 按设计不支持（`keyid` 不被当作可信身份）。
- 工具链版本：低于上表的版本未验证；`--deny-warn` 门禁依赖该版本的告警集合，
  升级工具链后应先重跑本节的验证流程。

## 使用示例（可直接运行）

下面几段代码按顺序放进同一个包即可编译运行。`examples/readme_snippets/` 是它的
可执行版本：`moon run examples/readme_snippets` 会打印每段的结果，CI 也会编译并
运行它，因此公开 API 一旦变化，这里的示例会先失败。

### 公共准备：请求、密钥、签名参数

```moonbit
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
```

### 1. 请求签名

```moonbit
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
// signed.signature_input / signed.signature / signed.signature_base.text
```

### 2. 请求验签

```moonbit
let resolver = @hsig.InMemoryKeyResolver::new() // 生产环境应替换为共享存储
let _ = resolver.add(key, @hsig.Limits::default())
let policy = @hsig.VerificationPolicy::hmac_only()
let clock = @hsig.FixedClock::new(1700000000L) // 时钟也可用 SystemClock::new()
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
```

被覆盖的 `content-type` 一旦被篡改（`application/json` → `text/plain`），同一个
`verify_request` 调用会返回 `Err`，示例里的输出为 `tampered=rejected`。

### 3. 响应签名

```moonbit
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
let req_component = @hsig.covered_derived_with_params(
  @hsig.DerivedComponent::Method,
  { sf: false, key: None, bs: false, tr: false, req: true, name: None, },
)
let response_options : @hsig.SignOptions = {
  label: "respsig",
  components: [
    @hsig.covered_derived(@hsig.DerivedComponent::Status),
    req_component,
  ],
  parameters: params,
  algorithm: "hmac-sha256",
  key,
}
let signed_response = @hsig.sign_response(
  response,
  response_options,
  @hsig.Limits::default(),
).unwrap()
// signed_response.signature_base.text 中出现 `"@method";req`：相关请求被绑定
```

### 4. 多签名

`@hsig.MultiSignaturePolicy::{ AnyValid, AllPresentValid, SpecificLabel(label) }`
决定多个标签的接受条件，`@hsig.VerificationReport` 同时给出 `verified` 与
`rejected` 明细：

```moonbit
let k2 : @hsig.KeyRecord = {
  keyid: "k2",
  algorithm: "hmac-sha256",
  material: @hsig.SharedSecret(@utf8.encode("second-secret")),
}
let sig_b = @hsig.sign_request(
  request,
  {
    ..options,
    label: "sig-b",
    components: [@hsig.covered_derived(@hsig.DerivedComponent::Path)],
    parameters: { ..params, keyid: Some("k2"), },
    key: k2,
  },
  @hsig.Limits::default(),
).unwrap()
// 验证方掌握 k1 的正确密钥，但 k2 用的是错密钥
let _ = resolver.add(
  {
    keyid: "k2",
    algorithm: "hmac-sha256",
    material: @hsig.SharedSecret(@utf8.encode("wrong-secret")),
  },
  @hsig.Limits::default(),
)
let judge = fn(multi : @hsig.MultiSignaturePolicy) -> String {
  match @hsig.verify_request(
    request,
    signed.signature_input + ", " + sig_b.signature_input,
    signed.signature + ", " + sig_b.signature,
    resolver,
    policy,
    clock,
    @hsig.InMemoryNonceStore::new(),
    @hsig.Limits::default(),
    multi,
  ) {
    Ok(r) =>
      "ok(verified=" +
      r.verified.length().to_string() +
      ", rejected=" +
      r.rejected.length().to_string() +
      ")"
    Err(e) => "err(" + e.kind_name() + ")"
  }
}
// sig1 有效、sig-b 无效（密钥不匹配）时的判定结果：
// AnyValid             -> ok(verified=1, rejected=1)  只要有一个签名有效即通过
// AllPresentValid      -> err(SignatureMismatch)      要求每个标签都有效
// SpecificLabel("sig1")-> ok(verified=1, rejected=1)  只要求指定标签有效
```


## HMAC 安全说明

- `hmac-sha256` 是共享密钥方案，不提供公钥验签；密钥分发与管理由应用负责。
- MAC 比较使用 `constant_time_equal`，禁止用 `==` 直接比较。
- 本库**不实现** SHA-256，而是使用成熟依赖 `gmlewis/sha256`（Apache-2.0）。
- 详见 `docs/security.md`。

## Content-Digest

HTTP 消息签名本身**不保护 Body**。只有同时满足：消息带 `Content-Digest`、
digest 已验证、且 `content-digest` 被覆盖组件包含，才能声称 Body 被绑定。
策略字段：`require_content_digest`、`require_content_digest_covered`。

## CLI

```sh
moon run cmd/httpsig-tool help
moon run cmd/httpsig-tool version
moon run cmd/httpsig-tool -- parse-input --signature-input 'sig1=("@method" "@target-uri");created=1618884473;keyid="k1"'
moon run cmd/httpsig-tool -- parse-signature --signature 'sig1=:dGVzdA==:'
moon run cmd/httpsig-tool -- parse-accept --accept-signature 'a=("@method");created;keyid="k"'
moon run cmd/httpsig-tool -- build-base --method POST --path /foo --header 'content-type=application/json' --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1";alg="hmac-sha256"'
moon run cmd/httpsig-tool -- sign-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --created 1700000000 --component @method
# 下一条的 --signature 就是上面 sign-hmac 输出的 signature 值（输入固定，结果确定）
moon run cmd/httpsig-tool -- verify-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --now 1700000000 --signature-input 'sig1=("@method");created=1700000000;keyid="k1";alg="hmac-sha256"' --signature 'sig1=:vfk3LxoBUi1Ki/7VyJah161GLhPBYs+gr4jGdARnU+8=:'
moon run cmd/httpsig-tool -- inspect --signature-input 'sig1=("@method");created=1618884473;keyid="k1"'
moon run cmd/httpsig-tool -- check-policy --signature-input 'sig1=("@method");created=1618884473;keyid="k1"' --required-component @method
moon run cmd/httpsig-tool -- rfc-example
```

CLI 输出稳定 JSON，详见 `docs/cli-reference.md`。

## Examples

```sh
moon run examples/sign_request
moon run examples/verify_request
moon run examples/sign_response
moon run examples/multiple_signatures
moon run examples/replay_policy
moon run examples/content_digest_binding
moon run examples/readme_snippets    # README「使用示例」的可运行版本
```

## 测试结果

- 具名测试：101 个（根目录 94 + 适配器 7）；
- 表驱动数据：`testdata/rfc9421/` 下 41 条 RFC fixture 条目，由
  `scripts/verify_rfc_fixtures.py` 校验（该脚本会先重新生成再比对，幂等）；
- 确定性属性测试：1100 组固定种子 sign→verify 循环（1000 组完整循环 +
  100 组覆盖/未覆盖变更判定）；
- RFC 9421 Appendix B 的 HMAC 示例与签名基示例逐字节通过；
- `wasm`、`wasm-gc`、`js`、`native` 四目标：`check`/`build`/`test` 均通过，0 errors，
  0 warnings（`reserved_keyword` 因规范要求保留 `method` 字段名而被抑制）。

复验记录（`moon 0.1.20261104` / `moonc v0.10.20`，2026-11-11）：

```
moon fmt --check                        -> 通过
moon check   --target all --deny-warn   -> 通过（0 warnings）
moon build   --target all               -> 通过
moon test    --target all --deny-warn   -> Total tests: 101, passed: 101, failed: 0（四目标各 101）
7 个示例 + CLI 4 项 smoke 测试            -> 退出码 0
python scripts/verify_rfc_fixtures.py   -> RFC 9421 fixtures OK
```

## 目录结构

```
├── cmd/httpsig-tool/        CLI
├── adapters/http11/         HTTP/1.1 文本适配器
├── docs/                    文档
├── examples/                7 个可执行示例（含 README 用法示例的可运行版本）
├── scripts/                 行数统计、fixture 生成/校验、一键验证
├── testdata/rfc9421/        RFC 测试向量
├── moon.mod / moon.pkg
└── *.mbt                    核心库
```

## Roadmap

- v0.1.1（当前）：终审兼容补丁、严格四目标验证与 CI。
- v0.1.0：RFC 9421 核心、HMAC、策略、CLI、测试。
- v0.2.0：完整 RFC 9651 Adapter、更多 HTTP Adapter。
- v0.3.0：Ed25519 Provider 与远程 Resolver 示例。
- v0.4.0：Webhook、ActivityPub、API Gateway Profile。

这些是未来计划，尚未完成。详见 `docs/roadmap.md`。

## License

Apache-2.0，见 [LICENSE](LICENSE)。

## 发布状态

截至项目立项时的公开生态检索，未发现完整的 MoonBit RFC 9421 HTTP Message
Signatures 实现。**这不是绝对保证**，仅代表立项时检索到的公开信息。
项目已公开发布到 GitHub（`xiguaAp6y3/moon-httpsig`），终审补丁版
`xiguaAp6y3/moon-httpsig@0.1.1` 已发布到 Mooncakes。

[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
