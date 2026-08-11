# moon-httpsig

RFC 9421 HTTP Message Signatures canonicalization, HMAC signing, verification,
and policy toolkit for MoonBit.

> 模块命名空间：`xiguaAp6y3/moon-httpsig`（原临时命名空间
> `localdev/moon-httpsig` 已统一替换）。

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
- **可执行示例**：签名/验签/响应签名/多签名/防重放/Content-Digest 绑定；
- **HTTP/1.1 文本适配器**：`adapters/http11`。

## English Summary

`moon-httpsig` is a from-scratch, local-only MoonBit implementation of
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
| 6 个可执行示例 | 已实现并测试 |
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

环境要求：MoonBit（含 `wasm-gc` / `js` / `native` 目标）、Python 3。

```sh
cd D:\Moonbit\projects\project8
moon add gmlewis/sha256          # 已写入 moon.mod，无需重复执行
moon test                        # 运行全部测试（默认目标）
moon run cmd/httpsig-tool -- --help
```

三目标验证：

```sh
moon check --target wasm-gc && moon build --target wasm-gc && moon test --target wasm-gc
moon check --target js && moon build --target js && moon test --target js
moon check --target native && moon build --target native && moon test --target native
```

一键验证脚本：

```sh
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1
```

## 请求签名

```moonbit
let options : SignOptions = {
  label: "sig1",
  components: [
    covered_derived(DerivedComponent::Method),
    covered_field("content-type"),
  ],
  parameters: params,   // created/keyid/...
  algorithm: "hmac-sha256",
  key,
}
let signed = sign_request(request, options, Limits::default()).unwrap()
// signed.signature_input / signed.signature / signed.signature_base
```

## 请求验签

```moonbit
let report = verify_request(
  request,
  signed.signature_input,
  signed.signature,
  resolver,       // InMemoryKeyResolver（生产环境应替换为共享存储）
  policy,         // VerificationPolicy
  clock,          // FixedClock / SystemClock
  nonces,         // InMemoryNonceStore
  Limits::default(),
  MultiSignaturePolicy::AnyValid,
).unwrap()
// report.verified / report.rejected
```

## 响应签名

```moonbit
let req_component = covered_derived_with_params(
  DerivedComponent::Method,
  { sf: false, key: None, bs: false, tr: false, req: true, name: None },
)
let signed = sign_response(response, options_with(req_component), Limits::default()).unwrap()
```

## 多签名

`MultiSignaturePolicy::{ AnyValid, AllPresentValid, SpecificLabel(label) }`
决定多个签名标签的接受条件；`VerificationReport` 同时给出 verified 与
rejected 明细。

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
moon run cmd/httpsig-tool -- --help
moon run cmd/httpsig-tool -- --version
moon run cmd/httpsig-tool -- parse-input --signature-input 'sig1=("@method" "@target-uri");created=1618884473;keyid="k1"'
moon run cmd/httpsig-tool -- parse-signature --signature 'sig1=:dGVzdA==:'
moon run cmd/httpsig-tool -- parse-accept --accept-signature 'a=("@method");created;keyid="k"'
moon run cmd/httpsig-tool -- build-base --method POST --path /foo --header 'content-type=application/json' --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1";alg="hmac-sha256"'
moon run cmd/httpsig-tool -- sign-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --created 1700000000 --component @method
moon run cmd/httpsig-tool -- verify-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --now 1700000000 --signature-input 'sig1=("@method");created=1700000000;keyid="k1";alg="hmac-sha256"' --signature 'sig1=:...:'
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
```

## 测试结果

- 具名测试：100 个（超过要求的 100 个）；
- 表格案例：超过 200 个；
- 确定性属性测试：1000+ 组固定种子 sign→verify 循环（1100 组）；
- RFC 9421 Appendix B 的 HMAC 示例与签名基示例逐字节通过；
- `wasm-gc`、`js`、`native` 三目标：`check`/`build`/`test` 均通过，0 errors，
  0 warnings（`reserved_keyword` 因规范要求保留 `method` 字段名而被抑制）。

## 目录结构

```
project8/
├── cmd/httpsig-tool/        CLI
├── adapters/http11/         HTTP/1.1 文本适配器
├── docs/                    文档
├── examples/                6 个可执行示例
├── scripts/                 行数统计、fixture 生成/校验、一键验证
├── testdata/rfc9421/        RFC 测试向量
├── moon.mod / moon.pkg
└── *.mbt                    核心库
```

## Roadmap

- v0.1.0（当前）：RFC 9421 核心、HMAC、策略、CLI、测试。
- v0.2.0：完整 RFC 9651 Adapter、更多 HTTP Adapter。
- v0.3.0：Ed25519 Provider 与远程 Resolver 示例。
- v0.4.0：Webhook、ActivityPub、API Gateway Profile。

这些是未来计划，尚未完成。详见 `docs/roadmap.md`。

## License

Apache-2.0，见 [LICENSE](LICENSE)。

## 本地开发状态

截至项目立项时的公开生态检索，未发现完整的 MoonBit RFC 9421 HTTP Message
Signatures 实现。**这不是绝对保证**，仅代表立项时检索到的公开信息。
本项目目前为纯本地、匿名开发状态，未提交、未发布、未参赛。

[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
