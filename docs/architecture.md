# 架构

moon-httpsig 按职责划分为七个层次。数据从 HTTP 消息模型流向签名基，再由
signer/verifier 驱动。

## 层次概览

| 层 | 模块 | 职责 |
| --- | --- | --- |
| 第一层 | message.mbt, ordered_headers.mbt, limits.mbt, error.mbt, ascii.mbt | HTTP 消息模型 |
| 第二层 | sf_model.mbt, sf_cursor.mbt, sf_parser.mbt, sf_serializer.mbt | RFC 9651 结构化字段子集 |
| 第三层 | component.mbt, component_params.mbt, derived_components.mbt, field_components.mbt | 覆盖组件解析与取值 |
| 第四层 | signature_base.mbt | 签名基构造 |
| 第五层 | algorithm.mbt, hmac_sha256.mbt, constant_time.mbt, base64_value.mbt | 算法抽象与 HMAC-SHA256 |
| 第六层 | key_resolver.mbt, clock.mbt, nonce_store.mbt, verification_policy.mbt, digest_binding.mbt | 验证策略 |
| 第七层 | signer.mbt, verifier.mbt, cmd/httpsig-tool, examples, adapters/http11 | 用户接口 |

## 消息模型

`OrderedHeaders` 按线序保存 `HeaderField { name, value, trailer }`，保留同名
多值、Header/Trailer 区分与原始值（含内部空格）。`RequestContext` 持有
method/scheme/authority/path/query/headers/body；`ResponseContext` 额外持有
可选的 `related_request` 以支持 `req`。构造时执行完整校验（方法 token、
scheme 语法、CR/LF 卫生、Body 大小限制）。

## Structured Field 子集

`SfCursor` 扫描输入，`parse_sf_dictionary` 等解析出 `SfDictionaryEntry` /
`SfItem` / `SfInnerList` / `SfBareItem` 树，`serialize_sf_dictionary` 等按
RFC 9651 §4.2 规范序列化。顺序（字典顺序、内表顺序、参数顺序）被完整保留，
这是签名基逐字节可复现的前提。所有解析函数在失败时 `raise HsError`；公共
边界用 `try/catch` 转成 `Result[T, HsError]`。

## 组件解析

`CoveredComponent::Derived(DerivedComponent, ComponentParameters)` 与
`CoveredComponent::Field(FieldComponent)`。`parse_covered_component` 把一个
覆盖组件字符串（如 `"@method"`、`"content-type";sf`、`"@query-param";name="pet"`）
解析成模型，并执行组合规则校验（name 仅限 @query-param、key 需要 sf、
sf 与 bs 互斥、派生组件仅允许 req 等）。`resolve_component` 依据 `SignTarget`
（请求或响应）解析出规范字符串值。

## 签名基

`build_signature_base` 按覆盖组件原顺序生成每一行
`"组件标识": 值`，以 LF 结尾，最后追加
`"@signature-params": (覆盖组件);参数` 且**不带**尾部换行。组件标识按
RFC 9421 §2.5 序列化为 sf-string（带双引号）。`@signature-params` 的值与
`Signature-Input` 字段的序列化严格一致。

## Algorithm Provider

`SignatureAlgorithm` trait（`name`/`sign`/`verify`）与可持有的
`SignatureAlgorithmProvider` 联合类型。内置 `HmacSha256`；未实现算法映射到
`UnsupportedAlgorithm`，sign/verify 一律返回 `AlgorithmNotAllowed`。

## Verifier

`verify_target` 依次：解析两个字段、校验标签一致、逐个标签执行廉价检查
（参数结构、算法白名单、时间、required components、keyid）→ key 解析 →
签名基构造 → 密码学验签 → nonce → Content-Digest，最后按
`MultiSignaturePolicy` 判定总体结果，产出 `VerificationReport`。

## Policy

`VerificationPolicy` 编码应用层要求；`Clock` 抽象时间来源（`SystemClock` /
`FixedClock`）；`NonceStore` 抽象防重放存储；`DigestBinding` 抽象 Body 绑定。
核心库不联网解析 keyid，不自动访问 URL / JWKS / DID。

## Digest Binding

`validate_content_digest` 解析 `Content-Digest`（RFC 9651 Dictionary），
对 `sha-256` 用 `sha256_raw(body)` 常量时间比对；不支持的其他算法按
RFC 9530 §3 忽略；要求 digest 字段被覆盖组件包含。
