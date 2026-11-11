# Roadmap

以下为未来计划，尚未完成。

## v0.1.2（当前版本）

- 适配 MoonBit `0.1.20261104` 工具链（`Array(capacity=...)`、`exact_view`、
  显式 `pub extend`、`moon fmt` 新规则）；
- 公开 API 与签名/验签行为保持不变；
- 新增 README 用法示例的可运行版本 `examples/readme_snippets`；
- README 记录已验证工具链基线，并补充工具链兼容性与支持范围说明。

## v0.1.1

- 保持 v0.1.0 的 RFC 9421 功能边界；
- 适配当前 MoonBit 编译器的显式 Trait 方法调用；
- 增加四目标严格验证和 GitHub Actions CI。

## v0.1.0（基础版本）

- RFC 9421 核心：消息模型、Structured Field 子集、组件解析、签名基；
- HMAC-SHA256 签名/验签与常量时间比较；
- 验证策略（白名单/时间/required/keyid/nonce/tag）；
- CLI `httpsig-tool`；
- 101 个具名测试、91 个表格案例、1100 组属性测试、RFC B.2 逐字节向量；
- HTTP/1.1 文本适配器与 6 个示例。

## v0.2.0

- 完整 RFC 9651 Adapter（支持 Decimal、List 全量、严格序列化边界）；
- 更多 HTTP 框架适配器（视生态可用框架而定）。

## v0.3.0

- Ed25519 Provider（基于成熟依赖）；
- 远程 Key Resolver 示例（带白名单与超时，避免 SSRF）。

## v0.4.0

- Webhook / ActivityPub / API Gateway Profile 应用层封装。

> 这些条目**尚未完成**，仅作为后续规划；本阶段交付 v0.1.2。
