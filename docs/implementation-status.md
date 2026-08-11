# 实现状态

## 已完成

- HTTP 消息模型（Request/Response/OrderedHeaders/Header/Trailer/Body）；
- Structured Field 子集解析与规范序列化；
- 覆盖组件解析（派生 + 字段 + sf/bs/key/tr/req 参数）；
- 签名基构造（逐字节）；
- HMAC-SHA256 与常量时间比较；
- 验证策略、防重放、Content-Digest 绑定、多签名策略；
- Signer / Verifier；
- CLI（11 个子命令）；
- 6 个可执行示例；
- HTTP/1.1 文本适配器；
- RFC 9421 Appendix B 测试向量（HMAC 与签名基逐字节）；
- 101 个具名测试、91 个表格案例、1100 组属性测试；
- `wasm-gc` / `js` / `native` 三目标 check/build/test 全部通过；
- 行数统计脚本、RFC fixture 生成/校验脚本、一键验证脚本。

## 部分完成

- RFC 9651 仅实现本库所需子集（无 Decimal、无 List 顶层）。
- RFC 9530 仅支持 `sha-256` digest；其他算法按规范忽略。
- HTTP/1.1 适配器为文本适配，未对接具体 HTTP 框架（MoonBit 核心库无框架）。

## 未完成

- rsa-pss-sha512、rsa-v1_5-sha256、ecdsa-p256-sha256、ecdsa-p384-sha384、
  ed25519 算法（返回 `AlgorithmNotAllowed`，不提供假验签）；
- 远程 Key Resolver / JWKS / DID（按设计禁止，核心库不联网）；
- Accept-Signature 自动协商（仅解析/序列化）。

## 阻塞

- 无。三目标本机工具链完整，全部通过。

## 风险

- 参数序列化顺序固定为 `created, expires, keyid, nonce, alg, tag,
  extensions`；与 RFC 示例（created/keyid/nonce/tag 顺序）一致，但与
  其他实现的自选顺序可能互操作受限；
- `reserved_keyword` 警告被抑制（因规范要求字段名 `method`）；
- HMAC 密钥分发与共享存储（NonceStore）由应用负责；
- 属性测试覆盖派生/字段组件组合，但不覆盖全部非法组合枚举。
