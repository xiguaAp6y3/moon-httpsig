# 安全说明

使用本库前请阅读以下条目。它们大多来自 RFC 9421 §7（Security
Considerations），另有一些是本库的工程约束。

1. **HTTP 消息签名不提供加密**。它只提供消息完整性与（对共享密钥/公钥的）
   签名来源证据，不保护消息内容不被读取。
2. **TLS 仍然必须使用**。签名不能替代 TLS；传输保密性由 TLS 提供。
3. **验签成功不等于用户已授权**。验签只证明“知道密钥的一方对该组件集
   签过名”；是否授权由应用根据 keyid、tag、业务上下文决定。
4. **keyid 不是可信身份**。keyid 只是查找密钥的标识；把 keyid 当身份是
   常见错误。
5. **不允许算法降级**。不要在同一消息上接受“先用强算法、再退化为弱算法”
   的组合；使用算法白名单。
6. **必须设置算法白名单**。`VerificationPolicy::allowed_algorithms` 应只
   列出业务允许的算法。
7. **必须验证 created 和 expires**。至少要求 `created` 存在，并按
   `expires` / `max_signature_age_seconds` 校验时效；否则消息可被长期重放。
8. **高风险请求应使用 nonce**。对幂等性要求高的操作，用 `nonce` + 共享
   `NonceStore` 防止单次请求被重复提交。
9. **多节点环境需要共享 NonceStore**。`InMemoryNonceStore` 只用于单进程
   测试/示例；生产环境应使用 Redis、数据库或分布式共享存储。
10. **Body 需要 Content-Digest 绑定**。消息签名默认不覆盖 Body；只有
    `Content-Digest` 存在、已验证且被覆盖组件包含时，Body 才被绑定。
11. **未覆盖 Header 可以被修改**。签名只保护覆盖组件；中间人可改未覆盖的
    Header 而不破坏签名。
12. **Header 合并语义可能影响签名**。多个同名字段按 `", "` 合并；若中间人
    合并空白，签名可能失效。建议签名的字段只出现单行，或用 `sf` 严格序列化。
13. **不自动访问 keyid URL**。keyid 形如 URL 时，本库只把它当作查找键，
    从不联网获取。
14. **网络 Key Resolver 可能产生 SSRF**。若你自行实现远程 resolver，必须
    加白名单与超时；核心库默认不提供网络 resolver。
15. **不能把旧版 Draft 当作 RFC 9421**。两者字段名与签名基格式不同，混用会
    产生互操作与安全错误。
16. **HMAC 是共享密钥方案**。签名与验签用同一个秘密；泄露任一方即泄露全部。
17. **HMAC 不提供公钥验证**。它不能证明“不可抵赖”的发送方身份；需要非对称
    能力时应使用 Ed25519 等（本库尚未实现）。
18. **错误信息不能泄漏密钥**。`HsError.context` 只含简短描述，不含密钥、
    完整签名、完整 Body 或巨大 Header。
19. **先做格式检查，再做密码学**。verifier 的检查顺序确保廉价检查先行，
    避免对畸形输入做无谓的密码计算。
20. **inspect 不等于 verify**。CLI `inspect` 只做解析，不做验签。
21. **parse 不等于 verify**。解析 Signature-Input/Signature 成功不代表签名
    有效。
22. **signature base 可能包含敏感 Header**。签名基可能含 Cookie、Authorization
    等值；调试输出不要在生产环境打印。
23. **调试模式不应在生产环境记录完整签名基**。日志中记录签名基等于记录敏感
    字段明文。
24. **Content-Digest 验证成功不代表业务授权**。digest 只证明 Body 未被篡改，
    不代表请求被授权。
25. **nonce 和时间策略由应用决定**。本库提供机制，是否开启由
    `VerificationPolicy` 与应用配置决定。
