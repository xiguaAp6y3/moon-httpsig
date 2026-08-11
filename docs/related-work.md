# 相关工作与边界声明

## 本项目不复制其他实现

本项目从零实现 RFC 9421，未复制、翻译或改写任何其他语言的 HTTP Message
Signatures 实现源码。使用的内容包括：

- RFC 9421 中的公开算法、测试密钥、签名基与 HMAC 测试结果；
- 官方登记的参数名与组件名；
- 成熟 SHA-256 依赖（`gmlewis/sha256`，Apache-2.0）。

## 相关规范

- RFC 9421 — HTTP Message Signatures（主标准）
- RFC 9530 — Digest Fields（Content-Digest）
- RFC 9651 — Structured Field Values for HTTP
- RFC 9110 — HTTP Semantics
- RFC 2104 — HMAC（HMAC 构造）
- IANA HTTP Message Signature Registry

## 与本库无关的实现

- JWT / JWS / JWE；
- HTTP 服务器与客户端；
- TLS；
- 通用密码学库（OpenSSL、BoringSSL 等）；
- 旧版 Cavage HTTP Signatures Draft。

## 生态检索声明

截至项目立项时的公开生态检索，未发现完整的 MoonBit RFC 9421 HTTP Message
Signatures 实现。**这不是绝对保证**，仅代表立项时检索到的公开信息。
