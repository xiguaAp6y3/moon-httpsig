# RFC 合规矩阵

状态取值：`Implemented and tested` / `Implemented but partially tested` /
`Adapter required` / `Not implemented` / `Out of scope`。

| RFC 章节 | 功能 | 源码文件 | 测试文件 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- |
| RFC 9421 §2.1 | 字段名小写、多值合并、OWS 处理 | field_components.mbt | field_components_test.mbt, transformation_test.mbt | Implemented and tested | |
| RFC 9421 §2.1.1 | sf 严格序列化 | field_components.mbt | field_components_test.mbt | Implemented and tested | |
| RFC 9421 §2.1.2 | Dictionary key 参数 | field_components.mbt | field_components_test.mbt | Implemented and tested | |
| RFC 9421 §2.1.3 | bs 二进制包装 | field_components.mbt | field_components_test.mbt | Implemented and tested | |
| RFC 9421 §2.1.4 | tr Trailer 取值 | field_components.mbt | field_components_test.mbt, negative_matrix_test.mbt | Implemented and tested | |
| RFC 9421 §2.2.1–2.2.8 | @method/@target-uri/@authority/@scheme/@request-target/@path/@query/@query-param | derived_components.mbt | derived_components_test.mbt | Implemented and tested | |
| RFC 9421 §2.2.9 | @status | derived_components.mbt | derived_components_test.mbt, response_test.mbt | Implemented and tested | |
| RFC 9421 §2.3 | 签名参数 created/expires/nonce/alg/keyid/tag/扩展 | signature_params.mbt | signature_input_test.mbt, policy_test.mbt | Implemented and tested | 序列化顺序固定 |
| RFC 9421 §2.4 | req 参数（响应引用相关请求） | derived_components.mbt, field_components.mbt | response_test.mbt | Implemented and tested | |
| RFC 9421 §2.5 | 签名基构造 | signature_base.mbt | signature_base_test.mbt, rfc9421_examples_test.mbt | Implemented and tested | 逐字节 |
| RFC 9421 §3.1 | 创建签名 | signer.mbt | signing_test.mbt, rfc9421_examples_test.mbt | Implemented and tested | |
| RFC 9421 §3.2 | 验证签名 | verifier.mbt | verification_test.mbt | Implemented and tested | |
| RFC 9421 §3.3.3 | HMAC Using SHA-256 | hmac_sha256.mbt | hmac_sha256_test.mbt | Implemented and tested | |
| RFC 9421 §3.3.1/2/4/5/6 | rsa-pss/rsa-v1_5/ecdsa/ed25519 | algorithm.mbt | hmac_sha256_test.mbt | Not implemented | 返回 AlgorithmNotAllowed |
| RFC 9421 §4.1 | Signature-Input 字段 | signature_input.mbt | signature_input_test.mbt | Implemented and tested | |
| RFC 9421 §4.2 | Signature 字段 | signature_field.mbt | signature_field_test.mbt | Implemented and tested | |
| RFC 9421 §4.3 | 多签名 | verifier.mbt | verification_test.mbt, multiple_signatures | Implemented and tested | |
| RFC 9421 §5.1 | Accept-Signature 字段 | accept_signature.mbt | accept_signature_test.mbt | Implemented and tested | 仅解析/序列化 |
| RFC 9421 §5.2 | Accept-Signature 处理 | — | — | Out of scope | 不实现自动协商 |
| RFC 9421 §6.x | IANA 注册表 | — | — | Out of scope | |
| RFC 9421 §7 | 安全考虑 | docs/security.md | negative_matrix_test.mbt | Implemented and tested | 见安全文档 |
| RFC 9421 App. B | 测试向量 | testdata/rfc9421, rfc9421_examples_test.mbt | rfc9421_examples_test.mbt | Implemented and tested | B.2.1–B.2.6 |
| RFC 9530 | Content-Digest | digest_binding.mbt, adapters/http11 | digest_binding_test.mbt | Implemented but partially tested | 支持 sha-256，忽略其他算法 |
| RFC 9651 | Structured Field Values | sf_parser.mbt 等 | structured_field_test.mbt | Implemented but partially tested | 子集：Dictionary/Inner List/Item/Parameters |
| RFC 9110 | HTTP Semantics | message.mbt, ascii.mbt | model_test.mbt | Implemented but partially tested | 字段名/合并规则子集 |
