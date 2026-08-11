# 测试矩阵

本文件由真实测试结果更新。执行：

```sh
moon test --target wasm-gc
moon test --target js
moon test --target native
```

## 结果（最近一次全量）

| 目标 | check | build | test | 具名测试 | 结果 |
| --- | --- | --- | --- | --- | --- |
| wasm-gc | 通过 | 通过 | 通过 | 101 | 0 failed |
| js | 通过 | 通过 | 通过 | 101 | 0 failed |
| native | 通过 | 通过 | 通过 | 101 | 0 failed |

## 覆盖维度

| 维度 | 测试文件 | 说明 |
| --- | --- | --- |
| HTTP 模型 | model_test.mbt | 方法/scheme/CRLF/status/Body 校验、target-uri 构造 |
| Ordered Headers | ordered_headers_test.mbt | 大小写、多值、组合、set/remove、trailer |
| Structured Field | structured_field_test.mbt | 字典/内表/项 roundtrip、拒绝表、边界 |
| Signature-Input | signature_input_test.mbt | 解析、序列化、重复标签、参数类型、扩展保留 |
| Signature | signature_field_test.mbt | 字节序列、拒绝非字节、标签校验 |
| Accept-Signature | accept_signature_test.mbt | 解析、序列化、请求标志 |
| 派生组件 | derived_components_test.mbt | @method/@path/@query/@query-param/@status/req |
| 字段组件 | field_components_test.mbt | sf/bs/key/tr/req、多值、OWS |
| 签名基 | signature_base_test.mbt | 逐字节、顺序、无尾部换行、重复组件 |
| HMAC | hmac_sha256_test.mbt | RFC 2104 向量、边界 key、provider sign/verify |
| 常量时间 | constant_time_test.mbt | 相等/首中尾字节不同/长度不同/空/大输入 |
| Signer | signing_test.mbt | RFC B.2.5 精确、不修改消息、算法白名单 |
| Verifier | verification_test.mbt | 报告、多签名策略、时间、标签 |
| Policy | policy_test.mbt | created/expires/keyid/nonce/tag/required/白名单 |
| Replay | replay_test.mbt | 首次成功、重放失败、不同 keyid、过期清理 |
| Response | response_test.mbt | 响应签名、req、篡改 status/related request |
| Transformation | transformation_test.mbt | 覆盖/未覆盖变更对签名的影响 |
| Digest Binding | digest_binding_test.mbt | digest 正确/篡改/缺失/未覆盖 |
| RFC 9421 B.2 | rfc9421_examples_test.mbt | B.2.1–B.2.6 签名基逐字节、B.2.5 HMAC |
| 负面矩阵 | negative_matrix_test.mbt | 31 项负面用例（见 compliance） |
| 属性测试 | property_test.mbt | 1100 组固定种子 sign→verify 循环 |
| Adapter | adapters/http11/adapter_test.mbt | HTTP/1.1 解析/格式化/附加头/digest |

## 表格案例计数

表驱动测试条目合计 91 个：structured_field 50、ordered_headers 8、
signature_input 7、negative_matrix 7、rfc9421_examples 6、
derived_components 9、model 4。

## 属性测试

固定种子 `0x5EED9421`，生成 1100 组：1000 组完整 sign→parse→rebuild→verify
→reserialize→reparse 循环（含 SI 序列化稳定性），100 组覆盖/未覆盖变更判定。
三目标结果一致。
