# 规范-源码-测试映射

| RFC 9421 章节 | 源码 | 测试 |
| --- | --- | --- |
| §2.1 HTTP Fields | ascii.mbt, field_components.mbt, ordered_headers.mbt | field_components_test.mbt, ordered_headers_test.mbt, transformation_test.mbt |
| §2.1.1 sf | field_components.mbt | field_components_test.mbt |
| §2.1.2 key | field_components.mbt | field_components_test.mbt |
| §2.1.3 bs | field_components.mbt | field_components_test.mbt |
| §2.1.4 tr | field_components.mbt | field_components_test.mbt, negative_matrix_test.mbt |
| §2.2 Derived Components | derived_components.mbt, message.mbt | derived_components_test.mbt |
| §2.2.7 @query | message.mbt | derived_components_test.mbt |
| §2.2.8 @query-param | derived_components.mbt | derived_components_test.mbt |
| §2.2.9 @status | derived_components.mbt | derived_components_test.mbt, response_test.mbt |
| §2.3 Signature Parameters | signature_params.mbt | signature_input_test.mbt, policy_test.mbt |
| §2.4 req | derived_components.mbt, field_components.mbt | response_test.mbt |
| §2.5 Signature Base | signature_base.mbt, component.mbt | signature_base_test.mbt, rfc9421_examples_test.mbt |
| §3.1 Creating | signer.mbt | signing_test.mbt |
| §3.2 Verifying | verifier.mbt | verification_test.mbt |
| §3.3 Algorithms | algorithm.mbt, hmac_sha256.mbt | hmac_sha256_test.mbt |
| §4.1 Signature-Input | signature_input.mbt | signature_input_test.mbt |
| §4.2 Signature | signature_field.mbt | signature_field_test.mbt |
| §4.3 Multiple | verifier.mbt | verification_test.mbt, examples/multiple_signatures |
| §5.1 Accept-Signature | accept_signature.mbt | accept_signature_test.mbt |
| §7 Security | docs/security.md | negative_matrix_test.mbt |
| App. B Test Vectors | testdata/rfc9421 | rfc9421_examples_test.mbt |

| RFC 9651 章节 | 源码 | 测试 |
| --- | --- | --- |
| §3.2 Dictionary | sf_parser.mbt | structured_field_test.mbt |
| §3.1 Inner List | sf_parser.mbt | structured_field_test.mbt |
| §4.2 Serialization | sf_serializer.mbt | structured_field_test.mbt |
| §4.2.1 String/Token | sf_parser.mbt, sf_serializer.mbt | structured_field_test.mbt |
| §4.2.4 Byte Sequence | sf_parser.mbt | structured_field_test.mbt |

| RFC 9530 章节 | 源码 | 测试 |
| --- | --- | --- |
| §3 Digest Fields | digest_binding.mbt | digest_binding_test.mbt |

| RFC 9110 章节 | 源码 | 测试 |
| --- | --- | --- |
| §5.1 字段名 | ascii.mbt | ordered_headers_test.mbt |
| §5.2 组合值 | ordered_headers.mbt | ordered_headers_test.mbt |
