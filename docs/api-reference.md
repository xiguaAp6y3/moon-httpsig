# API 参考

所有公共 API 返回 `Result[T, HsError]`（失败为结构化错误，见下）。

## 消息模型

- `RequestContext::new(...)` / `new_default(...)` → `Result[RequestContext, HsError]`
- `ResponseContext::new(...)` / `new_default(...)`
- `RequestContext::target_uri / request_target / authority_component / path_component / query_component / raw_query / has_query`
- `OrderedHeaders::new / append / append_trailer / append_field / set / remove / get_first / get_all / contains / entries / header_values / trailer_values / combined_value / combined_value_with / length`

## Structured Field 子集

- `parse_sf_dictionary_string(input, limits)` → `Result[Array[SfDictionaryEntry], HsError]`
- `parse_sf_item_string` / `parse_sf_inner_list_string`
- `serialize_sf_dictionary / serialize_sf_item / serialize_sf_inner_list`
- `serialize_sf_string / serialize_sf_token / serialize_sf_integer / serialize_sf_boolean / serialize_sf_byte_sequence`
- `sf_string / sf_token / sf_integer / sf_boolean / sf_bytes`

## 组件

- `parse_covered_component(item)` / `parse_covered_components(items, max)`
- `resolve_component(component, target)` / `resolve_derived_component(...)` / `resolve_field_component(...)`
- `covered_derived / covered_derived_with_params / covered_field / covered_field_with_params`
- `CoveredComponent::identifier / to_component_string`
- `parse_component_parameters / serialize_component_parameters`

## 签名字段

- `parse_signature_input(input, limits)` → `Result[SignatureInput, HsError]`
- `serialize_signature_input(input)`
- `get_signature_input / append_signature_input / validate_signature_input`
- `parse_signature_field(input, limits)` / `serialize_signature_field`
- `get_signature / append_signature / validate_signature_labels`
- `parse_accept_signature / serialize_accept_signature`
- `parse_signature_parameters / serialize_signature_parameters`

## 签名基

- `build_signature_base(target, entry, limits)` / `build_request_signature_base` / `build_response_signature_base`
- `SignatureBase { bytes, text, lines }`

## 算法

- `trait SignatureAlgorithm`（`name` / `sign` / `verify`）
- `HmacSha256::new()`；`hmac_sha256(key, message)`；`sha256_raw(data)`
- `UnsupportedAlgorithm`；`algorithm_provider(name)`
- `KeyMaterial::{ SharedSecret(Bytes), ExternalKey(String) }`
- `constant_time_equal(a, b)`

## 策略

- `VerificationPolicy::{ hmac_only(), permissive() }`；字段含算法白名单、
  required components、require_created/expires/keyid/nonce、
  max_signature_age_seconds、allowed_clock_skew_seconds、
  max_future_seconds、expected_tag、reject_unknown_parameters、
  require_content_digest(_covered)
- `trait Clock`；`SystemClock` / `FixedClock`
- `trait KeyResolver`；`InMemoryKeyResolver`
- `trait NonceStore`；`InMemoryNonceStore`
- `trait DigestBinding`；`NoDigestBinding` / `RequireCoveredContentDigest` / `CallbackDigestBinding`
- `validate_content_digest(covered, headers, body, limits)`

## Signer / Verifier

- `sign_request(request, options, limits)` / `sign_response` / `sign_target`
- `SignOptions { label, components, parameters, algorithm, key }`
- `SignedFields { signature_input, signature, signature_base }`
- `verify_request / verify_response / verify_target / verify_label`
- `VerificationReport { verified, rejected }`
- `MultiSignaturePolicy::{ AnyValid, AllPresentValid, SpecificLabel(label) }`

## 辅助

- `Limits::{ default(), strict(), permissive_for_tests() }`
- `base64_encode_bytes / base64_decode_bytes / hex_encode_bytes / hex_decode_bytes`
- `library_version()`、`parse_int64_cli`、`parse_int_cli`

## 错误模型

- `HsErrorStage`：MessageConstruction、StructuredFieldParsing、
  SignatureInputParsing、SignatureFieldParsing、ComponentResolution、
  SignatureBaseConstruction、Signing、KeyResolution、PolicyValidation、
  CryptographicVerification、ReplayProtection、DigestBinding
- `HsErrorKind`：UnexpectedEnd、UnexpectedByte、InvalidHeaderName、
  InvalidHeaderValue、InvalidMethod、InvalidScheme、InvalidAuthority、
  InvalidPath、InvalidStatus、DuplicateLabel、MissingSignatureInput、
  MissingSignature、LabelMismatch、InvalidSignatureInput、
  InvalidSignatureField、InvalidAcceptSignature、InvalidCoveredComponent、
  UnsupportedDerivedComponent、UnsupportedComponentParameter、
  MissingComponent、InvalidComponentCombination、InvalidStructuredField、
  InvalidBase64、InvalidInteger、InvalidTimestamp、CreatedInFuture、
  SignatureExpired、SignatureTooOld、MissingKeyId、KeyIdTooLong、
  KeyNotFound、AlgorithmMissing、AlgorithmNotAllowed、AlgorithmMismatch、
  InvalidKeyMaterial、SignatureMismatch、MissingRequiredComponent、
  DuplicateNonce、NonceRequired、NonceTooLong、InvalidTag、
  ContentDigestRequired、ContentDigestNotCovered、ContentDigestInvalid、
  InputTooLarge、TooManyHeaders、TooManySignatures、TooManyComponents、
  TooManyParameters、SerializationFailure
- `HsError` 访问器：`stage()`、`kind()`、`offset()`、`context()`、
  `stage_name()`、`kind_name()`、`to_debug_string()`
