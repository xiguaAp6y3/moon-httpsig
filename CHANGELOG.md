# Changelog

## 0.1.2 — 2026-11-11

工具链兼容性复验版：在 `moon 0.1.20261104` / `moonc v0.10.20+65efd5b93` 上复验并通过
全部检查、构建与测试；公开 API 与签名/验签行为未变。

### Added

- `examples/readme_snippets/`：README「使用示例」四个片段（请求签名、请求验签、
  响应签名、多签名）的完整可编译版本，CI 与 `scripts/verify_all.ps1` 都会运行它，
  从而在公开 API 变化时及时发现 README 失效。
- README 的用法示例改为自包含代码：补齐了 `request`/`key`/`params`/`resolver`
  等变量的定义，并修正了原先用占位符 `sig1=:...:` 导致无法执行的 `verify-hmac`
  CLI 示例。
- README 新增「已验证的工具链」「工具链兼容性说明」「支持范围与限制」三节。

### Changed

- `Array::new()` → `Array(capacity=0)`（66 处，`Array::new()` 已 deprecated）。
- `StringView::sub(...)` → `exact_view(...)`（2 处，`sub` 已 deprecated）。
- 跨 `impl` 的隐式方法提升改写为显式 `pub extend`（10 处），适配
  `implicit_impl_as_method` 告警及其后续移除计划。
- 按新工具链的 `moon fmt` 规则重新格式化（`Int` → `Int32`、结构体字面量补尾逗号，
  涉及 52 个文件）。
- `moon.mod`：移除未使用的 `moonbitlang/core/strconv` 依赖；`warnings` 中显式关闭
  `result_error_return` 与 `test_unqualified_package`（理由见 README
  「工具链兼容性说明」）。

### Verified

- `moon check/build/test --target all --deny-warn` 四目标全部通过，101 个测试全绿。
- `moon fmt --check`、`moon info`、`moon package --list`、7 个示例、CLI smoke 测试、
  RFC 9421 fixture 校验（`scripts/verify_rfc_fixtures.py`）全部通过。

## 0.1.1 — 2026-08-21

- Updated trait method dispatch for the current MoonBit compiler without changing signing or verification behavior.
- Added warning-free four-target checks, GitHub Actions CI, and stricter reproducible verification.
- Refreshed final-acceptance documentation and public release metadata.

## 0.1.0

Initial implementation of RFC 9421 HTTP Message Signatures for MoonBit.

### Added

- HTTP message model: `RequestContext`, `ResponseContext`, `OrderedHeaders`,
  Header/Trailer distinction, raw URL components, body bytes.
- RFC 9651 structured-field subset: Dictionary, Inner List, Item, Parameters,
  canonical parsing and serialization.
- Covered-component resolution: `@method`, `@target-uri`, `@authority`,
  `@scheme`, `@request-target`, `@path`, `@query`, `@query-param`, `@status`,
  field components with `sf`/`bs`/`key`/`tr`/`req`.
- Byte-exact signature-base construction (RFC 9421 §2.5).
- HMAC-SHA256 provider (RFC 2104) over `gmlewis/sha256`; constant-time MAC
  comparison.
- Verification policy, replay protection (`NonceStore`), RFC 9530
  Content-Digest binding, multi-signature policies.
- `httpsig-tool` CLI with stable JSON output.
- Six runnable examples.
- HTTP/1.1 text adapter.
- Test suite: 101 named tests, 91 table-driven cases, 1100 deterministic
  property cases, RFC 9421 Appendix B byte-exact vectors.

### Notes

- Algorithms other than `hmac-sha256` are recognized but not implemented;
  they return `AlgorithmNotAllowed`.
- Module namespace is `xiguaAp6y3/moon-httpsig` (renamed from the temporary
  `localdev/moon-httpsig`); see `docs/renaming.md`.
