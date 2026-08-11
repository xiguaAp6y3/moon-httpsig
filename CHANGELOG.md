# Changelog

## 0.1.0-dev (unreleased)

Local, anonymous development build. Initial implementation of RFC 9421
HTTP Message Signatures for MoonBit.

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
- Test suite: 100 named tests, 200+ table cases, 1400 deterministic property
  cases, RFC 9421 Appendix B byte-exact vectors.

### Notes

- Algorithms other than `hmac-sha256` are recognized but not implemented;
  they return `AlgorithmNotAllowed`.
- Module name is the temporary `localdev/moon-httpsig`; see `docs/renaming.md`.
