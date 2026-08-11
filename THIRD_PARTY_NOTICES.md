# Third-Party Notices

## Runtime dependency

- **gmlewis/sha256@0.17.32** — Apache-2.0. Used as the mature SHA-256 primitive
  for HMAC-SHA256 and Content-Digest. No code is copied from it; it is consumed
  as a dependency.

## RFC test data

- **RFC 9421 (HTTP Message Signatures)** — Appendix B test vectors, the public
  `test-shared-secret`, and the HMAC/Signature-Input/Signature/Signature-Base
  example values are used as test data. These are public standard text and are
  not copied from any third-party language implementation.
- **RFC 2104** — HMAC construction vectors used as test data.
- **RFC 9530 / RFC 9651 / RFC 9110** — referenced normative text only.

## Scope of this notice

This project does not copy, translate, or rewrite any third-party HTTP Message
Signatures implementation in another language. The use of RFC test data is
limited to validation of this implementation.
