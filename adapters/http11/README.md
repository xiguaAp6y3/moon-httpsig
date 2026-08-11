# adapters/http11

A generic HTTP/1.1 text adapter for moon-httpsig.

MoonBit's core distribution ships no HTTP framework, so this adapter works on
raw HTTP/1.1 message text instead of a third-party framework:

- `parse_http11_request` — parses a request line, header section, and body
  into the library's `RequestContext`.
- `format_http11_request` — formats a `RequestContext` back to wire text.
- `make_sha256_content_digest` — computes an RFC 9530 `Content-Digest` value.
- `attach_signature_headers` — appends `Signature-Input` and `Signature`
  headers without mutating the input message.
- `Http11Sha256DigestBinding` — a callback-style `DigestBinding` that
  validates `sha-256` digests against the body.

Tests: `moon test`
