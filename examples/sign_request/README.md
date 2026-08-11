# sign_request

Signs a POST request with HMAC-SHA256, covering `@method`, `@target-uri`,
and a RFC 9530 `Content-Digest` computed over the request body.

```text
Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=...;keyid="local-key";alg="hmac-sha256"
Signature:       sig1=:...:
```

Run:

```sh
moon run examples/sign_request
```
