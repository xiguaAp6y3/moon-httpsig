# sign_response

Signs a response covering `@status` and, via the `req` parameter, the related
request's method. Tampering with the status code breaks the signature.

Run:

```sh
moon run examples/sign_response
```
