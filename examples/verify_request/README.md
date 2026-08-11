# verify_request

Signs a request, verifies it with a `FixedClock` and an in-memory key
resolver, then shows that changing a covered header breaks the signature.

Run:

```sh
moon run examples/verify_request
```
