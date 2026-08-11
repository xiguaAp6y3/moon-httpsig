# replay_policy

Demonstrates nonce-based replay protection: a signature carrying a nonce is
accepted once, a second presentation is rejected, and the same nonce under a
different keyid is allowed. The in-memory store is single-process only.

Run:

```sh
moon run examples/replay_policy
```
