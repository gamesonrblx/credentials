# Contributing

Credentials is pre-alpha. The encryption design lives in [docs/ENCRYPTION.md](docs/ENCRYPTION.md). Implementation should follow that document. Do not invent a cipher, a key-encapsulation scheme, or a hybrid combiner.

## Build and test

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo deny check` runs in CI and checks dependency advisories and licenses.

## Pull requests

- Keep changes focused.
- Add tests for crypto and authorization changes. A bit flip, a swapped associated-data binding, a revoked token, and a failed audit append should keep failing closed.
- Do not commit secret values, tokens, cloud credentials, or generated dev key files (`.credentials-dev-keys.json`).
- The dev KMS is for local runs and tests. Production key storage belongs behind `RootKeyProvider` in a KMS or HSM.

Apache-2.0. See [LICENSE](LICENSE).
