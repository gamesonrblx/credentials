# Contributing

Credentials is pre-alpha. Follow [docs/ENCRYPTION.md](docs/ENCRYPTION.md). Do not invent a cipher, a KEM, or a hybrid combiner.

Project documents use ASD-STE-100 Simplified Technical English. Write short sentences. Use the active voice. Use one instruction in each procedure sentence. Keep articles. Use one meaning for each word. You may use API names, crate names, and algorithm names as technical nouns.

## Build and test

Run the tests:

```bash
cargo test --workspace
```

Check the format:

```bash
cargo fmt --all --check
```

Run Clippy:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

SQLite is the local database. macOS CI and Windows CI use SQLite. Ubuntu CI also starts Postgres.

Run the Postgres test on your machine:

```bash
CREDENTIALS_TEST_POSTGRES=postgres://credentials:credentials@localhost:5432/credentials?sslmode=disable \
  cargo test -p credentials-gateway --test durable
```

CI runs `cargo deny check`. That check covers advisories and licenses.

## Pull requests

- Keep each change small.
- Add a test for a crypto change or an access-control change.
- A changed bit, a wrong associated-data value, a revoked token, or a failed audit append must stop the operation.
- Do not commit secret values, tokens, cloud credentials, or `.credentials-dev-keys.json`.
- Use `RootKeyProvider` for production key storage. The dev key file is only for local runs and tests.

The license is Apache-2.0. Read [LICENSE](LICENSE).
