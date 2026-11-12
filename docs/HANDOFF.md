# Handoff

This file is the current state of the repository. Read it before you change the trust model.

## Current state

Milestones M0 through M6 are in this tree.

M0 is the encryption specification and the Rust workspace.

M1 stores secret versions in SQLite and in Postgres. It shreds a workspace. It signs the audit tip.

M2 publishes the HTTP API. It requires an operator token when the listener is not loopback. It delivers `env` and `header` only on the local socket.

M3 seals an end-to-end secret as CRD2. The production control plane releases ciphertext. The injector opens that ciphertext.

M4 starts the production control plane. `CREDENTIALS_ENV=production` rejects the dev key file, the dev signer, and the dev audit anchor.

M5 describes the hosted control plane. No hosted service is live. The hosted process is the same control plane as M4.

M6 has one-shot import readers, a dashboard that does not decrypt, OIDC login, and a passkey ceremony. SAML is not in the tree.

## Architecture

The control plane stores ciphertext, policy, tokens, and the audit log.

The customer holds the decapsulation key. The injector opens an end-to-end secret outside the control plane.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the process split. Read [ENCRYPTION.md](ENCRYPTION.md) for the key hierarchy. Read [ROADMAP.md](ROADMAP.md) for the milestone order.

## Build, test, and run

Install Rust 1.89 or a later stable release.

Clone the repository. Then run these commands from the repository root.

```sh
cargo test --workspace --locked
cargo run -p credentials-gateway
```

The dev gateway listens on `127.0.0.1:8080`. Keep that port on the local machine.

Set `CREDENTIALS_ENV=production` to start the control plane that cannot unwrap. That mode requires `CREDENTIALS_SIGNING_KEY`, `CREDENTIALS_AUDIT_ANCHOR`, `CREDENTIALS_DATABASE_URL`, and `CREDENTIALS_PUBLIC_URL`. It also requires `CREDENTIALS_TLS_CERT` and `CREDENTIALS_TLS_KEY` unless `TLS_REQUIRE_HYBRID` is off. Read [SELF_HOST.md](SELF_HOST.md) for each variable.

The GitHub Actions workflow `.github/workflows/ci.yml` runs format, Clippy, tests, and `cargo deny` on Linux, macOS, and Windows.

The `integration` job runs on `ubuntu-latest`. It starts these containers.

- Postgres 16 on port 5432. The user, the password, and the database name are `credentials`.
- LocalStack 3 on port 4566. The service is KMS.
- MinIO from `cgr.dev/chainguard/minio:latest` on port 9000. The root user and the root password are `minioadmin`.
- Vault 1.18 in dev mode on port 8200. The root token is `root`.
- Dex v2.41.1 on port 5556. The client id is `credentials`. The client secret is `secret`.

Set `CREDENTIALS_INTEGRATION=1` and the `CREDENTIALS_TEST_*` URLs from that job. Then run this command.

```sh
cargo test -p credentials-edge --locked --test live --test fixtures -- --test-threads=1
```

## Security invariants

Do not break these rules.

The operator of the hosted control plane must not obtain plaintext or an unwrapped key. `Gateway::control_plane` uses `RejectingRootKeys`. `unwrap_kek` returns before a KMS call when `unwrap_secrets` is false.

Do not add an operator recovery recipient. Recovery is a customer device, a passkey PRF output, a recovery kit, or a teammate.

Write the allow event before you open a secret. If that write fails, do not decrypt. A lagged audit anchor stops inject.

Check `revoked_jtis` on every inject request. A revoked `jti` is an authentication failure.

Bind each DPoP proof to the request method, the request URI, and the access token. Reject a proof `jti` that the store has already claimed.

Sign every end-to-end release. The injector verifies the grant signature before it reads a grant field. It rejects an unsigned grant. Change the grant format in the gateway and in the injector together. `crates/injector/tests/gateway_grant.rs` links both and fails on drift.

Do not return a proxy response that contains the secret. Do not add `TRACE` or `CONNECT` to the method list.

## Gaps that need hardware or a paid account

A Nitro EIF, a vsock to the hypervisor, and a document that the AWS Nitro root signed need Nitro hardware. CI verifies a COSE_Sign1 ES384 document with a test root.

AWS KMS and AWS S3 Object Lock need an AWS account. CI uses LocalStack and MinIO.

## Other remaining work

SAML is not implemented.

The integration job does not call the hosted Infisical, Doppler, or 1Password APIs. Those readers are tested against local fixtures.

No hosted deployment is live.

M7 is still open. It decides the licence and the public name.

Revise [ENCRYPTION.md](ENCRYPTION.md) section 10. That section still draws the dev inject path. The production path releases ciphertext. It does not open the secret in the control plane.

Dependabot pull request #4 bumps `actions/checkout` from 4 to 7. It is not part of this stack.

## Open items from the security review

Pull request #28 fixed the findings of a full code review. The items below are still open. Do not report them as fixed.

### Review of the fix itself

No person has reviewed pull request #28. Agents wrote it. It changed about 8,400 lines in 72 files. CI passed on Linux, macOS, Windows, Postgres, and the container job. Read the gateway commit first. It changes what production inject returns and how workspace deletion works.

### Left on purpose

The audit chain is an unkeyed hash chain. A writer with database access can rebuild it. Detection rests on the signed checkpoints and on the anchor check that runs once for each workspace in each process. A keyed chain is a format change.

One Ed25519 key signs agent tokens, audit checkpoints, and grants. Each signature has its own prefix. The three uses do not have separate keys. An anchored tip carries no key id, so a signing-key rotation fails the anchor check. Add a key id to the anchor format before you rotate that key.

OIDC login does not verify the identity provider signature on the ID token. It checks the issuer, the audience, the expiry, and the nonce. The token comes from the token endpoint over TLS. Add JWKS verification before you accept an ID token from any other channel.

OIDC discovery is not cached. `/v1/login` allows 16 concurrent identity-provider calls and returns 503 above that.

`unwrap_kek` in the dev gateway makes a synchronous KMS call on an async thread. The production control plane does not reach that code.

The secret-in-response check compares exact bytes. It does not catch a base64 or URL-encoded copy. It skips a value shorter than 8 bytes. An allow-listed host is still inside the trust boundary.

The TLS listener has a handshake timeout and a header timeout. A slow request body after the headers has no timeout.

`Gateway::audit_log` still loads and verifies the whole chain. The HTTP route no longer calls it. Do not put it back on a request path.

`credentials-edge` holds adapters for AWS KMS, Vault Transit, S3 Object Lock, the import readers, WebAuthn, and Nitro attestation. Only OIDC is wired into the gateway. The other adapters run only in tests. The S3 adapter does not send a session token.

Nitro verification does not check revocation, key usage, or unknown critical extensions.

### Not verified

No one has run `docker compose up` with the new `compose.yaml` and `Dockerfile`. CI does not build the image. Check that the named volume is writable by uid 10001 and that the health check passes.

No real AWS Nitro document has gone through `verify_attestation`. The tests build the chain with a test root.

No test makes a real HTTPS call through `HttpUpstream::new` or through the injector `ReqwestTransport`. The tests use a local server or a recorder.

No test covers `serve_tls` from end to end. The accept retry, the timeouts, and the connection limit have no test. The 503 paths of the login handlers have no test.

Dex is the only identity provider that the login has run against.

### Repository settings

The `main` branch has no branch protection. Require the CI checks and one review before a merge.

## Defaults

An unset `CREDENTIALS_ENV` starts the dev gateway. The dev gateway can open a `wrap_mode=gateway` row. The process exits on a value other than `production`, `prod`, `development`, `dev`, or `test`.

`CREDENTIALS_LISTEN` defaults to `127.0.0.1:8080`. A listener that is not loopback requires `CREDENTIALS_OPERATOR_TOKEN` with at least 16 characters.

`TLS_REQUIRE_HYBRID` is on when `CREDENTIALS_ENV=production` and the variable is unset. The listener then offers only group 4588, `X25519MLKEM768`.

The dev key file is `.credentials-dev-keys.json`. The dev signer file is `.credentials-dev-signer.json`. The default database is a SQLite file beside the process.

OIDC login uses client id `credentials` when `CREDENTIALS_OIDC_CLIENT_ID` is unset. The redirect defaults to `<CREDENTIALS_PUBLIC_URL>/v1/login/callback`. Without that variable it uses the listen address.

The dashboard session cookie is not an inject credential. The OAuth `state` is not the PKCE verifier.

## Advisory ignores

`deny.toml` ignores two advisories. Do not widen that list.

`RUSTSEC-2026-0459` is the bundled SQLite in `sqlx` 0.8. The gateway creates its own database and does not open WAL mode. Remove the ignore when `sqlx` can take the patched `libsqlite3-sys`.

`RUSTSEC-2023-0071` is the Marvin timing leak in RSA private-key operations. `webauthn-rs` 0.6.2 pulls `rsa` 0.10.0-rc.19 through `crypto-glue`. The only call is `RS256VerifyingKey::verify` on a credential public key. This tree does not decrypt or sign with an RSA private key. `sqlx-mysql` pins `rsa` 0.9.10, and this workspace does not enable MySQL. Remove the ignore when `crypto-glue` depends on `rsa` 0.10.0 or a later release.

`webauthn-rs` is MPL-2.0. `deny.toml` allows that licence.

## Future work

The pstack skills are in `.cursor/skills`. The MIT licence is `.cursor/skills/pstack-LICENSE`. Attribution is `.cursor/skills/ATTRIBUTION.md`.

Use `poteto-mode` for the next change. Read `.cursor/skills/poteto-mode/SKILL.md` first.
