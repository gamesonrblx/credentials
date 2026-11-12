# Self-host the control plane

Status: public pre-alpha. The project has no customers, no certification, and no production SLA.

`CREDENTIALS_ENV=production` starts a control plane that cannot unwrap secrets. The process rejects `CREDENTIALS_DEV_KEYS`, `CREDENTIALS_DEV_SIGNER`, and `CREDENTIALS_DEV_ANCHOR`.

| Variable | Role |
| --- | --- |
| `CREDENTIALS_DATABASE_URL` | SQLite or Postgres URL. This Postgres client uses `sslmode=disable`. |
| `CREDENTIALS_SIGNING_KEY` | Seed file for token signatures and audit signatures. It does not unwrap secrets. |
| `CREDENTIALS_AUDIT_ANCHOR` | Append-only file of checkpoint signatures. It is not object storage with a retention lock. |
| `CREDENTIALS_OPERATOR_TOKEN` | Required when `CREDENTIALS_LISTEN` is not loopback. |
| `CREDENTIALS_LISTEN` | Socket address. |
| `CREDENTIALS_ISSUER` | Optional token issuer. |
| `CREDENTIALS_AUDIENCE` | Optional token audience. |
| `CREDENTIALS_TLS_CERT` | PEM certificate. Required when `TLS_REQUIRE_HYBRID` is on. |
| `CREDENTIALS_TLS_KEY` | PEM private key. Required when `TLS_REQUIRE_HYBRID` is on. |

`POST /v1/secrets` with plaintext fails in production. Seal the value with your X-Wing key. Send it to `POST /v1/e2e-secrets`. Run `credentials-injector` in a separate process. The injector writes the opened value to a new file. On Unix that file mode is `0600`. The injector does not print the value.

`compose.yaml` is an example with Postgres 16. The password in that file is only an example. The injector service uses the `injector` profile. The control-plane container does not receive a decapsulation key.

Set `CREDENTIALS_TLS_CERT` and `CREDENTIALS_TLS_KEY` to PEM files. The listener uses TLS 1.3. The preferred group is `X25519MLKEM768` (4588). `TLS_REQUIRE_HYBRID=true` offers only that group. Production sets that flag on by default. The process exits when the certificate files are absent. A dev process leaves the flag off and can listen without TLS.

The production signing key is a local file. It signs tokens and audit tips. It does not unwrap secret data keys. `credentials-edge` can call Vault Transit or AWS KMS from a customer process. Do not give that decrypt role to the hosted control plane.
