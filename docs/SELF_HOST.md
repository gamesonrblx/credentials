# Self-hosting the control plane

Status: public pre-alpha. No SOC 2, customer, or certification claim. No production SLA.

`CREDENTIALS_ENV=production` starts a control plane that cannot unwrap secrets. It refuses `CREDENTIALS_DEV_KEYS`, `CREDENTIALS_DEV_SIGNER`, and `CREDENTIALS_DEV_ANCHOR`. It requires:

| Variable | Role |
| --- | --- |
| `CREDENTIALS_DATABASE_URL` | SQLite or Postgres URL. Postgres in this build is `sslmode=disable`. |
| `CREDENTIALS_SIGNING_KEY` | File for the token and audit signing seed. Not a secret-unwrapping key. |
| `CREDENTIALS_AUDIT_ANCHOR` | Append-only local file of checkpoint signatures. Not a retention-locked object store. |
| `CREDENTIALS_OPERATOR_TOKEN` | Required when `CREDENTIALS_LISTEN` is not loopback. |
| `CREDENTIALS_LISTEN` | Socket address. |
| `CREDENTIALS_ISSUER` | Optional token issuer. |
| `CREDENTIALS_AUDIENCE` | Optional token audience. |

`POST /v1/secrets` with plaintext fails. Callers seal with their own X-Wing key and `POST /v1/e2e-secrets`. `credentials-injector` holds the decapsulation key in a separate process and writes an opened value to a new file. On Unix that file is mode `0600`. The value is not printed.

`compose.yaml` is an example with Postgres 16. The database password in that file is for the example. The injector service is behind the `injector` profile so the control-plane container does not receive a decapsulation key.

Hybrid TLS group 4588 (`X25519MLKEM768`) is not negotiated by this build. Spec test 16 is not claimed. The listener is plain HTTP until a stack that can actually negotiate that group is wired.

There is no cloud KMS in this build. The production signing key is a local file. It signs tokens and audit tips. It does not unwrap secret data keys.
