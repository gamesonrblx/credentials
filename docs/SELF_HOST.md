# Self-host the control plane

Status: public pre-alpha. The project has no customers, no certification, and no production SLA.

`CREDENTIALS_ENV=production` starts a control plane that cannot unwrap secrets. The process rejects `CREDENTIALS_DEV_KEYS`, `CREDENTIALS_DEV_SIGNER`, and `CREDENTIALS_DEV_ANCHOR`. `prod` means the same as `production`. The process exits on a value it does not know, so a typo cannot start the dev gateway.

| Variable | Role |
| --- | --- |
| `CREDENTIALS_DATABASE_URL` | SQLite or Postgres URL. A Postgres URL needs `sslmode=require`, `verify-ca`, or `verify-full`. Use `verify-full` for a database on another host. |
| `CREDENTIALS_ALLOW_PLAINTEXT_DB` | Set to `1` to accept a Postgres URL without TLS. Use it only for a database on a private network. |
| `CREDENTIALS_PUBLIC_URL` | Required. The `https` origin that clients call, with no path. DPoP `htu` uses it. |
| `CREDENTIALS_SIGNING_KEY` | Seed file for token, audit, and grant signatures. It does not unwrap secrets. |
| `CREDENTIALS_AUDIT_ANCHOR` | Append-only file of checkpoint signatures. It is not object storage with a retention lock. |
| `CREDENTIALS_OPERATOR_TOKEN` | Required when `CREDENTIALS_LISTEN` is not loopback. At least 16 characters. The process refuses `change-me`. |
| `CREDENTIALS_LISTEN` | Socket address. |
| `CREDENTIALS_ISSUER` | Optional token issuer. |
| `CREDENTIALS_AUDIENCE` | Optional token audience. |
| `CREDENTIALS_TLS_CERT` | PEM certificate chain, leaf first. Required when `TLS_REQUIRE_HYBRID` is on. |
| `CREDENTIALS_TLS_KEY` | PEM private key. Required when `TLS_REQUIRE_HYBRID` is on. |

`POST /v1/secrets` with plaintext fails in production. Seal the value with your X-Wing key. Send it to `POST /v1/e2e-secrets`. Run `credentials-injector` in a separate process. Save the public key from `GET /v1/keys` and pass that file as `--control-plane-key`. `credentials-injector deliver` verifies the signed grant before it opens the secret. For a `proxy` grant it calls the upstream host and writes the response to `--out`. For a `header` or `env` grant it writes the value to a new file. On Unix that file mode is `0600`. The injector does not print the value. `credentials-injector import-dotenv` seals a `.env` file into request bodies for `POST /v1/e2e-secrets`.

`compose.yaml` is an example with Postgres 16. Set `CREDENTIALS_OPERATOR_TOKEN` and `CREDENTIALS_DB_PASSWORD` before you start it. Put `fullchain.pem` and `key.pem` in `./certs`. The gateway listens on port 8443. The bundled Postgres has no TLS. The file sets `CREDENTIALS_ALLOW_PLAINTEXT_DB=1` and keeps the database on an internal network. CI does not start this file. The injector service uses the `injector` profile. The control-plane container does not receive a decapsulation key.

Set `CREDENTIALS_TLS_CERT` and `CREDENTIALS_TLS_KEY` to PEM files. The listener uses TLS 1.3. The preferred group is `X25519MLKEM768` (4588). `TLS_REQUIRE_HYBRID=true` offers only that group. Production sets that flag on by default. The process exits when the certificate files are absent. A dev process leaves the flag off and can listen without TLS.

The production signing key is a local file. It signs tokens, audit tips, and grants. Each of the three signatures has its own prefix. It does not unwrap secret data keys. `credentials-edge` can call Vault Transit or AWS KMS from a customer process. Do not give that decrypt role to the hosted control plane.
