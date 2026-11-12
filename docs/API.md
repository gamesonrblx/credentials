# Credentials HTTP API

Status: public pre-alpha. This is the integrator surface of the gateway that is in the tree today. It makes no claim of customers, SOC 2, or any certification.

`wrap_mode = gateway` rows are decrypted inside this process. That path is the dev gateway. It refuses `CREDENTIALS_ENV=production`. `wrap_mode = e2e` rows are sealed by the caller. `POST /v1/inject` returns ciphertext for those rows and does not unwrap them. The customer injector (`credentials-injector`) holds the decapsulation key. This is not an attested enclave. Losing every recovery recipient loses the data, and the operator cannot reconstruct it.

The machine-readable description of these routes is [openapi.yaml](openapi.yaml). Names, scopes, and errors follow [ENCRYPTION.md](ENCRYPTION.md).

## Who calls what

A control plane holds the workspace credential. It creates secrets, agents, and sessions. A runner holds a short-lived agent token and a DPoP key. The model loop should not hold the workspace credential.

`POST /v1/workspaces` on the loopback dev listener is unauthenticated so a local process can bootstrap. Do not expose that listener beyond loopback.

Admin routes use `Authorization: Bearer <workspace credential>`. Inject uses the agent token plus a `DPoP` header. The workspace credential is not accepted on inject.

## Delivery

`proxy` is the delivery mode on the public listener. The gateway calls an `https` URL, sets the policy header itself, does not follow redirects, and does not copy that header back. `env` and `header` are refused on this listener.

A process on the same machine can set `CREDENTIALS_LOCAL_DIR`. The gateway creates that directory mode `0700` and listens on `credentials.sock` mode `0600`. It accepts a connection only when the peer uid matches the gateway uid. That socket speaks the same routes. `env` returns a body whose decoded bytes are `{ "env_name", "value" }`. `header` returns `{ "header_name", "value" }` and does not call the upstream. The HTTP `body` field is standard base64 of those bytes, same as a proxy response.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/v1/workspaces` | none on the loopback dev listener |
| `POST` | `/v1/secrets` | workspace credential |
| `POST` | `/v1/e2e-secrets` | workspace credential. Ciphertext only. A `value` field is rejected. |
| `POST` | `/v1/workspace-keys` | workspace credential. Encapsulation key only. |
| `POST` | `/v1/recovery-recipients` | workspace credential. Wraps only. `operator` is not a kind. |
| `POST` | `/v1/secrets/{name}/versions` | workspace credential |
| `POST` | `/v1/secrets/{name}/disable` | workspace credential |
| `POST` | `/v1/agents` | workspace credential |
| `POST` | `/v1/agent-sessions` | workspace credential |
| `GET` | `/v1/agent-sessions` | workspace credential |
| `POST` | `/v1/agent-sessions/{id}/revoke` | workspace credential |
| `POST` | `/v1/inject` | agent token and DPoP |
| `GET` | `/v1/audit` | workspace credential |
| `POST` | `/v1/kek/rotate` | workspace credential |
| `POST` | `/v1/workspaces/{id}/deletion` | workspace credential |
| `POST` | `/v1/workspaces/{id}/deletion/cancel` | workspace credential |

`{name}` may contain slashes, as in `prod/openai/api_key`.

`GET /v1/audit` returns each event's hash and previous hash so a client can recompute the chain, plus the latest checkpoint signature when one exists. It does not return secret values.

A disabled secret fails inject before any key unwrap. The ciphertext stays until the secret or the workspace is deleted.
