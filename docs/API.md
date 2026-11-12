# Credentials HTTP API

Status: public pre-alpha. This document describes the routes in the tree. The project has no customers and no certification.

The dev gateway opens `wrap_mode = gateway` rows. That process rejects `CREDENTIALS_ENV=production`. The caller seals `wrap_mode = e2e` rows. `POST /v1/inject` returns ciphertext for those rows. The process does not open them. `credentials-injector` holds the decapsulation key. Loss of every recovery recipient destroys the data. The operator cannot rebuild the key.

The machine-readable route list is [openapi.yaml](openapi.yaml). Names, scopes, and errors follow [ENCRYPTION.md](ENCRYPTION.md).

## Callers

The control plane holds the workspace credential. It creates secrets, agents, and sessions. The runner holds a short agent token and a DPoP key. Keep the workspace credential out of the model loop.

`POST /v1/workspaces` on the loopback dev listener has no authentication. Do not expose that listener beyond the local machine.

Admin routes use `Authorization: Bearer` and the workspace credential. Inject uses the agent token and a `DPoP` header. Inject rejects the workspace credential.

## Delivery

`proxy` is the delivery mode on the public listener. The gateway calls an `https` URL. It sets the policy header. It does not follow a redirect. It does not copy that header into the response. The public listener rejects `env` and `header`.

Set `CREDENTIALS_LOCAL_DIR` for a process on the same machine. The gateway creates that directory with mode `0700`. The socket `credentials.sock` has mode `0600`. The gateway accepts a peer only when the uid matches. `env` returns base64 of `{ "env_name", "value" }`. `header` returns base64 of `{ "header_name", "value" }`. Header delivery does not call the upstream host.

DPoP `htu` is the request URL from the `Host` header. The server ignores `x-dpop-htu`.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/v1/workspaces` | none on the loopback dev listener |
| `POST` | `/v1/secrets` | workspace credential |
| `POST` | `/v1/e2e-secrets` | workspace credential; ciphertext only |
| `POST` | `/v1/workspace-keys` | workspace credential; encapsulation key only |
| `POST` | `/v1/recovery-recipients` | workspace credential; wraps only |
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

`{name}` can contain slashes. Example: `prod/openai/api_key`.

`GET /v1/audit` returns each event hash and the previous hash. It can return the latest checkpoint signature. It does not return a secret value.

A disabled secret fails inject before a key unwrap. The ciphertext remains until you delete the secret or the workspace.
