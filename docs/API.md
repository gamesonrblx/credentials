# Credentials HTTP API

Status: public pre-alpha. This is the integrator surface of the gateway that is in the tree today. It makes no claim of customers, SOC 2, or any certification.

This gateway can read secret plaintext. It unwraps keys and decrypts inside the process that serves `/v1/inject`. That is not zero-knowledge against the operator. A production self-host or hosted deployment must not decrypt. That split is later work.

The machine-readable description of these routes is [openapi.yaml](openapi.yaml). Names, scopes, and errors follow [ENCRYPTION.md](ENCRYPTION.md).

## Who calls what

A control plane holds the workspace credential. It creates secrets, agents, and sessions. A runner holds a short-lived agent token and a DPoP key. The model loop should not hold the workspace credential.

`POST /v1/workspaces` on the loopback dev listener is unauthenticated so a local process can bootstrap. Do not expose that listener beyond loopback.

Admin routes use `Authorization: Bearer <workspace credential>`. Inject uses the agent token plus a `DPoP` header. The workspace credential is not accepted on inject.

## Delivery

`proxy` is the delivery mode on the public listener. The gateway calls an `https` URL, sets the policy header itself, does not follow redirects, and does not copy that header back. `env` and `header` are refused on this listener.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/v1/workspaces` | none on the loopback dev listener |
| `POST` | `/v1/secrets` | workspace credential |
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
