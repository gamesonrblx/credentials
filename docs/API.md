# Credentials HTTP API

Status: public pre-alpha. This document describes the routes in the tree. The project has no customers and no certification.

The dev gateway opens `wrap_mode = gateway` rows. That process rejects `CREDENTIALS_ENV=production`. The caller seals `wrap_mode = e2e` rows. `POST /v1/inject` returns ciphertext and a signed grant for those rows. The process does not open them. `credentials-injector` holds the decapsulation key. Loss of every recovery recipient destroys the data. The operator cannot rebuild the key.

The machine-readable route list is [openapi.yaml](openapi.yaml). Names, scopes, and errors follow [ENCRYPTION.md](ENCRYPTION.md).

## Callers

The control plane holds the workspace credential. It creates secrets, agents, and sessions. The runner holds a short agent token and a DPoP key. Keep the workspace credential out of the model loop.

`POST /v1/workspaces` on the loopback dev listener has no authentication. Do not expose that listener beyond the local machine.

Admin routes use `Authorization: Bearer` and the workspace credential. Inject uses the agent token and a `DPoP` header. Inject rejects the workspace credential.

## Delivery

`proxy` is the delivery mode on the public listener. The gateway calls an `https` URL. The URL has no user info and no port. The method is `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, or `DELETE`. The gateway sets the policy header. It sends the optional `content_type` field as `Content-Type`. It does not follow a redirect. It does not copy the policy header into the response. It stops after 30 seconds or after 8 MiB of response. It does not return a response that contains the secret or the header value. That check skips a value shorter than 8 bytes. The public listener rejects `env` and `header`.

A policy host is a public DNS name. The gateway rejects an IP address, `localhost`, a single-label name, and the suffixes `.localhost`, `.local`, `.internal`, `.lan`, and `.home.arpa`. The upstream client refuses a name that resolves to a loopback, private, or link-local address. The upstream client ignores proxy settings from the environment. The policy header name is an HTTP token. It is not `Host`, `Content-Type`, `Content-Length`, or another framing header. The `env_name` is a POSIX variable name.

Set `CREDENTIALS_LOCAL_DIR` for a process on the same machine. The gateway creates that directory with mode `0700`. The socket `credentials.sock` has mode `0600`. The gateway accepts a peer only when the uid matches. `env` returns base64 of `{ "env_name", "value" }`. `header` returns base64 of `{ "header_name", "value" }`. Header delivery does not call the upstream host.

DPoP `htu` is `CREDENTIALS_PUBLIC_URL` plus the request path. Production requires that variable. A dev gateway without it builds `htu` from the `Host` header. The server ignores `x-dpop-htu`.

## End-to-end grant

For a `wrap_mode = e2e` row, `POST /v1/inject` returns the ciphertext fields and three more fields. `grant` is base64 of a JSON object. `grant_signature` is base64 of an Ed25519 signature over the prefix `credentials.grant.v1`, a line feed, and the grant bytes. `grant_kid` names the signing key. `GET /v1/keys` returns the public key. Pin that key in the injector.

The grant states the workspace, the secret, the version, the workspace key, the agent, the secret name, and the delivery mode. It states `iat` and `exp`. The lifetime is 60 seconds. It holds the SHA-256 of the ciphertext. A proxy grant also holds the method, the URL, the host, the body hash, the content type, the header name, and the header format.

`credentials-injector deliver` verifies the signature before it reads the grant. It rejects an unsigned grant. For `proxy` it sends the request itself and writes only the upstream response. It applies the same method list, size limit, timeouts, and secret-in-response check as the gateway. For `header` and `env` it writes `{ "header_name", "value" }` or `{ "env_name", "value" }` to a new file. Those two modes hand the plaintext to the caller.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/v1/workspaces` | none on the loopback dev listener |
| `GET` | `/v1/keys` | none; public signing key only |
| `POST` | `/v1/workspaces/{id}/credential/rotate` | workspace credential |
| `POST` | `/v1/secrets` | workspace credential |
| `POST` | `/v1/e2e-secrets` | workspace credential; ciphertext only |
| `POST` | `/v1/workspace-keys` | workspace credential; encapsulation key only |
| `GET` | `/v1/workspace-keys` | workspace credential |
| `POST` | `/v1/recovery-recipients` | workspace credential; wraps only |
| `GET` | `/v1/recovery-recipients` | workspace credential |
| `POST` | `/v1/recovery-recipients/{id}/revoke` | workspace credential |
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

`GET /v1/audit` returns each event hash and the previous hash. It returns 500 events by default. Set `limit` up to 1000. Pass `next_after_seq` as `after_seq` to read the next page. It can return the latest checkpoint signature. It does not return a secret value.

`POST /v1/workspaces/{id}/credential/rotate` returns a new workspace credential. The old credential stops working.

`POST /v1/workspaces/{id}/deletion` revokes every session. The production control plane keeps the ciphertext for 7 days and then deletes it. Cancel inside that window restores the workspace. The dev gateway deletes the secret rows at once and schedules the root key for destruction.

A disabled secret fails inject before a key unwrap. The ciphertext remains until you delete the secret or the workspace.
