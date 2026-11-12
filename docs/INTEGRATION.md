# Integrate a runtime with Credentials

Status: public pre-alpha. The dev gateway can read secret plaintext. Do not treat that process as zero-knowledge. The project has no customers and no certification.

The public HTTP API is the integration surface. The API names no agent product. Read the routes in [API.md](API.md).

## Control plane

Keep the workspace credential in the control plane. Create secrets, agents, and sessions there. Mint a session of about five minutes. Give the session only `secret:inject:...` scopes. Send the agent token to the runner. Keep the workspace credential out of the model loop. Keep the agent token in the runner proxy.

`POST /v1/workspaces` is open on a loopback dev listener. Set `CREDENTIALS_OPERATOR_TOKEN` when the listen address is not loopback. Send that token as `Authorization: Bearer` on workspace creation. The process exits when the token is absent.

`CREDENTIALS_ISSUER` sets the token issuer. `CREDENTIALS_AUDIENCE` sets the audience. The default issuer is `https://credentials.local/v1`. The default audience is `credentials-gateway`.

## Runner

Call `POST /v1/inject` with the agent token and a DPoP proof. Use `proxy` for an API key. The gateway calls the allow-listed HTTPS host. It sets the policy header. The secret is not in the response.

The public listener rejects `env` and `header`. Set `CREDENTIALS_LOCAL_DIR` for a runner on the same machine. The socket is `credentials.sock`. The directory mode is `0700`. The socket mode is `0600`. The gateway drops a connection from a different uid. The decoded body is `{ "env_name", "value" }` or `{ "header_name", "value" }`. Header delivery does not forward the request.

Build the DPoP `htu` from the request URL. Do not send a different `htu` in a header. The server uses the `Host` header.

## Limits of this build

The dev process decrypts `wrap_mode = gateway` rows. The production control plane does not open `wrap_mode = e2e` rows. Do not store a valuable secret in the dev key file.
