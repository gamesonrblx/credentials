# Integrating a runtime with Credentials

Status: public pre-alpha. This gateway can read secret plaintext. Do not treat it as zero-knowledge against the operator. No customer, SOC 2, or certification claim.

The public HTTP API is the only integration surface. Nothing in it names a particular agent product. A control plane or runner uses the same routes as any other caller. The route list is [API.md](API.md).

## What the control plane holds

The control plane keeps the workspace credential. It creates secrets, agents, and sessions. It should mint a session that lasts about five minutes, with only `secret:inject:...` scopes, and hand the agent token to the runner. Keep the workspace credential out of the model loop. Prefer that the agent token stays in the runner proxy as well.

On a loopback dev listener, `POST /v1/workspaces` is open so a local process can bootstrap. If the process listens on any other address, set `CREDENTIALS_OPERATOR_TOKEN` and send it as `Authorization: Bearer` on workspace creation. The process refuses to start otherwise.

`CREDENTIALS_ISSUER` and `CREDENTIALS_AUDIENCE` override the token issuer and audience. The default issuer is `https://credentials.local/v1`. The default audience is `credentials-gateway`.

## What the runner does

The runner calls `POST /v1/inject` with the agent token and a DPoP proof. Use `proxy` delivery for API keys. The gateway calls the allow-listed HTTPS host, sets the policy header, and returns the upstream response. The secret is not in that response.

`env` and `header` are refused on the public listener. They belong on a local channel for a runner on the same machine.

## What this build does not do

It decrypts in the gateway process. A later production split keeps plaintext out of the control plane. Do not point the dev key file at secrets you cannot afford to lose.
