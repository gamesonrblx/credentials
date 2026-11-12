# Human login and the dashboard

This document is the design for the human surface. The page does not decrypt.

A human signs in to administer a workspace. The session can call the same admin routes as a workspace credential. Those routes cover agents, sessions, policy, audit, and deletion. The session is not an input to unwrap. `POST /v1/inject` rejects it. An agent token cannot call the admin routes. An agent token has no reveal scope.

The dashboard reads:

- `GET /v1/agent-sessions`
- `GET /v1/audit`
- `GET /v1/workspace-keys`
- `GET /v1/recovery-recipients`

The dashboard can revoke a session and a recovery recipient. It cannot show a secret value. Only the customer injector can show a value. The injector holds the decapsulation key outside the control plane. The control plane has no route that returns plaintext for an end-to-end secret.

Login does not recover the workspace key. The customer enrolls devices and recovery recipients. The page can list recipient kinds and can revoke one. The page never receives a PRF output, a recovery-kit secret, or a decapsulation key.

`credentials-edge` can start an OIDC authorization-code flow with PKCE. The group `credentials-admin` maps to the admin role. The group name `inject` is not a role. SAML is not implemented. The workspace credential remains the admin bearer until a full login ships.

`dashboard/index.html` is a static page. It does not call inject. It has no field for a secret value.
