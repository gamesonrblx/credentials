# Human login and the dashboard

This is the design for the human surface. It is not a decrypting page.

A human signs in to administer a workspace. The session authorizes the same admin routes a workspace credential authorizes: agents, sessions, policy, audit, deletion. It is not an input to unwrap, and it is not accepted on `POST /v1/inject`. Agent tokens stay unable to call those admin routes. Nothing in this design gives an agent token a reveal scope.

The dashboard reads:

- `GET /v1/agent-sessions`
- `GET /v1/audit`
- `GET /v1/workspace-keys`
- `GET /v1/recovery-recipients`

It can revoke a session and a recovery recipient. It cannot show a secret value. Showing a value is only possible in the customer injector, which holds the decapsulation key outside the control plane. The control plane has no route that returns plaintext for an e2e secret.

Logging in does not recover the workspace key. Enrollment and recovery stay on the customer side: the page can list recipient kinds and start a revoke. It never receives a PRF output, a recovery-kit secret, or a decapsulation key.

SSO is not implemented. The first human credential remains the workspace credential, presented as a bearer on the admin routes. A later SSO session would mint that same kind of admin capability and still would not unwrap.

`dashboard/index.html` is a static page with those limits written on it. It does not call inject and it has no field for a secret value.
