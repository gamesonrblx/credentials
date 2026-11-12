# Credentials roadmap

This file is the milestone plan for [Credentials](https://github.com/tacticocc/credentials).
Credentials is an AI-native secrets provider.
An agent receives a scoped session.
The session is short-lived.
The injector places the secret at runtime.
The secret does not enter the agent context.
The control plane writes each access in the audit log for that agent.

Credentials is a standalone API.
Any agent platform integrates through the public API.
The licence is Apache-2.0.
A later licence decision is possible.
Tactico may operate a hosted control plane for that same API.
The design can support other implementations.
Credentials competes with Infisical, Doppler, and 1Password.
A team imports each secret one time.
The injector seals the imported secret in Credentials.
Keycard is another agent-native project in this area.

The project is pre-alpha.
This document claims no customers, no SOC 2, and no certification.
This document assigns no calendar dates.
Each later milestone needs the exit criteria of the earlier milestone.

[docs/ENCRYPTION.md](ENCRYPTION.md) specifies encryption, keys, tokens, injection, and the audit log.
[docs/ARCHITECTURE.md](ARCHITECTURE.md) specifies the system, the zero-knowledge split, and account-bound recovery.
Build the encryption spec as that file states it.
This roadmap states the order, the crates, and the files.
If this plan and the spec disagree, this roadmap records the disagreement.
The spec stays the normative text.

Rust is the implementation language.
SQLite and Postgres store rows.
`wrap_mode=gateway` and `wrap_mode=e2e` both exist.
The dev gateway opens `wrap_mode=gateway` rows.
The dev gateway rejects `CREDENTIALS_ENV=production`.
The production control plane uses `RejectingRootKeys`.
The production control plane does not open an e2e secret.
`credentials-injector` opens an e2e secret.
TLS 1.3 uses rustls and aws-lc-rs.
The handshake negotiates `X25519MLKEM768`, group 4588.
`TLS_REQUIRE_HYBRID` defaults to on in production.
The local socket delivers `env` and `header`.
That directory mode is `0700`.
The peer uid must match the process uid.
There is no live hosted service.
Default CI does not use S3 Object Lock.
There is no real Nitro hardware path.
`credentials-edge` checks a test PCR document.
That check is not a live enclave.
The tree has no full `COSE_Sign1` AWS chain verifier.
Vault Transit and AWS KMS adapters are in `credentials-edge`.
A customer process or a dev process can call those adapters.
`Gateway::control_plane` does not call those adapters.
`credentials-edge` has a WebAuthn software authenticator.
`credentials-edge` has OIDC PKCE helpers.
SAML is not implemented.
The dashboard HTML does not decrypt a secret.
Import HTTP readers exist for Infisical, Doppler, 1Password Connect, and Vault KV.
Default CI does not call those live APIs.

## How to read the milestones

- **M0** is the foundation on `main`. PR #1 added the encryption spec. PR #2 added the Rust foundation. This file is the plan.
- **M2** is the API-bridge MVP. The public API is versioned. A runtime integrates from the public docs and the API. The dev gateway opens `wrap_mode=gateway` rows. M2 is not the production release.
- **M3** requires zero-knowledge against the operator for self-host production and for a hosted control plane. The production control plane does not open an e2e secret.
- **M4** is the first release a third party can self-host. It uses the M3 trust model, real signing keys, and TLS. TLS 1.3 is already in the tree.
- **M5** is an optional hosted beta of the same public API. Tactico would be the operator. The beta claims no certification. Zero-knowledge is an exit criterion. No hosted mode lets Tactico decrypt a secret. There is no live hosted service.
- **M6** covers import, human login, and the dashboard. Import HTTP readers are in `credentials-edge`. Default CI does not call the live APIs. SAML is not implemented. The dashboard HTML does not decrypt a secret.
- **M7** decides the licence and the public name. Zero-knowledge stays in M3.

M6 and M7 do not block the MVP.
M3 blocks M4 and M5.

## Current tree

The Cargo workspace in `Cargo.toml` has five crates.
Each crate is version `0.1.0`.
`publish` is false.
The Rust version is 1.89.
The licence is Apache-2.0.
`repository` is `https://github.com/tacticocc/credentials`.

| Crate | Path | Role |
| --- | --- | --- |
| `credentials-crypto` | `crates/crypto` | Envelope encryption, KEK wrap, `RootKeyProvider`, dev and memory providers, X-Wing, and CRD2. |
| `credentials-gateway` | `crates/gateway` | Axum server for tokens, scopes, inject, the audit chain, SQLite, Postgres, and TLS. |
| `credentials-client` | `crates/client` | HTTP client with DPoP proofs and TLS 1.3. |
| `credentials-injector` | `crates/injector` | Opens a `wrap_mode=e2e` grant. The control plane does not link this crate. |
| `credentials-edge` | `crates/edge` | Vault Transit, AWS KMS, import readers, WebAuthn, OIDC, and a test PCR document. |

CI in `.github/workflows/ci.yml` runs `fmt`, `clippy -D warnings`, `cargo-deny`, and `cargo test --workspace --locked`.
The hosts are Ubuntu, macOS, and Windows.
Dependabot watches Cargo and GitHub Actions each week.

---

## M0 — Pre-alpha foundation

**Status: done on `main`.** This file is the milestone plan on that foundation.

### Goal

Land the encryption spec and a tested Rust skeleton.
The skeleton implements the envelope, a dev key provider, and a small gateway.
Later work extends those modules.

### Deliverables (what exists)

M0 added the files below.
Later milestones added SQLite, Postgres, CRD2, TLS, the injector, and `credentials-edge`.
Read the current facts above for that later work.

- `docs/ENCRYPTION.md` specifies the envelope, rotation, crypto-shred, hybrid key transport, tokens, injection, and the audit log (PR #1).
- `docs/ROADMAP.md` is this plan.
- Workspace metadata is `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, and `.gitattributes`.
- The repo also has `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, and `README.md`.
- `credentials-crypto`
  - `src/aad.rs` builds `CRD1` payload associated data and data-key wrap associated data. Known-answer tests cover both.
  - `src/aead.rs` and `src/envelope.rs` seal and open AES-256-GCM. The functions are `seal_secret`, `open_secret`, and `rewrap_dek`. Rewrap leaves the payload bytes unchanged. A bit flip, swapped associated data, a bad nonce, or an unknown algorithm makes the open fail.
  - `src/kms.rs` defines `RootKeyProvider` with `CreateTenantRoot`, `Encrypt`, `Decrypt`, `ScheduleDestruction`, and `CancelDestruction`. It also defines `KekContext`, `MemoryRootKeys`, `DevFileRootKeys`, and `CountingProvider`. `DevPolicy` rejects `CREDENTIALS_ENV=production`. `RejectingRootKeys` is the production control-plane provider.
  - `src/hybrid.rs` wraps and unwraps a 32-byte key with X-Wing (X25519 + ML-KEM-768). The dev gateway does not call X-Wing for `wrap_mode=gateway`. `credentials-injector` uses it for `wrap_mode=e2e`.
  - `src/random.rs` and `src/error.rs` supply random bytes and errors.
- `credentials-gateway`
  - `src/store.rs` defines the `Store` trait and `MemoryStore`. `SqlStore` implements the trait for SQLite and Postgres.
  - `src/token.rs` has an in-process Ed25519 JWT signer, `DevSigner`. The audience is `credentials-gateway`. The default TTL is 5 minutes. The hard maximum is 15 minutes. The token is identity and scope. The token is not a decryption key. The dev gateway rejects this signer when `CREDENTIALS_ENV=production`. A production KMS signer is still an M4 item. `Gateway::control_plane` still accepts a `DevSigner`.
  - `src/dpop.rs` implements DPoP (RFC 9449) with Ed25519 and RFC 7638 thumbprints.
  - `src/policy.rs` checks the delivery policy, the scope, and the host. An agent session may hold only `secret:inject:...`.
  - `src/audit.rs` builds the workspace chain and the per-agent chain. `hash = SHA-256(prev_hash || body)`. The dev process can sign a tip. A hosted retention lock is not in default CI.
  - `src/service.rs` creates a workspace, a secret, an agent, and a session. It revokes a session and injects through a proxy. It appends `secret.access.allowed` before unwrap. It does not decrypt if that append fails. It rotates a KEK and rewraps in process. Delete sets `deleting` and schedules tenant-root destruction after 7 days. The KEK cache TTL is 60 seconds. The public listener rejects `env` and `header`. The local socket accepts those modes.
  - `src/http.rs` serves `POST /v1/workspaces`, `/v1/secrets`, `/v1/agents`, `/v1/agent-sessions`, `/v1/agent-sessions/{id}/revoke`, `/v1/inject`, `/v1/kek/rotate`, and `/v1/workspaces/{id}/deletion`. It also serves `GET /v1/audit` and `GET /healthz`. Workspace creation on the loopback listener has no credential, so a local process can start.
  - `src/upstream.rs` defines `Upstream`, `RecordingUpstream`, and an HTTPS client. The client replaces the policy header. The client does not follow a redirect. The client does not copy that header back.
  - `src/main.rs` binds `127.0.0.1:8080`, or `CREDENTIALS_LISTEN`. It loads `.credentials-dev-keys.json`, or `CREDENTIALS_DEV_KEYS`. It exits when `CREDENTIALS_ENV=production`.
  - `src/redact.rs`, `src/names.rs`, `src/error.rs`, and `src/b64.rs` support redaction, names, errors, and base64.
- `credentials-client` implements `create_workspace`, `create_secret`, `create_agent`, `create_session`, and `inject` with DPoP. The client has a TLS 1.3 module.
- Tests cover spec items 1–13 in outline. They cover associated-data vectors, seal and open, integrity failures, and rewrap with unchanged payload bytes. They cover a wrong KMS context, the production-policy refusal, and revoked, expired, or wrong-DPoP tokens. A denial makes zero KMS calls. A failed audit append skips decrypt. A `deleting` workspace fails inject before `Decrypt`. CI is green on each OS.

### What is still stubbed after M0

M0 did not include the durable store, TLS, the local socket, or `wrap_mode=e2e`.
The current tree includes those items.
Read the current facts at the top of this file.

These items are still absent.
There is no live hosted service.
Default CI does not use S3 Object Lock.
There is no Nitro EIF and no live Nitro path.
The tree has no full `COSE_Sign1` AWS chain verifier.
SAML is not implemented.
The dashboard HTML does not decrypt a secret.
`Gateway::control_plane` does not call the Vault Transit adapter or the AWS KMS adapter.

The dev key file does not hide plaintext from an operator who runs the dev gateway.
That process opens `wrap_mode=gateway` rows.

### Exit criteria

The spec is in the tree.
The crates build and the tests pass on the CI matrix.
The dev provider cannot be constructed when `CREDENTIALS_ENV=production`.
A loopback dev gateway can create a workspace, store a secret, and mint a DPoP-bound session.
It can proxy-inject through a test upstream, rotate a KEK, and schedule a shred.
The audit chain verifies.

### Dependencies

None.

---

## M1 — Durable v1 core

### Goal

Finish the storage, audit, and API seams from `docs/ENCRYPTION.md` on a store that survives a process restart.
The dev gateway may use the dev root-key provider or the memory provider.
After this milestone the dev gateway is a single-node service.
It still uses the dev-gateway decrypt path for `wrap_mode=gateway`.
M3 changes who can open an e2e secret.

### Deliverables

- `SqlStore` in `crates/gateway/src/sql_store.rs` implements `Store` for SQLite and for Postgres. `MemoryStore` remains for unit tests. The logical schema follows `docs/ENCRYPTION.md` section 7, including `wrap_mode` and `e2e_encapsulation`. `wrap_mode=gateway` and `wrap_mode=e2e` both exist. The production control plane does not open an e2e row.
- A migration and a restart test keep a sealed secret. The same payload opens after startup.
- `Gateway` methods and HTTP routes:
  - `POST /v1/secrets/{name}/versions` calls `Store::insert_version`. A new version does not replace ciphertext in place.
  - `POST /v1/workspaces/{id}/deletion/cancel` calls `RootKeyProvider::cancel_destruction`. It sets the workspace to `active` only while destruction is still pending.
  - A shred poller observes destruction and sets `status=shredded`. It appends `tenant.shredded`.
  - On `DeleteWorkspace`, revoke every session and every workspace credential. Drop cached KEKs. Delete secret rows and KEK rows after the schedule. Keep the audit rows.
- Audit checkpoints and an `AuditAnchor` trait live in `crates/gateway/src/audit.rs` and `crates/gateway/src/anchor.rs`. The dev anchor appends to a local file. `CREDENTIALS_ENV=production` rejects that dev anchor. Sign the tip every 1,000 events or 60 seconds, and on shutdown, as in section 9. After `AUDIT_ANCHOR_MAX_LAG`, inject returns 503 `audit_anchor_unavailable`.
- The `Upstream` HTTP client in `crates/gateway/src/upstream.rs` uses HTTPS only. It replaces the configured header. It does not follow a redirect. It does not copy the secret header back. `cargo run` can proxy-inject to an allow-listed host.
- Use singleflight per KEK id. The 60-second TTL in `service.rs` already exists. Drop a cache entry when the workspace is not `active`. The dev gateway cache holds unwrapped KEKs. The production control plane must not keep that cache for secret keys.
- Tenant-root rotation to a new key id rewraps KEKs only. Payloads and data keys stay. Do that work here if it stays small. Otherwise wait for a cloud KMS adapter. On the production path, the control plane must not unwrap secret data keys. That is the default.
- The encryption spec names Rust as the implementation language. TLS in this tree uses rustls and aws-lc-rs. The Go TLS notes are not a second codebase.

`Cargo.toml` and the private-advisory link in `SECURITY.md` already use `https://github.com/tacticocc/credentials`.

### Exit criteria

- A restart keeps workspaces, secrets, sessions, and the audit chain.
- A second version, a cancelled shred, and a completed shred each write the matching audit event. Inject on a `deleting` or `shredded` workspace fails before `Decrypt`.
- A second rewrap wraps zero rows and leaves the ciphertext unchanged (spec test 15).
- A failed audit append or a lagged anchor blocks decrypt on the dev-gateway path.
- An allow-listed HTTPS host succeeds on `cargo run`. Tests reject a redirect and a header append.
- The encryption spec does not say that no code implements the envelope.

### Dependencies

M0.

---

## M2 — API-bridge MVP

### Goal

Publish a stable public API and a generic client.
Any agent platform or runtime can integrate with that API.
The API has no platform-specific types.
A third party does not need to read control-plane internals.

The dev gateway still opens `wrap_mode=gateway` in `Gateway::inject`.
That path is the MVP for API shape and for `wrap_mode=gateway` delivery.
It is not zero-knowledge.
It is not the production release.
The production control plane does not open an e2e secret.

### Deliverables

- Add an integrator API document, for example `docs/API.md`, and an OpenAPI description of the `/v1` routes. Include the error codes from `docs/ENCRYPTION.md` section 10. Keep agents, workspaces, sessions, and scopes generic. Name no product as the required first client.
- Authenticate workspace creation except on a loopback dev listener. A self-host or shared process needs an operator credential. The issuer, the audience, and the listen address must be configurable. The default `ISSUER` is `https://credentials.local/v1`. `set_issuer` can change it.
- Serve proxy injection on the public listener. That mode is the default for an API key. Deliver `env` and `header` only on the local channel. Use a Unix socket in a mode-`0700` directory and check the peer uid with `SO_PEERCRED` or the platform equivalent. Or use TLS to loopback with a client certificate for that session. The public listener rejects `env` and `header`. The local response is `{ env_name, value }` or `{ header_name, value }`. Do not send header delivery through `Upstream`.
- `credentials-client` covers the MVP surface, including new versions, revoke, audit, deletion, cancel, and TLS. Do not write secret plaintext in a log. Place any other language SDK outside this repository or under `sdks/`.
- Support a disabled secret, session list, and session revoke. `GET /v1/audit?agent_id=…` exists. Include hashes so a client can recompute the agent chain. Include the latest checkpoint signature when an anchor exists.
- Write an integration guide for a control plane or a runtime that holds the workspace credential. That guide shows a 5-minute DPoP-bound session. Do not place the workspace credential in the model loop. Do not place the agent token in the model loop when the runtime can do that. Prefer `proxy` on the public listener. Use `env` and `header` only on a local channel or a single-tenant runner. The guide names no house client.
- Add HTTP tests in `crates/client/tests` and `crates/gateway/tests` for the new routes and the local channel. Add the log-canary test from spec item 14 if the suite does not already cover that path.

Production import is M6.
Do not add an M2 loopback helper that seals a production secret under the dev KEK.
That helper would teach the wrong production path.

### Exit criteria

- An operator can start the dev gateway, create a secret, and mint an agent session.
- A runner can call an allow-listed HTTPS upstream through `POST /v1/inject`.
- The secret does not appear in the agent context, the response, or the logs.
- `env` and `header` work only on the local channel.
- The public listener forbids those modes.
- A third-party runtime can integrate from the public docs and the API alone.
- Nothing in the API is specific to one integrator.
- CI stays green on the three-OS matrix.
- The MVP docs say that the dev gateway can read plaintext for `wrap_mode=gateway`.

### Dependencies

M1, for the durable store, versions, the upstream client, and the audit anchor.

---

## M3 — Zero-knowledge against the operator

### Goal

Make zero-knowledge a core property of self-host production and of a Tactico-hosted control plane.
The operator of the control plane must not see secret plaintext.
The operator must not see the keys that decrypt that plaintext.
Tactico is that operator when Tactico hosts the control plane.

The dev gateway is not zero-knowledge against its operator.
The production control plane uses `RejectingRootKeys` and does not open an e2e secret.
`credentials-injector` opens an e2e secret.
M1 and M2 may keep the dev-gateway decrypt path.
That path is not the production ship for M4 or M5.

### Where the code and the spec are today

The dev gateway can see plaintext and unwrap keys.
The production control plane cannot open an e2e secret.

- `docs/ENCRYPTION.md` section 12 is the production path for `wrap_mode=e2e`. The dev gateway opens `wrap_mode=gateway` and rejects `CREDENTIALS_ENV=production`. The production control plane releases ciphertext and does not call `open_secret` on an e2e row.
- `Gateway::inject` on the dev gateway unwraps the workspace KEK through `RootKeyProvider::decrypt` and then calls `open_secret`. Proxy delivery and header delivery copy plaintext into an upstream header on that path. `env` delivery returns plaintext in the response body on the local channel. The event `secret.access.allowed` is committed first. A failed append skips decrypt. That order is an audit control. It does not hide plaintext from the dev-gateway operator after a successful append.
- Unwrapped KEKs sit in a process-local cache for 60 seconds (`KEK_CACHE_TTL`) in the dev gateway.
- `DevFileRootKeys` in `crates/crypto/src/kms.rs` writes raw 32-byte tenant root keys to `.credentials-dev-keys.json`. `CREDENTIALS_DEV_KEYS` overrides that path. `MemoryRootKeys` holds the same raw keys in process memory. The dev gateway rejects `CREDENTIALS_ENV=production`. `Gateway::control_plane` uses `RejectingRootKeys`. An operator who can read the dev key file can open `wrap_mode=gateway` rows.
An operator who can read the dev process memory can open those rows.
An operator with a decrypt role on the dev gateway can open those rows.
- `SealedSecret` stores payload ciphertext, the data-key wrap, nonces, and algorithm labels. Rows also store `wrap_mode` and `e2e_encapsulation`. `wrap_mode` is `gateway` or `e2e`.
- `crates/crypto/src/hybrid.rs` can generate an X-Wing key pair and wrap a 32-byte key. The associated data for that library wrap is `credentials.hybrid.wrap.v1`. CRD2 is the stored e2e format. The dev gateway does not call X-Wing to open a `wrap_mode=gateway` row.
- A token is not a decryption key (`crates/gateway/src/token.rs`, spec decision 6). A stolen token cannot open a database dump offline. That property is required. It is not zero-knowledge by itself. The dev gateway that accepts the token still decrypts `wrap_mode=gateway`.
- Secret names are stored in the clear, by design. The control plane can authorize before anyone opens a secret. Zero-knowledge here covers plaintext and unwrap keys. It does not hide names.

Section 12 is the start for architecture (i) below.
The live enclave path is not built.
`credentials-edge` has a test PCR document.
The tree has no Nitro EIF, no live Nitro path, and no full `COSE_Sign1` AWS chain verifier.
[docs/ARCHITECTURE.md](ARCHITECTURE.md) records the target split, the enclave key-release flow, and account-bound recovery.

### Architecture (i) — customer-run injector

The control plane stores ciphertext, policy, tokens, and the audit log.
It does not store a decapsulation key, an unwrapped KEK, or an unwrapped data key.
It does not call `open_secret` for `wrap_mode=e2e`.

`credentials-injector` holds the X-Wing decapsulation key from section 12.
Generate that key on a machine the control-plane operator does not control.
Register the encapsulation key with the control plane.
The decapsulation key stays with the customer.
Account-bound recovery in [docs/ARCHITECTURE.md](ARCHITECTURE.md) wraps that key for customer recipients.
The recipients are enrolled devices, WebAuthn PRF passkeys, an offline recovery kit, and optional admin teammates.
`hybrid.rs` is the primitive.
CRD2 persists `e2e_encapsulation`.

Injection for `env`, `header`, or `proxy` happens in the injector.
On an inject attempt, the control plane authorizes and writes the audit log.
Check the DPoP-bound token, the scope, the delivery policy, and revocation.
Append `secret.access.allowed` before any release.
On audit failure, release nothing.
Release ciphertext that the injector can open, or a grant that identifies that ciphertext.
Do not release plaintext.

Self-host production uses this split too.
Self-host means the customer runs the control plane.
The people who administer that database are the operator.
They must not be able to open a secret.
The workload owner runs the injector, with the decapsulation key, in a separate trust domain.
A single process that stores the rows and holds the dev root key is the dev path only.

### Architecture (ii) — hosted injection inside an attested enclave

Some callers want the operator to proxy-inject without an injector on their host.
That path exists only inside a confidential-computing enclave, such as an AWS Nitro Enclave or an AMD SEV-SNP guest.
The control plane outside the enclave stores ciphertext, policy, tokens, and the audit log.
It has no `Decrypt` on keys that wrap secrets.

Bind key release to a remote attestation of the enclave image.
The customer, or a release service the customer trusts, checks the measurement before the key enters the enclave.
The measurement is the image identity and the configuration that measurement commits to.
Operator staff and the parent host see the host-side process.
They do not get a measurement for a different binary.
They do not receive the key.
A substituted binary that prints plaintext fails attestation.
The key is not released.

The current dev gateway cannot be treated as an enclave.
`Gateway::inject`, the KEK cache, and `DevFileRootKeys` assume a normal process.
The host can read that process memory.
The enclave image has to be a small unwrap-and-inject path.
Attestation, the measurement log, and the release policy are product surface.
The host-side proxy that feeds the enclave must not receive plaintext.
An upstream call that leaves the enclave carries the secret only on the intended request.
That is the same exposure the upstream already has in proxy mode.

This path is not a live enclave.
`credentials-edge` checks a test PCR document.
The tree has no Nitro EIF and no full `COSE_Sign1` AWS chain verifier.
[docs/ARCHITECTURE.md](ARCHITECTURE.md) is the design note.
Hardware attestation trusts the CPU vendor and the published measurement.
It does not claim that the operator cannot affect availability.

### Architecture (iii) — tradeoffs

These costs belong in the product text.

**Key recovery.** [docs/ARCHITECTURE.md](ARCHITECTURE.md) specifies account-bound recovery, and this milestone implements it.
Wrap the workspace key for recipients the customer controls.
Each enrolled device is a recipient.
A passkey through the WebAuthn PRF extension is a recipient.
An offline recovery kit is a recipient.
An optional admin teammate is a recipient.
Never wrap that key for an operator-held key.
Authentication does not recover the key.
Loss of every recipient loses the data.
The operator cannot reconstruct that key.
An operator-held recovery recipient would break zero-knowledge.
Destruction of a tenant root key crypto-shreds `wrap_mode=gateway` rows only.
Section 12 wraps an e2e data key to the client workspace key.
KMS destruction does not shred those versions.
Shred them by destroying every recipient that can open the workspace key.
A backup of any one recipient undoes that shred.

**Revocation.** The dev gateway loads the session, rejects a revoked session, and only then unwraps.
The same process decides and decrypts, so a revocation is visible on the next request.
A customer who holds the decapsulation key and a ciphertext copy can open the secret.
That open does not need the control plane.
Revocation stops the supported injector when the injector must fetch ciphertext from the control plane.
The same rule applies to a per-access grant.
The control plane checks `revoked_at` and the `jti` table first.
A failed audit append returns nothing.
Revocation does not stop a party who already copied the key and the ciphertext.
Token lifetime does not close that hole.
The product must say so.

**Audit.** The hash chain stays meaningful for requests that the control plane handles.
The control plane can refuse ciphertext when the allow event cannot be written.
It cannot prove that an injector which already had the key did not decrypt.
The operator cannot inject for the customer from the control plane.
The operator cannot debug by reading a secret.
The operator process has no KEK cache for secret keys.
A normal hosted multi-tenant process does not proxy-inject.
The operator keeps authorization, DPoP, scope, and an audit log for the supported path.
The operator keeps a database that the operator cannot open.

**Enclave-specific loss.** Attested injection depends on the hardware vendor and on the measurement the customer pinned.
Enclave I/O must not leak plaintext to the host.
A crash dump, a debug console, and a host-visible swap file break the claim.
Injection availability follows the enclave and the attestation service.
The control plane can still revoke by refusing ciphertext.
The control plane still cannot see the opened secret.

### Deliverables

- Keep the spec aligned with this rule. Production self-host and a hosted control plane are zero-knowledge against the operator. The dev gateway may open `wrap_mode=gateway` and must reject `CREDENTIALS_ENV=production`.
- Persist `wrap_mode` and `e2e_encapsulation`. `wrap_mode=e2e` stores the X-Wing encapsulation and a data-key wrap under the X-Wing shared secret. The encoding is `CRD2`. The tree includes the draft-11 X-Wing test vectors. `hybrid.rs` is the primitive. Its library associated data (`credentials.hybrid.wrap.v1`) is not the stored secret format.
- Ship `credentials-injector`. It holds the unlocked decapsulation key and performs `env`, `header`, and proxy injection. The control-plane inject path does not call `open_secret` for `wrap_mode=e2e`. The production control plane has no path that loads a decapsulation key.
It has no path that loads a tenant root which unwraps a secret data key. It uses `RejectingRootKeys`.
- Implement account-bound recovery from [docs/ARCHITECTURE.md](ARCHITECTURE.md) before the mode is called generally available. Wrap the workspace key for recipients the customer controls. Never wrap it for an operator-held key.
  - Multi-recipient wrap. A client that already holds the workspace key produces each new wrap. The control plane stores the wrapped blobs and the public encapsulation keys.
  - Device enrollment. Each enrolled device has its own X-Wing key pair. Register only the encapsulation key.
  - Passkeys through the WebAuthn PRF extension. The PRF output unwraps the workspace key on the client. Do not upload that output. `credentials-edge` has a software authenticator.
  - An offline recovery kit, generated on the client and displayed one time.
  - Optional admin teammates, as further customer-held recipients.
  - No operator recipient. The control plane, its KMS role, and a login session are not recipients. Authentication alone cannot recover the workspace key.
- Control-plane release rules: run revocation and the audit append before any ciphertext or grant is released. Audit failure releases nothing. Released bytes are not plaintext.
- Hosted enclave injection needs an enclave image, remote attestation, and key release bound to the measurement.
That path does not exist in this tree. This tree has a test PCR document only. If the enclave path is not ready, hosted production uses architecture (i) only. It does not use a normal process that decrypts. There is no live hosted service.
- Tests: an operator-level process with the database, the control-plane IAM, and no customer key cannot open a secret. The injector with the key can inject. A revoked session receives no ciphertext. A failed audit append releases nothing. A `wrap_mode=gateway` dev row opens only in the dev gateway. An enclave release, when that path exists, rejects a measurement that is not the pinned one.

### Exit criteria

- The control-plane operator cannot read secret plaintext in self-host production.
- The operator cannot read the keys that decrypt that plaintext.
- The same limit applies to a configuration that Tactico would host.
- A database dump plus control-plane credentials is not enough to open an e2e secret. Opening it requires the customer decapsulation key, or a key released only to an attested enclave measurement.
- Existing `wrap_mode=gateway` rows keep their meaning on the dev path. Production startup does not serve them from the control plane.
- Recovery and the revocation and audit limits above are in the spec and in the operator docs.
- Account-bound recovery matches [docs/ARCHITECTURE.md](ARCHITECTURE.md). A second device can be enrolled from an existing customer recipient. A lost device can be replaced from another device, a WebAuthn PRF passkey, the recovery kit, or an admin teammate. An operator with the database and the control-plane credentials cannot unwrap the workspace key.
A login session does not add a customer recipient. There is no operator-held recovery recipient. Loss of every recipient loses the data. The docs say so.
- The dev root-key file and the dev `Gateway::inject` decrypt path remain for loopback development. They reject `CREDENTIALS_ENV=production`.

### Dependencies

M2, for a stable public API and the delivery modes.
The schema columns from M1 are assumed.
M4 and M5 depend on this milestone.

---

## M4 — Self-hostable release

### Goal

Ship an open-core release that a third party can run.
Production secret custody is the M3 architecture.
The people who operate the control plane cannot open a secret.
The injector can open a secret.
This is the first tagged release that is more than a dev binary.

### Deliverables

- Package the control plane and `credentials-injector`. Provide container images, a compose example or an equivalent with the chosen database, and a documented config surface. That surface includes `CREDENTIALS_LISTEN`, `CREDENTIALS_ENV`, signing keys, TLS, the anchor, the issuer, and the injector. Document backup, enrollment, recovery, shred of client-held keys, and key-file hygiene for the dev path.
- Use a KMS or an HSM for non-exportable token-signing keys and audit-signing keys (`signing_keys`, KMS Sign). The production control-plane role does not get `Decrypt` on keys that wrap secret data keys. `credentials-edge` has Vault Transit and AWS KMS adapters for a customer process or a dev process. `Gateway::control_plane` does not call them. Production startup fails if the control plane is given that decrypt role. One cloud provider is enough. The provider is an open question. PKCS#11 is later. Integration tests that talk to a real KMS need credentials and do not run in default CI.
- Replace `DevSigner` for production token signatures. `CREDENTIALS_ENV=production` rejects the dev root-key provider, the dev signer, and the dev audit anchor. It starts when the production signer, the anchor, and the zero-knowledge configuration are present. `Gateway::new` returns `KmsUnavailable` for a production start of the dev constructor. `Gateway::control_plane` is the production constructor. It uses `RejectingRootKeys`. It still takes a `DevSigner` argument in this tree. It must not take a secret-unwrapping `RootKeyProvider`.
- Serve public TLS 1.3. Prefer `X25519MLKEM768` (RFC 10024, group 4588). Record `tls_classical_kex_total`. `TLS_REQUIRE_HYBRID` defaults to on in production and then offers only group 4588. A dev process may leave the flag off for an older local tool. Spec test 16: a client that offers the hybrid group negotiates 4588. `credentials-client` has a TLS backend. The stack is rustls and aws-lc-rs.
- Implement the metrics and log-redaction rules in section 13, beyond `metrics_integrity` and the field-name denylist. Control-plane logs and traces have no plaintext to redact, because that process does not open a secret. The injector still redacts.
- Stay on Apache-2.0. Stay pre-certification. The release notes must not claim SOC 2, customers, or a production SLA.

### Exit criteria

- A self-hoster can start the control plane and the injector.
- The self-hoster can create a workspace, enroll a client key, inject over TLS, and revoke a session. The control-plane process cannot open the secret.
- `CREDENTIALS_ENV=production` fails when a dev backend is selected or when the control plane receives a secret-unwrapping key. It starts when neither is true.
- Hybrid TLS is tested. Default CI still runs without cloud credentials.
- The docs are sufficient to deploy without reading the source.
- The release notes make no SOC 2, customer, or certification claim.

### Dependencies

M3.
The signing-key adapter and TLS can be prototyped beside M2.
The release assumes the MVP API and the zero-knowledge split.
TLS 1.3 is already in the tree.

---

## M5 — Hosted beta

### Goal

Operate an optional multi-tenant hosted beta of the same public API.
Tactico would be the host.
Stay honest about pre-certification status.
Tactico is the operator of the control plane.
Zero-knowledge against that operator is an exit criterion.
There is no live hosted service in this tree.

### Deliverables

- Deploy the M4 control plane for the hosted beta. It stores ciphertext, policy, tokens, and the audit log. It does not store a decapsulation key. It has no KMS `Decrypt` permission on keys that wrap customer secrets. It does not run the dev root-key provider. It uses `RejectingRootKeys`.
- Hosted injection, if it is offered, runs only as architecture (ii) from M3. That is an attested enclave, with key release bound to the measurement. Operator staff and the host cannot unwrap keys. The tree has no live enclave. It has a test PCR document in `credentials-edge` and no full `COSE_Sign1` AWS chain verifier. If the enclave path is not in this beta, callers use `credentials-injector` against the hosted control plane. There is no mode in which a normal Tactico process decrypts.
- Use a hosted audit anchor with a retention lock.
- S3 Object Lock or an equivalent meets that rule.
- Key each object by `{workspace_id}/{seq}`. The publisher can put objects and cannot delete them. The database role has no permission on the bucket. Default CI does not use S3 Object Lock. `credentials-edge` can send an object with compliance-mode headers. Default CI does not start that store.
- Harden multi-tenant operation with rate limits, per-workspace isolation, and request ids in the audit log. Write operator runbooks for fail-closed behavior when attestation or the injector is unavailable. Alert on integrity failure and anchor lag. A KMS outage of a signing key stops token issue and audit signing. Do not hide that outage by unwrapping a secret in the control plane.
- Keep the section 13 metrics that apply to a control plane that does not decrypt.
- Those metrics are `crypto_integrity_failure_total` when the injector reports it, `inject_total`, and `token_denied_total`.
- Also keep `tls_classical_kex_total` and `audit_anchor_lag_seconds`. KMS decrypt metrics apply to the enclave or the injector, not to a Tactico decrypt path. Do not add a hosted dashboard counter that requires plaintext.
- Add a narrow operator path to create a workspace and issue the first workspace credential. Full human SSO and a dashboard are M6. `credentials-edge` has OIDC PKCE helpers. SAML is not implemented. The dashboard HTML does not decrypt a secret. That path returns the credential one time and does not return a secret.
- Set `TLS_REQUIRE_HYBRID=true` on the public listener. Production already defaults this flag to on.
- Publish status, data-handling, and threat-model pages.
- Restate the pre-alpha limits and the zero-knowledge claim.
- Use only words the deployment meets. Use no customer logos, no SOC 2, and no certification claims.

### Exit criteria

- No hosted mode lets Tactico decrypt secret plaintext or the keys that decrypt it.
- A hosted configuration fails this milestone if it calls `open_secret`.
- It fails if it holds a dev key file.
- It fails if it grants the control plane `Decrypt` on a secret-wrapping key.
- Two isolated workspaces can be created in the hosted environment. Ciphertext, tokens, and audit chains do not cross workspace boundaries. Destruction of one workspace's client-held keys does not open or destroy the other workspace's secrets.
- Hybrid TLS is required. Dev providers cannot be enabled.
- Alerts fire on integrity failures from the injector or the enclave, on attestation or key-release failure, and on anchor lag.
- Public wording stays inside what is actually operated. The beta claims no customers, no SOC 2, and no certification.
- There is no live hosted service until this milestone is operated.

### Dependencies

M4.
The zero-knowledge exit criteria are the M3 criteria, applied to a deployment Tactico operates.

---

## M6 — Migration and operator surfaces

### Goal

Give a team a one-time way to move secrets into Credentials.
Give a human a way to administer a workspace without being the agent.
Credentials stores the imported secret.
The injector seals it under the customer-held key from M3.

### Deliverables

- Provide one-time import from Infisical, Doppler, 1Password Connect, HashiCorp Vault KV, and `.env` files. HTTP readers for Infisical, Doppler, 1Password Connect, and Vault KV exist in `credentials-edge`. Default CI does not call those live APIs. The injector reads the source one time, seals each secret as a native version, and discards the source bytes. The control plane receives ciphertext. It does not receive the imported plaintext. It does not keep a live connection that fetches those products at inject time.
- The import path is not a live backend on the inject path. After import, injection uses only Credentials ciphertext. A failure during import stops that item.
The failure leaves no plaintext on the control plane.
The importer operator sees a failed item.
- Human identity, SSO, and a dashboard need their own design docs. `credentials-edge` has a WebAuthn software authenticator and OIDC PKCE helpers. SAML is not implemented. The dashboard HTML does not decrypt a secret. The workspace credential remains the bootstrap admin secret. A session cookie does not replace it on inject routes. The dashboard calls the control plane for policy, agents, sessions, and the audit log. Showing a secret is possible only in the injector or in an attested enclave, with a stronger audit reason. An agent token must be unable to mint that scope. A hosted page that decrypts in the control plane does not meet M5.
- Keep customer-held keys for enrollment and recovery on this operator surface when the UX needs them. The human who administers the workspace can see an enrolled key.
That human can start recovery with a customer-held recipient. The control plane never receives the decapsulation key.

### Exit criteria

- An import from each supported source produces envelope-encrypted versions, then discards the source bytes. A later inject does not call Infisical, Doppler, 1Password, Vault, or the `.env` file.
- The control-plane database and logs contain no imported plaintext. Opening an imported secret requires the customer-held key or an attested enclave.
- A human operator can authenticate, manage agents, policy, and sessions, and read the audit log. An agent token gains no new power. The control plane gains no decrypt path.
- A failed import does not write plaintext and does not create a version the operator can open.

### Dependencies

M4 is enough for a self-hosted importer.
M5 is required before the same importer is offered against a hosted control plane.
The human-identity design doc is a dependency of the dashboard, not of the importer.

---

## M7 — Licence and naming

### Goal

Decide the long-term licence and the public name.
Zero-knowledge is M3.
This milestone does not reopen it.

### Deliverables

- Decide the licence. Stay on Apache-2.0, or move new work to FSL or AGPL. Write the reason. Write a plan for existing contributors and self-hosters.
- Decide the name. Keep Credentials, or adopt a name such as Credena. Include the crate names, the issuer, and the docs.
- Later items can share this milestone or follow it.
- One item is PKCS#11 for the signing-key provider.
- Another item is hybrid token signatures with Ed25519 plus ML-DSA-65.
- Add those signatures after a reviewed library and a signing-key story exist.

### Exit criteria

- The licence and the name are decided in writing. The repository, the crates, and the docs match.
- Neither decision adds a hosted mode in which the operator can decrypt.

### Dependencies

M4 at minimum, so the decision is about a release people can run.
M5 and M6 may still be open.

---

## Open questions

These items are unresolved.
A written decision, or a decision to build the current default, unblocks the work.
None of them reopens the envelope, the token check, or the audit chain.
The first four shape M1–M4.
The rest can wait.
Zero-knowledge against the operator is not an open question.
M3, M4, and M5 require it.

1. **Durable storage engine.** SQLite and Postgres both exist behind `Store`. Is Postgres the production engine, with SQLite for a local run, or is one engine mandatory?
2. **First signing-key provider.** AWS, GCP, or Azure. One provider is enough for the production signer and the audit signer in M4. Which provider should the first adapter and the self-host docs lead with? If a hosted control plane is operated later, should it use the same provider? This key signs tokens and audit tips. It is not permission to wrap secret data keys for the control plane. Vault Transit and AWS KMS adapters exist in `credentials-edge` and are not called by `Gateway::control_plane`.
3. **SDK language priorities.** A Rust client exists. Which additional languages, for example TypeScript or Go, should follow, and in what order? Do those SDKs live in this repository or outside it?
4. **Naming.** Stay with Credentials, or move to a name such as Credena? The choice covers crate names, the JWT issuer, and any hosted product. A decision after M2 avoids a rename during integration. M7 is the latest responsible moment.
5. **Licence.** Remain on Apache-2.0 through the self-host release, or choose FSL or AGPL at M7? The current `LICENSE` and crate metadata use Apache-2.0.
6. **Default delivery path.** Confirm that M2 treats `proxy` as the required path on the public listener. Confirm that local-channel `env` and `header` serve a runner on the same machine or a single-tenant worker. Under M3, `credentials-injector` delivers the secret. An attested enclave would deliver hosted proxy injection. The enclave path is not live.
7. **Workspace bootstrap in hosted and self-host.** Who may call `POST /v1/workspaces` when the listener is not loopback-only?
8. **Recovery ceremony details.** The account-bound model is specified in [docs/ARCHITECTURE.md](ARCHITECTURE.md) and is an M3 deliverable. It includes multi-recipient wrap, device enrollment, WebAuthn PRF passkeys, an offline recovery kit, optional admin re-share, and no operator recipient. `credentials-edge` has a software authenticator. Authentication does not recover keys. Loss of every recipient loses the data. Still open: the exact recovery-kit encoding, and which passkey transports the first client supports. The operator must not hold a recovery key.
9. **Hosted injection mechanism.** Architecture (i) is sufficient for the M5 exit criteria. The injector exists. The beta can add architecture (ii) later.
Choose the first enclave technology at that time.
Do not add a hosted process that can decrypt. There is no live hosted service, no Nitro EIF, and no full `COSE_Sign1` AWS chain verifier.
10. **Audit retention after shred.** The default is 90 days, as a per-workspace setting, for audit metadata. Does any anticipated contract require immediate deletion of that metadata, including retention-locked anchors? Destruction of client-held keys shreds e2e payloads. Default CI does not use S3 Object Lock.
11. **Second person to approve shred.** For client-held keys, shred is destruction of the decapsulation key and the recovery recipients. Is a two-person rule required for a hosted operator console? The operator already cannot open the secret.
12. **`reveal` for humans, multi-region, and hybrid token signatures.**
A human reveal path exists only in the injector or in the attested enclave. Multi-region must not be solved by copying unwrap keys into the control-plane database. Hybrid token signatures stay as in section 14. The dashboard HTML does not decrypt a secret.
