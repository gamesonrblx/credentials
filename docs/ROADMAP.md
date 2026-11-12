# Credentials roadmap

This is the milestone plan for [Credentials](https://github.com/tacticocc/credentials), an AI-native secrets provider. Agents receive scoped, short-lived access. A gateway injects the secret at runtime. The value never enters the agent's context. Every access is written to a per-agent audit log.

Credentials is a standalone API and gateway from day one. Any agent platform or runtime integrates through the public API. The service is open-core under Apache-2.0, with a later licence decision possible. Tactico may operate a hosted offering of that same API, and the design is meant to stay open enough to become an industry standard. Credentials is a direct competitor to Infisical, Doppler, and 1Password, not a layer on top of them. A team switches by importing secrets once. Imported values are envelope-encrypted in Credentials. Keycard is another agent-native project in this space.

The project is pre-alpha. This document does not claim customers, SOC 2, or any certification. It does not assign calendar dates. Milestones are ordered by dependency: later work assumes the exit criteria of earlier ones.

The encryption, key-management, token, injection, and audit design lives in [docs/ENCRYPTION.md](docs/ENCRYPTION.md). The system architecture, including the target zero-knowledge split and account-bound recovery, lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Implementation of what the encryption spec already specifies must follow it. This roadmap says what to build, in what order, and which crates and files it lands in. Where this plan and the spec disagree, the disagreement is called out below and the spec is left for a later revision. This change does not rewrite `docs/ENCRYPTION.md` or `README.md`.

Two current documents still describe the previous product shape:

- `docs/ENCRYPTION.md` section 10 ("External secret backends") tells the gateway to fetch Infisical, 1Password, or Doppler at inject time and to avoid writing those values into the Credentials database. Section 2 lists encrypting data that stays in those products as a non-goal. That will be revised to one-shot import into native envelope encryption.
- `README.md` still says teams can keep secrets in Infisical, 1Password, or Doppler with Credentials as the agent-facing layer. That sentence will be revised with the spec.

Decision 7, the operator section of the threat model, the v1 non-goals, and section 12 still treat gateway decryption as the shipped model and zero-knowledge as optional later work. Milestone M3 below makes zero-knowledge a requirement for both self-hosted and Tactico-hosted production. The spec will be revised when that milestone is designed in detail. It is not revised here.

## How to read the milestones

- **M0** is what is already on `main` (PR #1, the encryption spec; PR #2, the Rust foundation), plus this plan.
- **M2** is the API-bridge MVP: a stable, versioned public API that any agent platform or runtime can integrate against using only the public docs and API. The MVP gateway still decrypts. It is not a production self-host or hosted release.
- **M3** is zero-knowledge against the operator. It is required for both the self-hosted release and the hosted beta.
- **M4** is the first release a third party can self-host, on the M3 trust model, with real signing keys and TLS.
- **M5** is an optional hosted beta of that same public API, operated by Tactico, still without compliance claims. Its exit criteria require zero-knowledge. There is no hosted mode in which Tactico can decrypt.
- **M6** is migration and operator surfaces: one-shot import, human login, and the dashboard.
- **M7** keeps the licence decision and the naming decision, after zero-knowledge has moved out to M3.

M6 and M7 must not block the MVP. M3 blocks M4 and M5.

## Current tree

The Cargo workspace (`Cargo.toml`) has three crates, all `0.1.0`, `publish = false`, Rust 1.89, Apache-2.0. `repository` points at `https://github.com/tacticocc/credentials`.

| Crate | Path | Role |
| --- | --- | --- |
| `credentials-crypto` | `crates/crypto` | Envelope encryption, KEK wrapping, `RootKeyProvider`, dev and in-memory providers, X-Wing key transport. |
| `credentials-gateway` | `crates/gateway` | Axum server: tokens, scopes, decrypt-and-inject, hash-chained audit, dev binary. |
| `credentials-client` | `crates/client` | HTTP client with DPoP proofs. This build speaks plain HTTP to a loopback gateway. |

CI (`.github/workflows/ci.yml`) runs `fmt`, `clippy -D warnings`, `cargo-deny`, and `cargo test --workspace --locked` on Ubuntu, macOS, and Windows. Dependabot watches Cargo and GitHub Actions weekly.

---

## M0 — Pre-alpha foundation

**Status: done on `main`.** This roadmap file is the milestone plan on top of that foundation.

### Goal

Land the encryption spec and a tested Rust skeleton that implements the envelope, a dev key provider, and a small gateway, so later work extends real modules instead of a blank repo.

### Deliverables (what exists)

- `docs/ENCRYPTION.md` — implementation spec for envelope encryption, rotation, crypto-shredding, hybrid key transport, agent tokens, injection, and the audit log (PR #1).
- `docs/ROADMAP.md` — this plan.
- Workspace metadata: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, `.gitattributes`.
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `README.md`.
- `credentials-crypto`
  - `src/aad.rs` — `CRD1` payload and DEK-wrap associated data, with known-answer tests.
  - `src/aead.rs`, `src/envelope.rs` — AES-256-GCM seal/open, `seal_secret` / `open_secret` / `rewrap_dek`, payload bits unchanged across rewrap, fail-closed on bit flips, swapped AAD, bad nonces, and unknown algs.
  - `src/kms.rs` — `RootKeyProvider` (`CreateTenantRoot`, `Encrypt`, `Decrypt`, `ScheduleDestruction`, `CancelDestruction`), `KekContext`, `MemoryRootKeys`, `DevFileRootKeys`, `DevPolicy` that refuses construction when `CREDENTIALS_ENV=production`, `CountingProvider` for tests.
  - `src/hybrid.rs` — X-Wing (X25519 + ML-KEM-768) wrap/unwrap of a 32-byte key. The gateway-decrypts path does not call this. It is reserved for later application-level transport and the zero-knowledge mode in M3.
  - `src/random.rs`, `src/error.rs`.
- `credentials-gateway`
  - `src/store.rs` — `Store` trait and in-memory `MemoryStore`. The trait is the intended seam for a later SQLite or Postgres adapter. `insert_version` is on the trait but has no service or HTTP caller yet.
  - `src/token.rs` — in-process Ed25519 JWT issuer/verifier (`DevSigner`). Audience `credentials-gateway`, default TTL 5 minutes, hard max 15. The token is identity and scope, not a decryption key. A production issuer would use KMS Sign; this signer is refused when `CREDENTIALS_ENV=production`.
  - `src/dpop.rs` — DPoP (RFC 9449) with Ed25519 and RFC 7638 thumbprints.
  - `src/policy.rs` — delivery-policy validation, scope matching, host checks. Agent sessions may only hold `secret:inject:...`.
  - `src/audit.rs` — workspace and per-agent hash chains as specified (`hash = SHA-256(prev_hash || body)`). No checkpoints, signatures, or external anchor yet.
  - `src/service.rs` — workspace create (tenant root + first KEK + hashed workspace credential), secret create, agent and session create, session revoke, proxy inject (audit `secret.access.allowed` before unwrap; refuse decrypt if the append fails), KEK rotation with in-process rewrap, workspace deletion that sets `deleting` and schedules root-key destruction (7-day wait). KEK cache with a 60-second TTL. Env and header delivery are refused unless `local_channel` is set; the HTTP listener never sets that flag.
  - `src/http.rs` — `POST /v1/workspaces`, `/v1/secrets`, `/v1/agents`, `/v1/agent-sessions`, `/v1/agent-sessions/{id}/revoke`, `/v1/inject`, `/v1/kek/rotate`, `/v1/workspaces/{id}/deletion`, `GET /v1/audit`, `GET /healthz`. Workspace creation on this listener is unauthenticated so a local process can bootstrap.
  - `src/upstream.rs` — `Upstream` trait, `RecordingUpstream` for tests, `UnconfiguredUpstream` for `cargo run` (inject returns an upstream error until a real client is wired).
  - `src/main.rs` — binds `127.0.0.1:8080` (or `CREDENTIALS_LISTEN`), loads `.credentials-dev-keys.json` (or `CREDENTIALS_DEV_KEYS`), exits if `CREDENTIALS_ENV=production`.
  - `src/redact.rs`, `src/names.rs`, `src/error.rs`, `src/b64.rs`.
- `credentials-client` — `create_workspace`, `create_secret`, `create_agent`, `create_session`, `inject` with DPoP. `reqwest` is built without a TLS backend.
- Tests covering spec items 1–13 in outline: AAD vectors, seal/open, integrity failures, rewrap leaving payload bytes unchanged, wrong KMS context, production-policy refusal, revoked/expired/wrong-DPoP tokens, zero KMS calls on deny, no decrypt when audit append fails, deleting workspace fails inject before `Decrypt`. Cross-platform CI is green.

### What is still stubbed after M0

Cloud KMS and HSM adapters; TLS, including `X25519MLKEM768`; audit checkpoints and an external anchor; a durable database; `POST /v1/secrets/{name}/versions`; cancel-deletion and a shred poller; tenant-root rotation to a new key id; local-channel env/header delivery; a real upstream HTTP client; one-shot import and migration into native secret versions; human login and a dashboard; zero-knowledge mode. The gateway still decrypts. `SealedSecret` has no `wrap_mode` or `e2e_encapsulation` column. `Gateway::new` refuses `CREDENTIALS_ENV=production`, so there is not yet a production constructor path. That refusal only blocks the dev key file. It does not hide plaintext from an operator who runs the dev process.

### Exit criteria

Met: the spec is in-tree, the three crates build and test on the CI matrix, the dev provider cannot be constructed in production, and a loopback gateway can create a workspace, store a secret, mint a DPoP-bound session, proxy-inject through a test upstream, rotate a KEK, and schedule shred, with the audit chain verifying.

### Dependencies

None.

---

## M1 — Durable v1 core

### Goal

Finish the remaining storage, audit, and API seams from `docs/ENCRYPTION.md` on a store that survives a process restart, still using the dev (or in-memory) root-key provider. After this milestone the gateway is a real single-node service, not only a memory-backed skeleton. It is still the gateway-decrypts design. M3 is what changes who can open a secret.

### Deliverables

- A durable `Store` implementation of `crates/gateway/src/store.rs` (engine decided under Open questions). Logical schema follows `docs/ENCRYPTION.md` section 7, including `wrap_mode` and a null `e2e_encapsulation` column so M3 does not need a meaning-changing migration of gateway-wrapped rows. Writers must reject `wrap_mode = e2e` until M3 exists. The Rust `SealedSecret` struct does not have these fields yet.
- Migrations and a restart test: a sealed secret created before shutdown opens after startup with the same payload.
- `Gateway` methods and HTTP routes that the store already anticipated or the spec already named:
  - `POST /v1/secrets/{name}/versions` — use `Store::insert_version`; updating a secret creates a new version, it does not overwrite ciphertext.
  - `POST /v1/workspaces/{id}/deletion/cancel` — call `RootKeyProvider::cancel_destruction` and return the workspace to `active` only while the key is still pending destruction.
  - A shred poller that observes KMS destruction and sets `status = shredded`, appending `tenant.shredded`.
  - On `DeleteWorkspace`, revoke every session and workspace credential, drop cached KEKs, then hygienically delete secret and KEK rows after scheduling destruction. Audit rows stay.
- Audit checkpoints and an `AuditAnchor` trait (`crates/gateway/src/audit.rs` and a new module, for example `crates/gateway/src/anchor.rs`). Dev implementation appends to a local file and is refused when `CREDENTIALS_ENV=production`. Sign the tip every 1,000 events or 60 seconds and on shutdown, as in section 9. After `AUDIT_ANCHOR_MAX_LAG`, inject returns 503 `audit_anchor_unavailable`.
- A real `Upstream` HTTP client in `crates/gateway/src/upstream.rs`: HTTPS only, overwrite (do not append) the configured header, do not follow redirects, do not copy the secret header back. `cargo run` can then proxy-inject against a configured allow-listed host.
- KEK-cache singleflight per KEK id (the 60-second TTL in `service.rs` already exists). Drop entries when the workspace is no longer `active`. In the gateway-decrypts process this cache holds unwrapped KEKs. M3 must not leave that cache in an operator-controlled control plane.
- Tenant-root rotation to a new key id (rewrap KEKs only; payloads and DEKs stay) can land here if it stays small; otherwise it waits until a cloud KMS adapter exists. On the production path, M3 and M4 decide whether a control-plane KMS key is allowed to unwrap secret DEKs at all. The default for production is that it is not.
- Docs hygiene, because implementers still read these files as source of truth:
  - Update the status line in `docs/ENCRYPTION.md` ("No code in this repository implements it yet" is stale). Record Rust as the implementation language of record, and treat the remaining Go TLS notes as guidance for the hosted/self-host TLS stack rather than as a second codebase.
  - Revise section 10, the section 2 non-goal about external products, and the README "bring your own backend" bullet so they match this roadmap: one-shot import, native envelope encryption, zero-knowledge against the operator. Do that in the PR that changes the product behavior, with the spec and the code together.

Repository URLs already point at `https://github.com/tacticocc/credentials` (`Cargo.toml` `repository`, and the private-advisory link in `SECURITY.md`).

### Exit criteria

- Killing and restarting the gateway leaves existing workspaces, secrets, sessions, and the audit chain intact.
- Creating a second version, cancelling a pending shred, and completing a shred all work, with the corresponding audit events, and inject fails closed on a `deleting` or `shredded` workspace before any `Decrypt`.
- Rewrap remains safe to run twice (spec test 15).
- A failed audit append or a lagged anchor still prevents decrypt on the gateway-decrypts path.
- A configured upstream succeeds on `cargo run` for an allow-listed HTTPS host; redirects and header-append are tested and rejected.
- The spec's status line no longer claims that no code implements the envelope.

### Dependencies

M0.

---

## M2 — API-bridge MVP

### Goal

Publish a stable, versioned public API and a generic client so any agent platform or runtime can integrate with the gateway. The API stays integrator-agnostic: no platform-specific types, and a third party should not need to read gateway internals.

This milestone still uses the gateway-decrypts path in `Gateway::inject`. It is the MVP for API shape and delivery. It is not zero-knowledge, and it is not the self-hosted or hosted production release.

### Deliverables

- An integrator-facing API document (for example `docs/API.md`) and a machine-readable OpenAPI description of the `/v1` routes, including error codes from `docs/ENCRYPTION.md` section 10. Core concepts stay generic: agents, workspaces, sessions, scopes. Name no specific product as the first client.
- Authenticated workspace bootstrap. Unauthenticated `POST /v1/workspaces` is acceptable only on a loopback dev listener. A self-host or shared process needs an operator credential, and issuer, audience, and listen addresses must be configurable (today `ISSUER` is hardcoded to `https://credentials.local/v1`).
- Proxy injection on the public listener, which is the default delivery path for API keys, plus local-channel delivery for `env` and `header` as specified: a Unix socket in a mode-`0700` directory with peer-uid checks (`SO_PEERCRED` or the platform equivalent), or TLS to loopback with a per-session client certificate. The public listener continues to refuse env and header modes. Response bodies match the spec (`{ env_name, value }` / `{ header_name, value }`). Header delivery must not be implemented as a second proxy-forward path (the current `service.rs` branch still sends header mode through `Upstream`).
- `credentials-client` brought up to the full MVP surface (new versions, revoke, audit, deletion/cancel, TLS). Keep secret values off logs. Additional language SDKs, if prioritized under Open questions, live out of tree or under `sdks/`.
- Disabled secrets, session listing/revocation, and audit export (`GET /v1/audit?agent_id=…` already exists; include hashes so a client can recompute the agent chain; include the latest checkpoint signature once M1 anchors exist).
- An integration guide aimed at a control plane or runtime that holds the workspace credential, mints 5-minute DPoP-bound sessions, and keeps both the workspace credential and, preferably, the agent token out of the model loop. Prefer `proxy` delivery for API keys on the public listener; `env` and `header` are for a local or single-tenant runner channel. The guide must not name a house client.
- HTTP-level tests in `crates/client/tests` and `crates/gateway/tests` for the new routes and the local channel, plus the log-canary test from spec item 14 if it is not already end-to-end.

Production import from other secret managers, and from `.env` files, is M6. An M2 loopback helper that seals under the dev KEK would teach the wrong production path. Do not add it here.

### Exit criteria

- A fresh operator can start the gateway, create secrets, mint an agent session, and have a runner call an allow-listed HTTPS upstream through `POST /v1/inject` without the secret appearing in the agent context, the response, or the logs.
- Env and header delivery work only on the local channel and are forbidden on the public listener.
- An arbitrary third-party agent runtime can integrate using only the public docs and API, without reading gateway internals, and nothing in the API is specific to one integrator.
- CI stays green on the three-OS matrix.
- The MVP docs say plainly that this gateway can read secret plaintext.

### Dependencies

M1 (durable store, versioning, real upstream, audit anchor).

---

## M3 — Zero-knowledge against the operator

### Goal

Make zero-knowledge a core property of both a self-hosted deployment and the Tactico-hosted service. The operator of the control plane, Tactico included when Tactico is the operator, must not be able to see secret plaintext or the keys that decrypt it.

The current design is not yet zero-knowledge against the operator. M1 and M2 may keep the gateway-decrypts path so the API, the store, and the audit chain exist. They must not be what M4 or M5 ship as production.

### Where the code and the spec are today

Plaintext and unwrap keys are available to whoever operates the gateway process.

- `docs/ENCRYPTION.md` decision 7 says the gateway-decrypts model ships first: the gateway unwraps keys through the KMS, decrypts, and injects. The same decision defers a client-held X25519+ML-KEM mode because the gateway then cannot inject on its own. Section 2 lists end-to-end / zero-knowledge as a non-goal for v1 and says writers emit `wrap_mode = gateway` only. Section 3 ("Insider and operator") states that an operator who can change gateway code, dump gateway memory, or call the KMS with the gateway role can read secrets while serving traffic, and that v1 accepts this for the hosted operator and for a customer who self-hosts. Section 12 records the later mode and says it is not built.
- `Gateway::inject` in `crates/gateway/src/service.rs` always unwraps the workspace KEK (`unwrap_kek` calls `RootKeyProvider::decrypt`) and then calls `open_secret`, which unwraps the DEK and opens the AES-256-GCM payload inside the gateway process. Proxy and header delivery copy the plaintext into an upstream header. Env delivery returns the plaintext in the response body. The audit event `secret.access.allowed` is committed first, and a failed append skips decrypt. That ordering is an audit control. It does not keep the operator from seeing the value after the append succeeds.
- Unwrapped KEKs sit in a process-local cache (`KEK_CACHE_TTL`, 60 seconds) in that same process.
- `crates/crypto/src/kms.rs` `DevFileRootKeys` writes raw 32-byte tenant root keys to `.credentials-dev-keys.json` (override `CREDENTIALS_DEV_KEYS`). `MemoryRootKeys` holds the same raw keys in process memory. `main.rs` and `Gateway::new` exit or return an error when `CREDENTIALS_ENV=production` because this build only has the dev provider. That is a production guard for a laptop key file. A future cloud KMS behind the same `Decrypt` call would still let the gateway role open every secret. The operator who can read the key file, the process memory, or that KMS role can open the database.
- `SealedSecret` in `crates/crypto/src/envelope.rs` stores payload ciphertext, DEK wrap, nonces, and algorithms. There is no `wrap_mode` and no `e2e_encapsulation`. Every row is gateway-wrapped under the workspace KEK. The schema in the spec reserves `wrap_mode IN ('gateway', 'e2e')` and a null `e2e_encapsulation`. The running store does not.
- `crates/crypto/src/hybrid.rs` can generate an X-Wing keypair and wrap a 32-byte key to the encapsulation key (associated data `credentials.hybrid.wrap.v1`). The module comment says the gateway-decrypts path does not call it. Nothing in `credentials-gateway` uses it to store or open a secret. Section 12's `CRD2` encoding, passphrase wrapping of the decapsulation key (Argon2id), and the rule that writers reject `wrap_mode = e2e` until the mode exists are not implemented.
- A token is already not a decryption key (`crates/gateway/src/token.rs`, spec decision 6). A stolen token cannot open a database dump offline. That property is necessary and it is not zero-knowledge. The gateway that honors the token still decrypts.
- Secret names are stored in the clear, by design, so the gateway can authorize before it opens a value. Zero-knowledge here is about plaintext and unwrap keys, not about hiding names.

Section 12 is the right starting point for architecture (i) below. It does not describe confidential-computing enclaves, and it does not require the property for v1. Both gaps are in scope for this milestone. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) records the target split, the enclave key-release flow, and account-bound recovery. The `docs/ENCRYPTION.md` revision that replaces decision 7 still lands with the M3 implementation, not in the roadmap.

### Architecture (i) — customer-run injector

The hosted or self-hosted control plane stores ciphertext, policy, tokens, and the audit log. It does not store a decapsulation key, an unwrapped KEK, or an unwrapped DEK, and it does not call `open_secret`.

A customer-run gateway, injector, or sidecar holds the X-Wing decapsulation key from section 12. That key is generated on a machine the control-plane operator does not control. The encapsulation key is registered with the control plane. The decapsulation key stays with the customer. Account-bound recovery in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) wraps it to enrolled devices, WebAuthn PRF passkeys, an offline recovery kit, and optional admin teammates. `hybrid.rs` is the primitive to start from; wiring it into `seal_secret` / `open_secret` and persisting `e2e_encapsulation` is the work.

Injection (env, header, or proxy) happens in the customer component. The control plane's job on an inject attempt is authorization and audit: check the DPoP-bound token, the scope, the delivery policy, and revocation; append `secret.access.allowed` before releasing anything; on audit failure, release nothing. What it releases is ciphertext the customer component can open, or a grant that points at that ciphertext. It does not release plaintext.

This is the self-hosted production shape as well. "Self-hosted" means the customer runs the control plane. The people who administer that database and that process are the operator, and they must not be able to open secrets. The workload owner runs the injector, with the decapsulation key, in a separate trust domain from the control-plane administrators. A single process that both stores the rows and holds the dev root key is the M0/M2 dev path only.

### Architecture (ii) — hosted injection inside an attested enclave

Some callers will want the operator to perform proxy injection without running a sidecar. That path exists only inside a confidential-computing enclave, for example an AWS Nitro Enclave or an AMD SEV-SNP guest. The control plane outside the enclave still stores ciphertext, policy, tokens, and audit, and still has no `Decrypt` on secret-wrapping keys.

Key release is bound to a remote attestation of the enclave image. The customer, or a release service the customer trusts, checks the measurement (the image identity and the configuration that measurement commits to) before the decapsulation key or the unwrap key enters the enclave. Operator staff and the parent host see the host-side process. They do not get a measurement that matches a different binary, and they do not receive the key. Substituting a gateway build that prints plaintext fails attestation, and the key is not released.

The current binary cannot be dropped into an enclave and called zero-knowledge. `Gateway::inject`, the KEK cache, and `DevFileRootKeys` assume a normal process whose memory the host can read. The enclave image has to be a small unwrap-and-inject path. Attestation, the measurement log, and the release policy are product surface, not a cloud checkbox on the existing Axum server. The host-side proxy that feeds the enclave must not be given the plaintext. Upstream calls that leave the enclave carry the secret only on the intended request, which is the same exposure the upstream already has in the spec's proxy mode.

Section 12 does not specify this architecture. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the design note for it, and the enclave path is not implemented until that note and the code agree. Hardware attestation is a trust in the CPU vendor and in the published measurement. It is not a claim that the operator is unable to interfere with availability.

### Architecture (iii) — tradeoffs

These are the costs of the property. They should be stated in the product, not smoothed over.

**Key recovery.** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) specifies account-bound recovery, and this milestone implements it. The workspace key is wrapped to several recipients the customer controls: each enrolled device, passkeys through the WebAuthn PRF extension, an offline recovery code or kit, and optionally admin teammates who can re-share. It is never wrapped to an operator-held key. Logging in does not recover the key. Losing every recipient loses the data, and the operator cannot reconstruct it. If Tactico or the control-plane operator held a recovery recipient, those secrets would not be zero-knowledge against them. Destroying a tenant root in the KMS crypto-shreds gateway-wrapped rows only. Section 12 wraps an e2e DEK to the client workspace key, so KMS destruction does not shred those versions. Shredding them means destroying every recipient that can open the workspace key, including devices, passkeys, the recovery kit, and any teammate copies. A backup of any one recipient undoes that shred.

**Revocation.** Today `Gateway::inject` loads the session, rejects a revoked session, and only then unwraps. The same process decides and decrypts, so a revocation on the primary is visible on the next request. Once the customer holds the decapsulation key and a copy of the ciphertext, they can open the value without asking the control plane. Revocation still stops the supported injector if that injector must fetch the ciphertext (or a per-access grant) from the control plane, the control plane checks `revoked_at` and the `jti` table first, and a failed audit append returns nothing. Revocation does not stop someone who already copied the key and the ciphertext. Token lifetime does not close that hole. The product has to say so.

**Audit.** The hash chain stays meaningful for requests that go through the control plane, because the control plane can refuse to release ciphertext when the allow event cannot be written. It cannot prove that a sidecar which already had the key refrained from decrypting. What is lost, relative to the gateway-decrypts model, is the operator's ability to inject on the customer's behalf from the control plane, the ability to debug by reading a secret, the KEK cache in the operator's process, and proxy injection from a normal hosted multi-tenant process. What is kept is authorization, DPoP, scope, and an audit log for the supported path, plus a database that the operator cannot open.

**Enclave-specific loss.** Attested injection adds a dependency on the hardware vendor, on the measurement the customer pinned, and on enclave I/O that must not leak plaintext to the host. Crash dumps, debug consoles, and a host-visible swap file are incompatible with the claim. Availability of injection follows the enclave and the attestation service. The control plane can still revoke by refusing to pass ciphertext in, and it still cannot see the opened value.

### Deliverables

- A short design revision, written with the implementation, that replaces decision 7 and section 12's "not in v1" status: production self-host and the hosted service are zero-knowledge against the operator; the loopback dev gateway may still decrypt and must refuse `CREDENTIALS_ENV=production`. This roadmap PR does not make that spec edit.
- Persist `wrap_mode` and `e2e_encapsulation` (M1 reserves the columns). `wrap_mode = e2e` stores the X-Wing encapsulation and a DEK wrap under the X-Wing shared secret. Pick one encoding, write it down as `CRD2`, and add the draft-11 X-Wing test vectors when this mode lands. `hybrid.rs` is the starting point. Its current associated data (`credentials.hybrid.wrap.v1`) is not yet the stored secret format.
- Customer-run injector: a separate binary or mode that holds the unlocked decapsulation key and performs env, header, and proxy injection. The control-plane `inject` path refuses to call `open_secret` for `wrap_mode = e2e`, and the production control plane has no code path that loads a decapsulation key or a tenant root that unwraps secret DEKs.
- Account-bound recovery, specified in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and implemented before the mode is called generally available. The workspace key is wrapped to several recipients the customer controls, and never to an operator-held key:
  - Multi-recipient wrapping. A client that already holds the workspace key produces each new wrap. The control plane stores the wrapped blobs and the public encapsulation keys.
  - Device enrollment. Each enrolled device has its own X-Wing keypair. Only the encapsulation key is registered.
  - Passkeys through the WebAuthn PRF extension. The PRF output unwraps the workspace key on the client and is not uploaded.
  - An offline recovery code or kit, generated on the client and shown once.
  - Optional admin teammates, as further customer-held recipients for re-sharing.
  - No operator recipient. The control plane, its KMS role, and a login session are not recipients. Logging in alone cannot recover the workspace key.
- Control-plane release rules: revocation and the audit append run before any ciphertext or grant is released; audit failure releases nothing; released bytes are not plaintext.
- For hosted injection, an enclave image of the unwrap-and-inject path, remote attestation, and key release bound to the attested measurement. If this path is not ready, hosted production still ships architecture (i) only. It does not fall back to a normal gateway that decrypts.
- Tests: an operator-level process with the database, the control-plane IAM, and no customer key cannot open a secret; a customer component with the key can inject; a revoked session receives no ciphertext; a failed audit append releases nothing; a gateway-wrapped dev row still opens only in the dev process; an enclave release, when that path exists, refuses a measurement that is not the pinned one.

### Exit criteria

- The control-plane operator cannot read secret plaintext or the keys that decrypt it, in the self-hosted production configuration and in any configuration intended for Tactico to host.
- A database dump plus control-plane credentials is not enough to open an e2e secret. Opening it requires the customer-held decapsulation key or a key released only to an attested enclave measurement.
- Existing `wrap_mode = gateway` rows, used by the dev path, keep their meaning. Production startup does not serve them from the control plane.
- Recovery and the revocation/audit limits above are written down in the spec revision and in the operator docs.
- Account-bound recovery matches [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). A second device can be enrolled from an existing customer recipient. A lost device can be replaced from another device, a WebAuthn PRF passkey, the recovery kit, or an admin teammate recipient. An operator who has the database, the control-plane credentials, and a login session, and who has no customer recipient, cannot unwrap the workspace key. There is no operator-held recovery recipient. Losing every recipient loses the data, and the docs say so.
- The dev root-key file and `Gateway::inject`'s current decrypt path still exist for loopback development and still refuse `CREDENTIALS_ENV=production`.

### Dependencies

M2, for a stable public API and delivery modes. The schema columns reserved in M1 are assumed. M4 and M5 depend on this milestone.

---

## M4 — Self-hostable release

### Goal

Ship an open-core release a third party can run in their own environment. Production secret custody is the M3 zero-knowledge architecture: the people who operate the control plane cannot open secrets. The customer-run injector can. This is the first tagged release that is more than a dev binary.

### Deliverables

- Packaging of the control plane and the customer-run injector: container images, a compose or equivalent example with the chosen database, and a documented config surface (`CREDENTIALS_LISTEN`, `CREDENTIALS_ENV`, signing keys, TLS, anchor, issuer, injector). Ops docs for backup, enrollment, recovery, shred of client-held keys, and key-file hygiene for the remaining dev path.
- KMS or HSM for non-exportable token-signing and audit-signing keys (`signing_keys`, KMS Sign). The production control-plane role does not get `Decrypt` on keys that wrap secret DEKs. A cloud KMS adapter that implements `RootKeyProvider::decrypt` may exist for the dev gateway and for a one-time migration read inside the customer-held component. Production startup fails if the control plane is configured with that decrypt role. One cloud provider is enough; which one is an open question. PKCS#11 is explicitly later. Integration tests that talk to a real KMS are gated on credentials and do not run in default CI.
- Replace `DevSigner` for production. `CREDENTIALS_ENV=production` refuses the dev root-key provider, the dev signer, and the dev audit anchor, and it starts when the production signer, anchor, and zero-knowledge configuration are present. `Gateway::new` today returns `KmsUnavailable` for every production start, because the dev policy check sits in the only constructor. The production constructor is new, and it must not take a secret-unwrapping `RootKeyProvider`.
- Public TLS listener: TLS 1.3, prefer `X25519MLKEM768` (RFC 10024, group 4588), metric `tls_classical_kex_total`, flag `TLS_REQUIRE_HYBRID` (off by default for older local tools). Spec test 16: a client that offers the hybrid group negotiates 4588. `credentials-client` gains a TLS backend.
- The metrics and log-redaction rules in section 13, beyond the current `metrics_integrity` counter and field-name denylist. Logs and traces from the control plane have no plaintext to redact because the process never opens secrets. The injector still redacts.
- Still Apache-2.0, still pre-certification. The release notes must not claim SOC 2, customers, or a production SLA.

### Exit criteria

- A self-hoster can bring up the control plane and a customer-run injector, create a workspace, enroll a client key, inject over TLS, and revoke a session, without the control-plane process being able to open the secret.
- `CREDENTIALS_ENV=production` fails closed if any dev backend is selected or if the control plane is given a secret-unwrapping key, and it starts cleanly when neither is true.
- Hybrid TLS is tested. Default CI still runs without cloud credentials.
- Documentation is sufficient to deploy without reading the source.
- The release notes make no SOC 2, customer, or certification claim.

### Dependencies

M3. The signing-key adapter and TLS can be prototyped in parallel with M2, but the release assumes the MVP API and the zero-knowledge split.

---

## M5 — Hosted beta

### Goal

Operate an optional multi-tenant hosted beta of the same public API, with Tactico as the host, while remaining honest about pre-certification status. Tactico is the operator of the control plane. Zero-knowledge against that operator is an exit criterion, not a follow-up.

### Deliverables

- Hosted deployment of the M4 control plane. It stores ciphertext, policy, tokens, and audit. It does not store decapsulation keys. It has no KMS `Decrypt` permission on keys that wrap customer secrets, and it does not run the dev root-key provider.
- Hosted injection, if it is offered at all, runs only as architecture (ii) from M3: an attested enclave, with key release bound to the enclave measurement, so operator staff and the host cannot unwrap keys. If the enclave path is not in this beta, callers inject from a customer-run injector (architecture (i)) against the hosted control plane. There is no third mode in which a normal Tactico process decrypts.
- Hosted audit anchor: an object store with retention lock (S3 Object Lock or equivalent), keyed by `{workspace_id}/{seq}`. The publisher can put objects and cannot delete them. The gateway's database role has no permission on the bucket.
- Multi-tenant hardening: rate limits, per-workspace isolation, request ids in the audit log, operator runbooks for fail-closed behavior when attestation or the customer injector is unavailable, integrity-failure and anchor-lag alerts. A KMS outage of a signing key fails token issue and audit signing. It must not be papered over by unwrapping secrets in the control plane.
- The metrics in section 13 that still apply to a control plane that does not decrypt secrets: `crypto_integrity_failure_total` where the injector reports it, `inject_total`, `token_denied_total`, `tls_classical_kex_total`, `audit_anchor_lag_seconds`. KMS decrypt metrics apply to the enclave or the customer injector, not to a Tactico-operated decrypt path. Do not add a hosted dashboard counter that requires plaintext.
- A narrow hosted operator path to create a workspace and issue the first workspace credential. Full human SSO and a dashboard are M6. That path returns the credential once and does not return secret values.
- `TLS_REQUIRE_HYBRID=true` on the public listener.
- Status, data-handling, and threat-model pages that restate the pre-alpha/beta limits and the zero-knowledge claim in the words the deployment actually meets. No customer logos, no SOC 2, no certification claims.

### Exit criteria

- There is no hosted mode in which Tactico can decrypt secret plaintext or the keys that decrypt it. A hosted configuration that calls `open_secret`, holds a dev key file, or grants the control plane `Decrypt` on secret-wrapping keys fails this milestone.
- Two isolated workspaces can be created in the hosted environment. Ciphertext, tokens, and audit chains do not cross tenant boundaries. Destroying one workspace's client-held keys does not open or destroy the other workspace's secrets.
- Hybrid TLS is required. Dev providers cannot be enabled.
- Alerts fire on integrity failures reported by the injector or enclave, on attestation or key-release failure, and on anchor lag.
- Public wording stays within what is actually operated. The beta does not claim customers, SOC 2, or any certification.

### Dependencies

M4. The zero-knowledge exit criteria are M3's, applied to a deployment Tactico operates.

---

## M6 — Migration and operator surfaces

### Goal

Give a team a one-shot way to move secrets into Credentials, and give humans a way to administer workspaces without being the agent. Credentials stores the imported secrets itself, envelope-encrypted under the M3 customer-held key.

### Deliverables

- One-shot import and migration tooling from Infisical, Doppler, 1Password, HashiCorp Vault, and `.env` files. The tool reads the source once, seals each value as a native Credentials secret version inside the customer-run injector (or inside the attested enclave), and discards the source bytes. The control plane receives ciphertext. It does not receive the imported plaintext, and it does not keep a live connection that fetches those products at inject time.
- The import path is not a set of backend adapters. After import, injection uses only Credentials ciphertext. A failure during import fails closed, leaves no partial plaintext on the control plane, and is visible to the operator of the importer as a failed item rather than as a stored secret.
- Human identity, SSO, and a dashboard. These are explicit non-goals of the v1 crypto spec and need their own design docs before code. Workspace credentials remain the bootstrap admin secret. They are not replaced by a session cookie on inject routes. The dashboard talks to the control plane for policy, agents, sessions, and the audit log. Showing a secret value is possible only in the customer-run injector or the attested enclave, with a stronger audit reason. Agent tokens must be unable to mint that scope. A hosted page that decrypts in Tactico's control plane does not meet M5.
- Customer-held keys for enrollment and recovery stay in this operator surface when the UX needs them: the human who administers the workspace can see that a key is enrolled and can start a recovery with a customer-held recipient. The control plane still never receives the decapsulation key.

`docs/ENCRYPTION.md` section 10 and the related non-goal in section 2 still describe Infisical, 1Password, and Doppler as live backends. `README.md` still describes Credentials as a layer in front of them. Those documents will be revised with the import work. This roadmap does not rewrite them.

### Exit criteria

- An import from each supported source produces envelope-encrypted Credentials versions, then discards the source bytes. A later inject does not call Infisical, Doppler, 1Password, Vault, or the `.env` file.
- The control plane's database and logs contain no imported plaintext. Opening an imported secret requires the customer-held key or an attested enclave.
- A human operator can sign in, manage agents, policy, and sessions, and read the audit log, without an agent token gaining any new power, and without the control plane gaining a decrypt path.
- A failed import does not write plaintext and does not create a version the operator can open.

### Dependencies

M4 is enough for a self-hosted importer. M5 is required before the same importer is offered against the hosted control plane. The human-identity design doc is a dependency of the dashboard, not of the importer.

---

## M7 — Licence and naming

### Goal

Decide the long-term licence and the public name, now that the product has a shape. Zero-knowledge is M3. This milestone does not reopen it.

### Deliverables

- Licence decision: stay Apache-2.0, or move new work to FSL or AGPL, with a written reason and a plan for existing contributors and self-hosters.
- Naming decision: keep Credentials, or adopt a name such as Credena, including crate, issuer, and documentation impact.
- Later, non-blocking items that can share this milestone or follow it: PKCS#11 for the signing-key provider, hybrid signatures on tokens (Ed25519 plus ML-DSA-65) once a reviewed library and a signing-key story exist.

### Exit criteria

- Licence and name are decided in writing, and the repository, crates, and docs match.
- Neither decision adds a hosted mode in which the operator can decrypt.

### Dependencies

M4 at minimum, so the decision is about a release people can run. M5 and M6 may still be open.

---

## Open questions

These are unresolved. A written decision, or "build the default until we decide," unblocks the work. None of them should reopen the envelope, the token check, or the audit chain. The first four shape M1–M4; the rest can wait. Zero-knowledge against the operator is not an open question. M3, M4, and M5 require it.

1. **Durable storage engine.** The spec's logical schema is Postgres. `Store` comments also mention SQLite. Is Postgres the only supported engine for M1/M4, with SQLite acceptable for laptop dev, or is a single engine mandatory from M1?
2. **First signing-key provider.** AWS, GCP, or Azure — one is enough for the production signer and audit signer in M4. Which provider should the first adapter and the self-host docs lead with? If a hosted offering is operated later, should it use the same provider? This key signs tokens and audit tips. It is not a licence to wrap secret DEKs for the control plane.
3. **SDK language priorities.** A Rust client exists. Which additional languages (for example TypeScript or Go) should follow, in what order, and do those SDKs live in this repository or out of tree?
4. **Naming.** Stay Credentials, or move to a name such as Credena, for the crate names, the JWT issuer, and any hosted product? Deciding after M2 avoids a mid-integration rename. Deciding at M7 is the latest responsible moment.
5. **Licence.** Remain Apache-2.0 through the self-host release, or choose FSL or AGPL at M7? Existing `LICENSE` and crate metadata assume Apache-2.0.
6. **Default delivery path.** Confirm that M2 treats `proxy` as the required path on the public listener, and local-channel `env`/`header` as the secondary path for a runner on the same machine or a single-tenant worker. Under M3 the process that performs that delivery is the customer-run injector, or an attested enclave for hosted proxy injection.
7. **Workspace bootstrap in hosted and self-host.** Who is allowed to call `POST /v1/workspaces` once the listener is no longer loopback-only?
8. **Recovery ceremony details.** The account-bound model is specified in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and is an M3 deliverable: multi-recipient wrapping, device enrollment, WebAuthn PRF passkeys, an offline recovery kit, optional admin re-sharing, and no operator recipient. Logging in does not recover keys. Losing every recipient loses the data. Still open: the exact recovery-kit encoding and which passkey transports the first client supports. Not open: whether the operator may hold a recovery key. The operator must not.
9. **Hosted injection mechanism.** Architecture (i) is sufficient for the M5 exit criteria. Whether the beta also offers architecture (ii), and which enclave technology is first, can be decided without adding a decrypt-capable hosted process.
10. **Audit retention after shred.** Default 90 days, per-workspace setting, for audit metadata. Does any anticipated contract require immediate deletion of that metadata, including retention-locked anchors? Client-held key destruction is what shreds e2e payloads.
11. **Second person to approve shred.** For client-held keys, shred is destruction of the decapsulation key and the recovery recipient. Is a two-person rule required for the hosted beta's operator console, given that the operator already cannot open the secret?
12. **`reveal` for humans, multi-region, hybrid token signatures.** A human reveal path exists only inside the customer injector or the attested enclave. Multi-region must not be solved by copying unwrap keys into the control-plane database. Hybrid token signatures stay as in section 14.

Doc nit that does not need a product decision, but should be cleaned up when M1 touches the spec: `docs/ENCRYPTION.md` still says no code implements it and still discusses Go TLS as the implementation language. The external-backend text and the v1 gateway-decrypts decision are product changes, tracked in M3 and M6, not nits.
