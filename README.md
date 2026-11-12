# Credentials

Agent-native secrets provider by Tactico. You can't commit your `.env`, and you shouldn't paste keys into an AI agent's context either. Credentials gives agents the access they need without ever handing them the raw secret.

## Core idea

- **Scoped, short-lived keys per agent run.** Each agent session (Claude, Codex, Grok, Devin and others) gets credentials scoped to one project and one task, which expire when the run ends.
- **Injected at runtime, never in context.** Secrets are swapped in at the process or gateway layer, so they never show up in prompts, transcripts or model memory.
- **Audit trail.** A log of which agent used which key, when, and for what task.
- **Import what you have.** A team brings a secret in once, from a `.env` file or another store. Credentials keeps the value under its own envelope. It does not fetch Infisical, 1Password, or Doppler at inject time.

## Architecture principle

Credentials is a standalone API and gateway from day one. It is not embedded in Momentum.

- Momentum (and later Momentum Cloud Projects) is the first client, and it talks to Credentials only through the public API, like any other customer would.
- Core concepts (agents, projects, sessions, scopes) stay generic, with nothing Momentum-specific baked in.
- That keeps Credentials ready to spin out as its own product later.

## Design docs

- [Architecture](docs/ARCHITECTURE.md). How the pieces fit together today, and the target zero-knowledge design: key hierarchy, injection, account-bound recovery, tokens, and the audit log.
- [Encryption and key management](docs/ENCRYPTION.md). Envelope encryption, key rotation and crypto-shredding, post-quantum key transport, agent tokens, injection, and the audit log. This is the implementation spec for that part of the system.

## Status

Pre-alpha. The encryption design is [docs/ENCRYPTION.md](docs/ENCRYPTION.md). The Rust workspace implements the envelope, a dev key provider, and a small gateway. It is not a production secrets service.

The dev root-key provider stores raw keys in a local file so the process can run without a cloud KMS. It refuses to start when `CREDENTIALS_ENV=production`. Do not point it at real secrets you cannot afford to lose, and do not commit the key file.

## Crates

| Crate | Role |
| --- | --- |
| `credentials-crypto` | AES-256-GCM envelope encryption, KEK wrapping, the `RootKeyProvider` trait, the dev provider, and X-Wing key transport. |
| `credentials-gateway` | Axum server: short-lived tokens, scope checks, decrypt-and-inject, hash-chained audit log. |
| `credentials-client` | Small HTTP client, including DPoP proofs for inject calls. This pre-alpha build speaks plain HTTP to a loopback gateway. |

Crypto uses reviewed crates: RustCrypto `aes-gcm` for AES-256-GCM, RustCrypto `x-wing` for X25519 + ML-KEM-768, and `ed25519-dalek` for token and DPoP signatures. The gateway is Tokio and Axum.

## Build and test

```bash
cargo test --workspace
```

The dev server listens on `127.0.0.1:8080`:

```bash
cargo run -p credentials-gateway
```

`CREDENTIALS_LISTEN` changes the address. `CREDENTIALS_DEV_KEYS` changes the dev key file (default `.credentials-dev-keys.json`). Workspace creation on this listener is unauthenticated so a local process can bootstrap. Keep it on loopback.

## What is still stubbed

Cloud KMS and HSM adapters, TLS with the hybrid `X25519MLKEM768` group, the end-to-end mode, one-shot import, and human login. The dev gateway stores ciphertext in SQLite (or Postgres when `CREDENTIALS_DATABASE_URL` points there) and can proxy-inject to an allow-listed HTTPS host. It still decrypts in process. That is not the production trust model.
