# Credentials

Agent-native secrets provider by Tactico. You can't commit your `.env`, and you shouldn't paste keys into an AI agent's context either. Credentials gives agents the access they need without ever handing them the raw secret.

## Core idea

- **Scoped, short-lived keys per agent run.** Each agent session (Claude, Codex, Grok, Devin and others) gets credentials scoped to one project and one task, which expire when the run ends.
- **Injected at runtime, never in context.** Secrets are swapped in at the process or gateway layer, so they never show up in prompts, transcripts or model memory.
- **Audit trail.** A log of which agent used which key, when, and for what task.
- **Import what you have.** Start from an existing `.env` file.
- **Bring your own backend.** Teams can keep secrets in Infisical, 1Password or Doppler, with Credentials acting as the agent-facing layer.

## Architecture principle

Credentials is a standalone API and gateway from day one. It is not embedded in Momentum.

- Momentum (and later Momentum Cloud Projects) is the first client, and it talks to Credentials only through the public API, like any other customer would.
- Core concepts (agents, projects, sessions, scopes) stay generic, with nothing Momentum-specific baked in.
- That keeps Credentials ready to spin out as its own product later.

## Design docs

- [Encryption and key management](docs/ENCRYPTION.md). Envelope encryption, key rotation and crypto-shredding, post-quantum key transport, agent tokens, injection, and the audit log. This is the implementation spec for that part of the system.

## Status

Concept stage. No code yet.
