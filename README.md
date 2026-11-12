<p align="center">
  <a href="https://github.com/tacticocc/credentials/actions/workflows/ci.yml"><img src="https://github.com/tacticocc/credentials/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

<h1 align="center">Credentials</h1>

<p align="center">
  Pre-alpha gateway for agent secrets.<br>
  The project has no customers and no certification.
</p>

<p align="center">
  <a href="docs/API.md"><strong>Read the API</strong></a>
  ·
  <a href="docs/ROADMAP.md">Roadmap</a>
  ·
  <a href="https://github.com/tacticocc/credentials/security/advisories/new">Report a vulnerability</a>
</p>

## Table of contents

- [About the project](#about-the-project)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Handoff](docs/HANDOFF.md)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgments](#acknowledgments)

## About the project

Credentials gives an agent a short session. The session can call an allow-listed host. The session does not receive the secret in the model prompt.

The dev process can read plaintext. That process stops when `CREDENTIALS_ENV=production`. The production control plane stores ciphertext. It does not open an end-to-end secret. The customer injector holds the decapsulation key. The control plane signs a grant for each release. The injector checks that grant before it opens the secret.

`CREDENTIALS_ENV` accepts `production`, `prod`, `development`, `dev`, and `test`. The process exits on any other value.

This repository is pre-alpha. It does not claim a production SLA.

### Built with

- [Rust](https://www.rust-lang.org/)
- [Tokio](https://tokio.rs/) and [Axum](https://github.com/tokio-rs/axum)
- [rustls](https://github.com/rustls/rustls) with [aws-lc-rs](https://github.com/aws/aws-lc-rs)
- [RustCrypto aes-gcm](https://github.com/RustCrypto/AEADs) for AES-256-GCM
- [RustCrypto x-wing](https://github.com/RustCrypto/KEMs) for X25519 and ML-KEM-768

## Getting started

### Prerequisites

- Install Rust 1.89 or a later stable release.
- Use Cargo from that toolchain.
- On Windows, install the Visual Studio C++ build tools, CMake, and NASM. Keep the checkout path short, or set `CARGO_TARGET_DIR` to a short path.

### Installation

1. Clone the repository.
   ```sh
   git clone https://github.com/tacticocc/credentials.git
   cd credentials
   ```
2. Run the tests.
   ```sh
   cargo test --workspace
   ```
3. Start the dev gateway.
   ```sh
   cargo run -p credentials-gateway
   ```

The dev gateway listens on `127.0.0.1:8080`. Keep that port on the local machine. The dev key file holds raw keys. Do not commit that file.

## Usage

Create a workspace on the loopback listener. Mint a short agent session. Call `POST /v1/inject` with the agent token and a DPoP proof.

Use `proxy` on the public listener. The gateway calls the allow-listed `https` host. It accepts `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. It does not return a response that contains the secret. An allow-listed host that returns the secret in another encoding can still leak it. Allow-list only hosts that you trust.

Use `env` or `header` only on the local socket. Set `CREDENTIALS_LOCAL_DIR`. The directory mode is `0700`.

Read [docs/API.md](docs/API.md) for the routes. Read [docs/INTEGRATION.md](docs/INTEGRATION.md) for the runner steps. Read [docs/SELF_HOST.md](docs/SELF_HOST.md) for production mode.

## Roadmap

The ordered plan is [docs/ROADMAP.md](docs/ROADMAP.md). The current state is [docs/HANDOFF.md](docs/HANDOFF.md).

- M1 stores rows in SQLite and Postgres.
- M2 publishes the HTTP API and the local socket.
- M3 seals end-to-end secrets. The control plane does not open them.
- M4 starts a production control plane and TLS group 4588.
- M5 describes the hosted control plane. No hosted service is live.
- M6 seals a dotenv import in the injector. The dashboard signs in with OIDC and does not decrypt.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository.
2. Create a branch.
3. Add tests for crypto changes and access checks.
4. Run `cargo test --workspace`.
5. Open a pull request.

## License

The license is Apache-2.0. Read [LICENSE](LICENSE).

## Contact

- Repository: [github.com/tacticocc/credentials](https://github.com/tacticocc/credentials)
- Vulnerability report: [private advisory](https://github.com/tacticocc/credentials/security/advisories/new)

Do not send secret values in a report.

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) for AES-256-GCM, X-Wing, and Ed25519.
- [rustls](https://github.com/rustls/rustls) and [aws-lc](https://github.com/aws/aws-lc) for TLS 1.3 and group 4588.
- The README layout follows the section order of the [Best-README-Template](https://github.com/othneildrew/Best-README-Template). The text is for this project.
