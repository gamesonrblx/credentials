# Hosted beta

Status: public pre-alpha. Tactico would be the operator of the control plane. This page does not claim customers, SOC 2, or any certification.

The hosted process is the production control plane from [SELF_HOST.md](SELF_HOST.md). It stores ciphertext, policy, tokens, and audit. It does not store a decapsulation key. `RejectingRootKeys` refuses encrypt and decrypt. There is no hosted mode that calls `open_secret`.

Hosted injection is the customer injector. An attested enclave is not in this build. If the injector is down, injection fails closed. The control plane does not decrypt to fill the gap.

The audit anchor in this build is an append-only file. It has no delete operation. It is not S3 Object Lock. A restart of a mock in-memory anchor is not used.

Two workspaces do not share secret rows, sessions, or audit chains. The store keys those rows by workspace id.

Hosted mode sets `TLS_REQUIRE_HYBRID` on. The listener offers only `X25519MLKEM768` (group 4588). A client that does not offer that group cannot connect. The certificate and key come from `CREDENTIALS_TLS_CERT` and `CREDENTIALS_TLS_KEY`.

A signing-key outage stops token issue and audit signatures. It is not worked around by unwrapping secrets.
