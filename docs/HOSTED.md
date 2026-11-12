# Hosted beta

Status: public pre-alpha. Tactico would operate the control plane. This page does not claim customers or a certification.

The hosted process is the production control plane in [SELF_HOST.md](SELF_HOST.md). It stores ciphertext, policy, tokens, and the audit log. It does not store a decapsulation key. `RejectingRootKeys` rejects encrypt and decrypt. No hosted mode calls `open_secret`.

The customer injector performs hosted injection. This build does not run an attested enclave. If the injector is down, injection stops. The control plane does not decrypt to replace it.

The audit anchor in this build is an append-only file. It has no delete operation. It is not S3 Object Lock. `credentials-edge` can send an object with compliance-mode headers. Default CI does not start MinIO.

Two workspaces do not share secret rows, sessions, or audit chains. The store keys those rows by workspace id.

Hosted mode sets `TLS_REQUIRE_HYBRID` on. The listener offers only `X25519MLKEM768` (group 4588). A client that does not offer that group cannot connect. Set `CREDENTIALS_TLS_CERT` and `CREDENTIALS_TLS_KEY`.

A signing-key failure stops token issue and audit signatures. The process does not unwrap secrets to hide that failure.
