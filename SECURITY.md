# Security

Credentials stores secrets. Report a vulnerability in private.

Use GitHub private vulnerability reporting:

https://github.com/tacticocc/credentials/security/advisories/new

Do not open a public issue for a suspected vulnerability. Do not include a secret value, a token, or key material in the report.

This repository is pre-alpha. The dev key file contains raw keys. Do not use that file in production. `CREDENTIALS_ENV=production` rejects the dev key file, the dev signer, and the dev audit anchor.

The production control plane does not open an end-to-end secret. The customer injector holds the decapsulation key. There is no operator recovery recipient.
