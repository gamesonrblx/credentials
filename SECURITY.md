# Security

Credentials stores secrets. Please report vulnerabilities privately.

Use GitHub private vulnerability reporting:

https://github.com/tacticocc/credentials/security/advisories/new

Do not open a public GitHub issue for a suspected vulnerability, and do not include secret values, tokens, or key material in a report.

This repository is pre-alpha. The dev root-key provider writes raw keys to a local file and must not be used in production. `CREDENTIALS_ENV=production` refuses that provider.
