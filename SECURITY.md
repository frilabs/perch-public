# Security

Perch handles account tokens, mailbox passwords, browser sessions and private provider data. Run it for one operator on a trusted host. A compromised host, encryption key, full client token or provider credential can compromise connected accounts.

## Supported use

- Bind HTTP to loopback or an explicitly permitted tailnet address; put HTTPS in front of remote access.
- Use read-only account access and scoped client grants by default. Full grants include future accounts and capabilities.
- Mail draft access does not permit Perch send or organize operations. Some provider credentials carry broader upstream rights; Perch cannot restrict their use outside Perch.
- Keep keys outside the data directory. Back them up separately. Private directories must be `0700`; credential files must be `0600`.
- Treat Microsoft/Slack sessions and the GOWA bridge as experimental or unofficial integrations. Do not bypass organizational controls, MFA, TLS checks or the browser sandbox.
- Public OAuth needs separate configuration, allowed identities, TOTP and explicit server pairing approval. Do not expose private tokens through URLs, logs or chat.
- Revoke unused client grants and devices. Review requested tool operations, especially sends, shares, invitations and public posts. Provider content is untrusted input, not authorization.

## Reporting

Do not post credentials, personal data or exploit details in a public issue. Use GitHub private vulnerability reporting if available for this repository; otherwise contact a repository maintainer privately to arrange a secure report. Include the affected ref/version, entry point, attacker prerequisites, expected boundary and a minimal reproduction with dummy data.

## Validation limits

Local tests exercise authorization, revocation, encrypted storage, input validation, local TLS and mocked provider operations. They do not prove a provider's live permissions, account-policy acceptance, session longevity, deployment configuration or absence of vulnerabilities. `npm audit` and secret scans are time-bound checks, not guarantees. See [release readiness](docs/RELEASE_READINESS.md) for the latest recorded scope and remaining prerequisites.
