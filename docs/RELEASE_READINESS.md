# Experimental / Early Access

Perch is a self-hosted MCP gateway for individual operators evaluating account integrations. This repository starts from a reviewed source snapshot with a fresh history.

## Validation

The source candidate passed 1,632 local tests, 13 built smoke tests, type checking, build and license validation. Dependency audit reported zero known advisories on 2026-10-27. These are time-bound checks, not an assurance that the project is vulnerability-free.

A separate security assessment was partial: Gitleaks completed without candidates; static OAuth/grant and HTML-output reviews found no supported bypass in their assigned scope. Semgrep had incomplete coverage, OSV/Trivy did not complete, and isolated application reproduction was unavailable. CI action pinning and checkout credential persistence remain hardening opportunities. Not all scanner candidates or provider operations received exhaustive review.

## Limits

Microsoft and Slack browser sessions and the WhatsApp bridge are unofficial. Provider policies, account restrictions and session lifetimes apply. Mock tests do not prove long-term unattended operation or every provider write. Use scoped read-only client grants by default.

Source installation is supported; npm publication is intentionally disabled with `private: true`. See [SETUP.md](SETUP.md), [SECURITY.md](../SECURITY.md), LICENSE and THIRD_PARTY_NOTICES.md.
