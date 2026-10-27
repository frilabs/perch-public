# Maintainer handoff

Perch is an experimental, single-operator, self-hosted MCP gateway.

- Start with [SETUP.md](SETUP.md), [SECURITY.md](../SECURITY.md) and [RELEASE_READINESS.md](RELEASE_READINESS.md).
- Account permissions and client grants are independent boundaries. Keep read-only defaults, explicit writes, OAuth rotation/revocation, provider identity checks and encrypted state protections.
- Microsoft and Slack browser sessions and the WhatsApp bridge are unofficial. Provider policies and session lifetimes still apply.
- Tests use synthetic accounts or local mocks unless explicitly stated. A green test suite does not establish live provider acceptance.
- Run `npm run check` before pushing. Use branches and reviewed pull requests; require explicit maintainer authorization for merge, deployment or publication.
- Keep private incident reports, account identities, operator conversations and deployment details outside the repository.

