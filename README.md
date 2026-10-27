<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/logo/perch-logo-white.svg">
  <img alt="Perch" src="brand/logo/perch-logo-black.svg" width="220">
</picture>

# Perch

**Experimental / Early Access.** For individual self-hosters evaluating the project; connector coverage and provider session lifetimes vary.

Self-hosted MCP server for multiple Google, Microsoft, IMAP/SMTP, Notion, Slack, WhatsApp, Luma and X accounts. Connect your accounts once, then use them from Claude Code, Codex, Claude, ChatGPT or another MCP client.

**Read-only by default.** Changes require both account permission and an explicit client grant. Mail supports read, read + draft, or read + write. Full client access includes future accounts and capabilities; use scoped grants when possible.

## Start

Requires Node.js ≥22.12 (22 and 24 are CI targets). For Microsoft browser sessions and the managed WhatsApp bridge, use a Linux server; their additional requirements are in the [onboarding guide](docs/SETUP.md).

```bash
git clone https://github.com/frilabs/perch-public.git perch
cd perch
npm ci
npm run build
node dist/cli.js setup
```

The wizard lets you skip any app and connect multiple accounts. No `.env` is required for the basic setup. Run `node dist/cli.js --help` for commands; below, `perch` means `node /path/to/perch/dist/cli.js`.

1. Connect the apps you need and choose their permissions.
2. Back up the generated store key separately from the encrypted data.
3. Start the server and configure private HTTPS access.
4. Run `perch connect` for each AI client and choose its access. claude.ai and ChatGPT need the public address: `perch connect --target claude-ai` (or `chatgpt`) offers `perch public setup` right away, which walks through the Google sign-in client, your allowed Google account and the Perch code, and ends with the exact systemd, Tailscale Funnel and test commands. `perch public status` shows what is still missing.
5. Run `perch status`, then validate reads. Test writes only to accounts and destinations you explicitly choose.

See the [complete onboarding journey](docs/SETUP.md), [security policy](SECURITY.md), and [release assessment](docs/RELEASE_READINESS.md).

## Apps

| App | Connection | Available operations |
| --- | --- | --- |
| Google Drive | One Google OAuth login with Gmail, Calendar and Contacts | Search, read, export; optional create, edit, share and trash |
| Gmail | Same Google login; standalone login also supported | Search, read; optional drafts, send and organize |
| Google Calendar | Same Google login | Read; optional event changes and separately permitted invitations |
| Google Contacts | Same Google login | Read only |
| Microsoft 365 / Outlook | Local Chrome login transferred over SSH; server discovers services | Teams, own mail, calendar, OneDrive for Business and SharePoint; optional writes |
| GMX / other IMAP + SMTP | Mailbox password or app password, entered hidden | Search, read; optional drafts, send and organize |
| Notion | Internal integration token, or public integration OAuth | Read permitted pages; optional page, block and comment changes |
| Slack | Browser session; existing API-token accounts remain supported | Channels, messages and search; optional messages, reactions and files |
| WhatsApp | Self-hosted GOWA bridge and phone pairing | Chats and media; optional messages and media sending |
| Luma | Official Luma MCP OAuth | Read; separately granted event, guest and blast operations |
| X | Your developer app, OAuth and API credits | Own login status; optional text posting |

Microsoft sessions and Slack session access are unofficial; WhatsApp's GOWA integration is unofficial and can lead to account restrictions. Microsoft service availability depends on the account, consent, session and organization policies. Mock tests do not establish live provider acceptance or session longevity. LinkedIn has been removed.

## Development

```bash
npm ci
npm run check
```

`check` runs type checking, unit/local-provider tests, build, built stdio/HTTP smoke tests and license validation. In a cloud shell with `umask 077`, run tests in a subshell with `umask 022`: a permission-rejection test deliberately creates a `0644` file. For slower local TLS teardown:

```bash
(umask 022; npm run typecheck && npm test -- --maxWorkers=2 --testTimeout=60000 && npm run smoke && npm run licenses:check)
```

Provider tests use mocks or local servers. Real accounts, public exposure and provider writes require separate, explicit operator setup.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Third-party providers, browser software and GOWA have their own terms. The source license does not grant provider access or permission to bypass their policies.
