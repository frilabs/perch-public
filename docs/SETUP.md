# Onboarding

Perch serves one operator's accounts. Repeat account connection for every account or workspace; repeat client pairing for every AI client. All commands below use `perch` as shorthand for `node /path/to/perch/dist/cli.js`.

## 1. Install

Install Node.js ≥22.12, Git, then:

```bash
git clone https://github.com/frilabs/perch-public.git perch
cd perch
npm ci
npm run build
node dist/cli.js setup
```

Skip apps you do not need. Return with `perch setup`, or connect an app directly below. Credentials are entered through hidden prompts and stored privately. Do not put passwords in command arguments.

Default state:

- Encrypted data: `~/.local/share/perch/`.
- Encryption key: `~/.config/perch/store.key`.
- Read-only HTTP token: `~/.config/perch/http-token`.

Back up the key separately from the encrypted data. Keep private directories `0700` and credential files `0600`. Never commit `.env`, client secrets, browser profiles, token files or backups. See `.env.example` for optional path and server configuration. If using a `.env`, make it `0600` and pass it with Node's `--env-file=/absolute/path/.env`.

## 2. Choose access

Account permission and client permission are separate. An operation must pass both.

| Access | Mail | Other apps |
| --- | --- | --- |
| Read | Search and read | Read operations supported by that connector |
| Read + draft | Read and create mail drafts; cannot send or organize | No general draft mode; use read or explicit write capabilities |
| Read + write | Read, draft, send and organize | Explicit changes supported by that connector |

For Google/Gmail and IMAP, choose `r`, `d` or `w`, or pass `--read-only`, `--drafts-only` or `--write`. With a combined Google login, draft mode enables Gmail drafts and leaves Drive/Calendar read-only; `--drafts-only` requires Gmail among the selected services. `--write` enables writes for selected services. Contacts remain read-only. Legacy `--allow-drafts`, `--allow-send` and `--allow-modify` flags permit narrower mailbox choices.

Microsoft offers read, mail drafts, or write after discovery. Draft mode keeps other detected services read-only. For later changes use `perch microsoft access GROUP_ID --service mail --drafts-only`; other services support `--read-only` or `--write`. Invitations require separate calendar permission.

**Provider limits:** Gmail's `gmail.compose` scope also permits sending at Google. IMAP credentials, Microsoft/Slack browser sessions and some integration tokens can carry broader upstream access than Perch allows. Draft-only is enforced by Perch's account checks and client grants; it does not turn those credentials into provider-enforced draft-only credentials. Protect them accordingly.

## 3. Connect apps

### Google: Drive, Gmail, Calendar and Contacts

```bash
perch google add --label Work
```

Choose services (`drive,gmail,calendar,contacts`, Enter selects all) and access. The guided client setup runs if needed:

1. Open Google Cloud Console and create or select a project.
2. Enable the APIs for the selected services: Drive, Gmail, Calendar and People.
3. Configure OAuth consent. In testing mode, add yourself as a test user.
4. Create an OAuth client of type **Desktop app**. Paste its JSON when Perch asks; it is saved privately.
5. Open the sign-in link and consent to the requested services. If the final local page cannot load, copy its full address and paste it into Perch's hidden prompt.

Google may grant only some services; Perch reports what connected. Testing-mode grants can expire after seven days. Reconnect the same account with `perch google add`; existing group and member IDs are reused after confirmation.

Use `perch google access GROUP_ID` for current per-service rights. Examples: `--service drive --read-only`, `--service gmail --write`, or `--add contacts`. Granting new provider rights signs in again. Revoking a Google login affects every service sharing that login; `--revoke` is explicit and checked for shared grants.

Standalone commands remain available: `perch gmail add` and `perch google-productivity add`.

### Microsoft 365 / Outlook

On the Linux server, install a supported Chrome/Chromium browser and ensure SSH access from your computer. Then:

```bash
perch microsoft add --label Work --ssh-host USER@SERVER
```

Use your own SSH alias or `USER@SERVER`; omit `--ssh-host` to enter it when prompted.

1. Keep the server terminal open.
2. Run the single helper command Perch prints on your computer. It obtains the checksum-verified helper from your server over SSH and starts a fresh local Chrome login.
3. Sign in, including local MFA/passkeys when supported.
4. Perch transfers session state over SSH, checks identity, and discovers Teams, own mail, calendar and accessible OneDrive for Business/SharePoint libraries.
5. Review verified services and discovery limits. Choose read, mail drafts, write, or cancel. Only then is the connection saved.

The computer can be closed afterwards. Organization policy, device binding or renewed MFA may prevent transfer or service access. Perch does not bypass those controls. Outlook web-session access is experimental and uses retired Outlook REST endpoints internally; it is not an officially supported Microsoft integration.

- `perch microsoft doctor GROUP_ID`: fresh checks without widening access.
- `perch microsoft reconnect GROUP_ID`: renew the session, preserving identity and explicit scopes.
- Add `--reuse-session` to reconnect using a checked copy of the saved login. Choose keep access, `--read-only`, `--drafts-only` or `--write`; an expired login requires reconnect without this flag.
- `--site https://TENANT.sharepoint.com/sites/SITE`: optionally include a missing accessible site.
- `--server-login`: alternative remote-browser viewer; follow its printed tunnel instructions.
- `perch microsoft remove GROUP_ID`: remove the local connection.

Do not run a browser as root or disable its sandbox. Browser sessions contain credentials and belong only in the private data directory.

### GMX / other IMAP and SMTP

```bash
perch imap add --label Private --email you@example.org
```

For GMX, enable IMAP in webmail settings and use an app password when required. Perch has GMX presets. For other providers, supply their IMAP/SMTP host settings when prompted or use the documented flags in `perch --help`.

Choose read, draft or write. Enter the password only in the hidden prompt. IMAP/SMTP requires verified TLS; STARTTLS must complete before authentication. Drafts require a suitable Drafts folder. Sending can file a Sent copy; Gmail/Outlook SMTP manage that themselves.

### Notion

```bash
perch notion add --label Work
```

Choose an internal integration token, or public integration OAuth when workspace permissions require it. For a token: create an integration at `https://www.notion.so/profile/integrations`, select only needed capabilities, and grant it access to the relevant pages. Paste the token when prompted. For OAuth, follow `perch notion client setup` and its redirect instructions, then sign in and choose pages.

Labels are user-assigned; Perch does not verify workspace identity. Notion search is title search, not full-text search. The upstream integration controls page scope and available writes; client grants separately choose `notion_read` or `notion_write`. There is no draft-only mode.

### Slack

```bash
perch slack add --label Work
```

Sign in to the intended workspace in your browser. Follow Perch's instructions to obtain the session token and cookie, then paste each into its hidden prompt. Treat both as credentials; never send them in chat or commit them. This session method is unofficial and may expire or be blocked by workspace policy. Existing API-token accounts remain supported.

Client grants choose `slack_read` and optionally `slack_send`. The latter includes messages, reactions, edits and supported file operations; there is no draft-only mode. Reconnect with `perch slack add` when the session expires.

### WhatsApp

```bash
perch whatsapp install
perch whatsapp add --label Private --phone +COUNTRYNUMBER
```

The optional installer requires Linux and a working systemd user service. It downloads the pinned GOWA release, verifies SHA-256, and binds the bridge to loopback. Read the warning and confirm installation. The setup wizard offers the same installation when needed.

On the phone, open **WhatsApp → Settings → Linked devices → Link a device → Link with phone number instead**, then enter the pairing code. Use separate account slots for multiple numbers. Client grants choose `whatsapp_read` and optionally `whatsapp_send`; sending also covers media. GOWA is unofficial; account restrictions are possible. Do not expose its bridge port publicly.

### Luma

```bash
perch luma add --label Work
```

Open the browser link, sign in and approve the official Luma MCP permissions. If the callback cannot load locally, paste its full address into Perch. No personal developer app is normally needed. Perch pins approved tool schemas; inspect changes with `perch luma tools ID` and accept them explicitly with `--accept` only after review.

Client grants separate `luma_read`, `luma_events`, `luma_guests` and `luma_blast`. Event/guest changes and message blasts are distinct permissions. There is no generic draft-only mode.

### X

```bash
perch x add --label Work
```

Create an X developer app at `https://developer.x.com/`, enable OAuth 2.0, register `http://127.0.0.1:8771/x/callback`, and add any API credits required by X. Follow Perch's client setup prompts; paste client credentials only into hidden prompts. Sign in as the intended account.

Perch uses PKCE and rotating refresh tokens. It supports own login status and text posting, not feeds, media, DMs, likes or deletion. Grant `x_read` for local login status and `x_post` only when publishing is intended. No draft mode. Check current X pricing; Perch does not set it.

### Removed: LinkedIn

No LinkedIn command, tool, login or network route remains. Old encrypted account records and historical ledger entries are retained solely for safe upgrades; LinkedIn capabilities are stripped from legacy client grants, and grants left without usable scope are revoked. To end old provider access, revoke the app in LinkedIn's permitted-services settings and remove the old `~/.config/perch/linkedin-client.json` file after confirming you no longer need it. Do not delete the shared Perch store or key.

## 4. Run privately

```bash
perch serve --http
```

The default listener is `127.0.0.1:8765`. For a server in your tailnet:

```bash
sudo tailscale serve --bg http://127.0.0.1:8765
```

Set `PERCH_ALLOWED_HOSTS` to your server's exact tailnet hostname and restart Perch with that configuration. Use `PERCH_PRIVATE_BASE_URL` only for an explicit private HTTPS issuer. The MCP path is `/mcp`; the authenticated overview is `/status`. Do not bind the listener or bridge publicly as a shortcut.

For persistent operation, create a systemd **user** service with your absolute Node and checkout paths:

```ini
[Unit]
Description=Perch MCP server
After=network-online.target

[Service]
Type=simple
ExecStart=/absolute/path/to/node /absolute/path/to/perch/dist/cli.js serve --http
Environment=PERCH_ALLOWED_HOSTS=SERVER.TAILNET.ts.net
Restart=on-failure
UMask=0077

[Install]
WantedBy=default.target
```

Save as `~/.config/systemd/user/perch.service`. If using `.env`, add Node's `--env-file=/absolute/path/.env` before the CLI path. Then run `systemctl --user daemon-reload` and `systemctl --user enable --now perch`. Use `loginctl enable-linger "$USER"` if the service should survive logout. Inspect startup with `journalctl --user -u perch`; never enable credential/body debug logging.

## 5. Connect AI clients

Run `perch --help` for the three starting points: server setup, AI clients, and apps/accounts. `perch connect --help` lists AI targets without starting pairing; `perch help --all` shows the complete command reference.

```bash
perch connect
```

| Client | Target | Connection |
| --- | --- | --- |
| Claude Code | `claude-code` | Private HTTPS MCP URL; `claude mcp add`, then authenticate |
| Codex | `codex` | Private HTTPS MCP URL; `codex mcp add`, then `codex mcp login perch` |
| Claude web, desktop and phone | `claude-ai` | Public HTTPS connector URL; pair each device |
| ChatGPT | `chatgpt` | Public HTTPS connector URL; pair each device |
| Other desktop client | `desktop` | Private HTTPS when the computer is in the tailnet |
| Agent on the server | `server-agent` | Private `0600` token file, HTTP or `PERCH_CLIENT_TOKEN_FILE` for stdio |
| Other MCP client | `other` | OAuth where supported; otherwise a scoped local client token |

Run `perch connect --target TARGET` for direct instructions. OAuth pairing requires your confirmation on the server. Read-only is the safe default. Full access includes every current and future account and capability.

Claude and the official Codex client metadata URL are recognized automatically; no `oauth client add` step is needed. OAuth clients renew their one-hour access tokens with rotating refresh tokens, including after a Perch restart. Keep using the same HTTPS issuer URL. Pairing is not required for each renewal.

If an older Codex login reports that refresh credentials are missing an authorization server issuer, authenticate once again with `codex mcp login perch` (or **Reconnect** in the app), with a pairing window open on the server. This replaces the incomplete client-side credentials. Static client tokens, including existing Claude Code configurations using them, do not have the OAuth one-hour expiry. Revoked or expired refresh sessions still require a new login.

For a mail assistant that can draft but never send:

```bash
perch client add --label 'Mail drafts' --allow read,draft --account MAIL_ACCOUNT_ID
```

For sending, explicitly add `send`; for organizing, add `modify`. A grant cannot exceed the account's enabled permissions. Other families use `drive_read,drive_write`, `notion_read,notion_write`, `calendar_read,calendar_write,calendar_invite,contacts_read`, `slack_read,slack_send`, `whatsapp_read,whatsapp_send`, Luma's four capabilities, `x_read,x_post`, or the documented `microsoft_teams_*`, `microsoft_calendar_*`, `microsoft_files_*` capabilities. Select only relevant account IDs.

Revoke tokens with `perch client remove ID`; revoke OAuth devices with `perch oauth revoke ID`. Revocation is checked again on tool calls.

### Optional public access

Claude web and ChatGPT connect from their cloud and need public HTTPS; a private tailnet URL alone is insufficient. Do not enable it until private reads and explicitly selected writes have been validated.

```bash
perch public setup      # or: perch connect --target claude-ai, which offers it
perch public status     # one ☑/☐ line per requirement, with the fixing command
```

`perch public setup` guides through everything in the terminal:

1. **Public address** (`PERCH_PUBLIC_BASE_URL`). If it is missing, Perch suggests `https://<tailnet name>:10000` (from `PERCH_ALLOWED_HOSTS`; port 443 usually serves the private address through Tailscale Serve, and Funnel offers only 443, 8443 and 10000). It writes the line to your `.env` only after `[y/N]` and only if Perch was started with `node --env-file=…` (or `PERCH_ENV_FILE` names the file); otherwise it prints the line to add.
2. **Google sign-in client** of type **Web application**, separate from the Desktop client of your accounts. The guide links to `https://console.cloud.google.com/auth/clients` and prints the exact redirect URI `<PERCH_PUBLIC_BASE_URL>/oauth/google/callback`; scopes are only `openid email`, and your Google account must be a test user. Paste the downloaded JSON (hidden input). Perch checks the `web` key, the client id, the secret and the redirect URI, refuses a Desktop client, and stores it `0600` at `PERCH_GOOGLE_LOGIN_CLIENT_FILE`, by default `~/.config/perch/google-web-client.json` (found there without any `.env` entry).
3. **Allowed Google account** (`perch oauth login-allow add`).
4. **Perch code**: TOTP with QR code and one-time recovery codes (`perch oauth totp setup`).

It ends with a checklist of exact commands; Perch changes neither systemd nor Tailscale itself. For the documented systemd unit (ExecStart ending in `serve --http`):

```bash
sed -i 's#serve --http$#serve --http --public#' ~/.config/systemd/user/perch.service && systemctl --user daemon-reload && systemctl --user restart perch
sudo tailscale funnel --bg --https=10000 http://127.0.0.1:8767   # your public port → PERCH_PUBLIC_PORT
curl -s https://SERVER.TAILNET.ts.net:10000/.well-known/oauth-authorization-server
perch connect --target claude-ai
```

Without a systemd unit, run `perch serve --http --public`. If Tailscale says Funnel is not enabled for the tailnet, open the link it prints. The curl answer is JSON with your public `issuer`.

Public login requires the allowed Google identity, Perch code, pairing code and server confirmation. Public/private OAuth issuers are separate. Kill switch: `perch public off`; privately paired devices remain separate.

## 6. Validate and maintain

Tool arguments are limited to 10,000 array elements and object keys in total, including nested values, before schema validation. Split larger batches; string and file byte limits apply separately. Microsoft status colors reflect the stored result, with the last probe time shown alongside ready services.

1. Run `perch status`; investigate every failed or partial check. `--no-check` shows stored state only.
2. In the client, list accounts and read one known item from each connected service. Confirm account identity and scope.
3. If enabled, test draft creation and confirm that draft-only clients cannot send. Test writes only to an explicitly chosen self/test destination. Never send test messages to other people implicitly.
4. Repeat one supported create/send with the same `requestId`: it must report the stored outcome without duplicating the action. An indeterminate result needs inspection, not a blind new request.
5. Inspect `perch audit list`. Keep live provider results separate from local mock-test results.

Update from your chosen reviewed Git ref, run `npm ci`, `npm run check`, rebuild and restart your service. Back up encrypted state and the separate key first. OAuth credentials and live processes may need renewal; a successful build is not a live account check.

To restrict an existing Gmail connection to drafts, run `perch google access GROUP_ID --service gmail --drafts-only`. Sending and organizing are disabled locally; missing draft permission requires another login.
