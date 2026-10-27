// Terminal rendering of `perch status` (docs/STATUS_UI_GOWA_HARDENING_SPEC.md §1) on hand-built, secret-bearing
// DUMMY store data: TTY vs. pipe vs. NO_COLOR, capability hints with the exact enabling commands, unconnected
// services, width handling, and that no secret or terminal escape from a label ever reaches the output.
import { describe, expect, it } from 'vitest';
import { GMAIL_READONLY_SCOPE } from '../src/mail/gmailAccounts.js';
import { SLACK_USER_SCOPES } from '../src/slack/slack.js';
import { formatStatusText, type StatusReport } from '../src/status/status.js';
import { accountCapabilities, fit, formatStatusTerminal, shellQuote } from '../src/status/terminal.js';
import type { StoreData } from '../src/store/credentialStore.js';

const AT = '2026-10-20T20:45:00.000Z';
const SECRETS = ['DUMMY-imap-password-1234', 'DUMMY-gowa-password-5678', 'DUMMY-gmail-refresh-9999', 'xoxp-DUMMY-slack-token'];
const ANSI = /\u001b\[/;

/** One GMX account (read, drafts, send), one WhatsApp account, one full client. */
function baseStore(): StoreData {
  return {
    version: 1,
    google: [],
    notion: [],
    gmail: [],
    microsoft: [],
    imap: [
      {
        id: 'imap-11112222',
        label: 'GMX',
        email: 'alice@example.org',
        username: 'alice@example.org',
        password: SECRETS[0]!,
        preset: 'gmx',
        imap: { host: 'imap.gmx.net', port: 993 },
        smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
        allowDrafts: true,
        allowSend: true,
        allowModify: false,
        createdAt: AT,
        updatedAt: AT,
      },
    ],
    clients: [{ id: 'client-33334444', label: 'Claude Code Mac', tokenSha256: 'a'.repeat(64), capabilities: ['read'], accountIds: [], full: true, createdAt: AT }],
    googleProductivity: [],
    users: [],
    slack: [],
    whatsappInstance: { origin: 'http://127.0.0.1:3000', username: 'perch', password: SECRETS[1]!, createdAt: AT, updatedAt: AT },
    whatsapp: [{ id: 'whatsapp-55556666', label: 'Whatsapp', deviceId: 'perch-0123456789abcdef', jid: '4366012345678@s.whatsapp.net', createdAt: AT, updatedAt: AT }],
    luma: [],
    googleGroups: [],
    x: [],
  };
}

function baseReport(): StatusReport {
  return {
    generatedAt: AT,
    version: '0.1.0',
    namespace: 'root',
    checked: true,
    accounts: [
      { family: 'mail', id: 'imap-11112222', label: 'GMX', provider: 'imap (gmx)', identity: 'alice@example.org', permissions: 'read, draft, send', connectedAt: AT, check: { state: 'ok', ms: 732 } },
      { family: 'whatsapp', id: 'whatsapp-55556666', label: 'Whatsapp', provider: 'gowa', identity: '+4366012345678', permissions: 'read, send', connectedAt: AT, check: { state: 'ok', ms: 16 } },
    ],
    googleGroups: [],
    clients: [{ id: 'client-33334444', label: 'Claude Code Mac', capabilities: ['read'], accountIds: [], full: true, createdAt: AT }],
    whatsappBridge: { origin: 'http://127.0.0.1:3000', configuredAt: AT },
    ledger: { sends: 0, maxSends: 1000, pending: 0, auditEvents: 0, auditDropped: 0 },
    publicAccess: { state: 'not_set_up', totp: false, allowedAccounts: 0, activeDevices: 0 },
  };
}

const render = (r: StatusReport, d: StoreData, opts: Partial<Parameters<typeof formatStatusTerminal>[2]> = {}) =>
  formatStatusTerminal(r, accountCapabilities(d), { tty: false, env: {}, ...opts });

describe('perch status terminal rendering', () => {
  it('renders sections, checkboxes and the result without ANSI when not a TTY', () => {
    const out = render(baseReport(), baseStore());
    expect(out).not.toMatch(ANSI);
    expect(out).toMatch(/^Perch 0\.1\.0 · namespace root +2026-10-20 20:45 UTC\n═{80}\n/);
    expect(out).toMatch(/── Mail · IMAP \(GMX …\) ─+\n☑ GMX  alice@example\.org +ok · 732 ms\n {2}imap-11112222 · imap \(gmx\) · since 2026-10-20\n {2}☑ read {3}☑ drafts {3}☑ send\n/);
    expect(out).toMatch(/── WhatsApp ─+\n☑ Whatsapp  \+4366012345678 +ok · 16 ms\n/);
    expect(out).toMatch(/☑ client Claude Code Mac  client-33334444 +full access\n {4}read \+ write on every account, also later ones/);
    expect(out).toMatch(/☐ public access \(OAuth for claude\.ai, ChatGPT …\) +not set up\n {4}perch public setup\n/);
    expect(out).toMatch(/☑ WhatsApp bridge  http:\/\/127\.0\.0\.1:3000/);
    expect(out).toMatch(/Send ledger {3}░{10,30}  0 \/ 1000 records\nAudit {9}0 events/);
    expect(out).toMatch(/── Onboarding 3\/4 ─+\n☑ at least one account connected\n☑ a client is set up\n☑ a client may write/);
    expect(out).toMatch(/☐ reminder: keep a backup of the key file/);
    expect(out.trimEnd().split('\n').pop()).toBe('✓ All checks passed');
    for (const line of out.split('\n')) if (!line.startsWith('    perch ')) expect([...line].length, line).toBeLessThanOrEqual(80);
  });

  it('colours only status on a TTY, and NO_COLOR turns colour off', () => {
    const r = baseReport();
    r.accounts[1]!.check = { state: 'error', message: 'Not logged in to WhatsApp: pair again with perch whatsapp add', ms: 5 };
    const tty = render(r, baseStore(), { tty: true, columns: 100 });
    expect(tty).toContain('\u001b[32m☑\u001b[0m GMX');
    expect(tty).toContain('\u001b[31m✗\u001b[0m Whatsapp');
    expect(tty).toContain('\u001b[31mNot logged in to WhatsApp');
    expect(tty).toContain('\u001b[31m✗ 1 check(s) failed\u001b[0m');
    // The ☐ hint stays monochrome; colour is for status only.
    expect(tty).toMatch(/\n {2}☐ organize/);
    for (const env of [{ NO_COLOR: '1' }, { NO_COLOR: 'true' }]) {
      const out = render(r, baseStore(), { tty: true, columns: 100, env });
      expect(out).not.toMatch(ANSI);
      expect(out).toContain('✗ Whatsapp');
      expect(out).toContain('☑ GMX');
    }
    // NO_COLOR="" does not count (no-color.org).
    expect(render(r, baseStore(), { tty: true, env: { NO_COLOR: '' } })).toMatch(ANSI);
  });

  it('shows a missing IMAP capability with the exact command that keeps the other opt-ins', () => {
    const out = render(baseReport(), baseStore());
    expect(out).toContain(
      '  ☐ organize (flags, move, archive, trash)\n' +
        '    perch imap remove imap-11112222 && perch imap add --label GMX --email alice@example.org --preset gmx --allow-drafts --allow-send --allow-modify\n',
    );
    expect(out).not.toMatch(/☐ (read|drafts|send)\b/);
  });

  it('keeps non-default IMAP settings in the command and quotes labels for the shell', () => {
    const d = baseStore();
    Object.assign(d.imap[0]!, {
      label: "Alice's mail",
      preset: undefined,
      username: 'alice',
      imap: { host: 'imap.example.org', port: 993 },
      smtp: { host: 'smtp.example.org', port: 587, security: 'starttls' },
      allowDrafts: false,
      allowSend: false,
      allowModify: true,
      draftsMailbox: 'Entwürfe',
      sentCopy: false,
    });
    const caps = accountCapabilities(d)['imap-11112222']!;
    expect(caps.map((c) => [c.name, c.enabled])).toEqual([['read', true], ['drafts', false], ['send', false], ['organize', true]]);
    expect(caps.find((c) => c.name === 'send')!.enable).toBe(
      "perch imap remove imap-11112222 && perch imap add --label 'Alice'\\''s mail' --email alice@example.org --username alice " +
        '--imap-host imap.example.org --imap-port 993 --smtp-host smtp.example.org --smtp-port 587 --smtp-security starttls ' +
        "--allow-send --allow-modify --drafts-mailbox 'Entwürfe' --no-sent-copy",
    );
    expect(shellQuote('a b')).toBe("'a b'");
  });

  it('derives Gmail, Microsoft, Drive, Calendar and Slack capabilities from the stored scopes', () => {
    const d = baseStore();
    d.gmail.push({ id: 'gmail-0000000a', label: 'Work Gmail', email: 'w@example.test', clientId: 'c', clientSecret: 'DUMMY-secret', refreshToken: SECRETS[2]!, scopes: [GMAIL_READONLY_SCOPE], createdAt: AT, updatedAt: AT });
    d.microsoft.push({ id: 'microsoft-0000000a', label: 'Outlook', email: 'o@example.test', tenant: 'common', clientId: 'c', refreshToken: 'DUMMY-ms', scopes: ['Mail.Read', 'Mail.Send'], createdAt: AT, updatedAt: AT });
    d.google.push({ id: 'google-0000000a', label: 'Drive', email: 'd@example.test', clientId: 'c', clientSecret: 'DUMMY-secret', refreshToken: 'DUMMY-drive', scopes: ['https://www.googleapis.com/auth/drive.readonly'], createdAt: AT, updatedAt: AT });
    d.googleProductivity.push({
      id: 'gprod-0000000a',
      label: 'Calendar',
      email: 'c@example.test',
      sub: '1',
      clientId: 'c',
      clientSecret: 'DUMMY-secret',
      refreshToken: 'DUMMY-gprod',
      scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
      services: ['calendar'],
      allowCalendarWrite: false,
      createdAt: AT,
      updatedAt: AT,
    });
    d.slack.push({ id: 'slack-0000000a', label: 'Company', token: SECRETS[3]!, teamId: 'T123', userId: 'U123', scopes: SLACK_USER_SCOPES.filter((s) => s !== 'im:write' && s !== 'mpim:write'), createdAt: AT, updatedAt: AT });
    const caps = accountCapabilities(d);
    const off = (id: string) => caps[id]!.filter((c) => !c.enabled).map((c) => [c.name, c.enable]);
    expect(off('gmail-0000000a')).toEqual([
      ['drafts', 'perch gmail remove gmail-0000000a && perch google add --label \'Work Gmail\' --services gmail --allow-drafts --login-hint w@example.test'],
      ['send', 'perch gmail remove gmail-0000000a && perch google add --label \'Work Gmail\' --services gmail --allow-send --login-hint w@example.test'],
      ['organize', 'perch gmail remove gmail-0000000a && perch google add --label \'Work Gmail\' --services gmail --allow-modify --login-hint w@example.test'],
    ]);
    // Retired OAuth credentials never offer active capabilities or reconnect flags.
    expect(caps['microsoft-0000000a']).toBeUndefined();
    expect(off('google-0000000a')).toEqual([['write', 'perch google remove google-0000000a && perch google add --label Drive --services drive --allow-write --login-hint d@example.test']]);
    const cal = 'perch google-productivity remove gprod-0000000a && perch google add --label Calendar --services calendar';
    expect(off('gprod-0000000a')).toEqual([
      ['contacts', `${cal},contacts --login-hint c@example.test`],
      ['calendar write', `${cal} --allow-calendar-write --login-hint c@example.test`],
      ['invitations', `${cal} --allow-calendar-write --login-hint c@example.test`],
    ]);
    expect(off('slack-0000000a')).toEqual([
      ['open DMs', 'perch slack add --label Company --session'],
    ]);
  });

  it('lists unconnected services with their add command and a one-line description', () => {
    const out = render(baseReport(), baseStore());
    const block = out.slice(out.indexOf('── Not connected'), out.indexOf('── Access'));
    // Google is ONE unconnected service: a single line and one command (rights per service: perch google access).
    expect(block).toContain('☐ Google (Drive, Gmail, Calendar, Contacts)  one login; read, opt-in: write\n    perch google add --label NAME\n');
    expect(block).not.toMatch(/☐ (Google Drive|Gmail|Google Calendar)/);
    expect(block).not.toContain('--services');
    for (const [title, cmd] of [
      ['Notion', 'perch notion add --label NAME'],
      ['Microsoft 365', 'perch microsoft add --label NAME'],
      ['Slack', 'perch slack add --label NAME'],
      ['Luma', 'perch luma add --label NAME'],
    ]) {
      expect(block).toMatch(new RegExp(`☐ ${title!.replace(/[/()]/g, '\\$&')} +\\S`));
      expect(block).toContain(`    ${cmd}`);
    }
    expect(block).not.toMatch(/IMAP|WhatsApp/);
    // Without a bridge the WhatsApp hint starts with the installer.
    const r = baseReport();
    r.accounts = [];
    delete r.whatsappBridge;
    r.clients = [];
    const empty = render(r, { ...baseStore(), imap: [], whatsapp: [], clients: [] });
    expect(empty).toContain('    perch whatsapp install, then perch whatsapp add --label NAME --phone +43…');
    expect(empty).toContain('☐ no client yet');
    expect(empty).toMatch(/── Onboarding 0\/4/);
  });

  it('adapts to the terminal width (min 60) and cuts long values', () => {
    const r = baseReport();
    r.accounts[0]!.label = `Very long label ${'x'.repeat(200)}`;
    for (const [columns, w] of [[40, 60], [72, 72], [300, 120]] as const) {
      const out = render(r, baseStore(), { columns });
      expect(out.split('\n')[1]).toBe('═'.repeat(w));
      const line = out.split('\n').find((l) => l.startsWith('☑ Very long'))!;
      expect([...line].length).toBe(w);
      expect(line).toMatch(/…  ok · 732 ms$/);
    }
    expect(fit('abcdef', 4)).toBe('abc…');
    expect(fit('abc', 4)).toBe('abc');
  });

  it('never prints a secret or a terminal escape from a label', () => {
    const d = baseStore();
    const r = baseReport();
    d.imap[0]!.label = 'evil\u001b[2J\u0007label';
    r.accounts[0]!.label = d.imap[0]!.label;
    for (const opts of [{ tty: false }, { tty: true }]) {
      const out = render(r, d, opts);
      for (const s of SECRETS) expect(out).not.toContain(s);
      expect(out).not.toContain('\u001b[2J');
      expect(out).not.toContain('\u0007');
    }
  });

  it('shows a failed check, skipped checks and a full ledger', () => {
    const r = baseReport();
    r.accounts[0]!.check = { state: 'error', message: 'Internal error (details withheld)', ms: 3 };
    r.ledger = { sends: 1000, maxSends: 1000, pending: 2, auditEvents: 12, auditDropped: 3, lastActivityAt: AT };
    const out = render(r, baseStore());
    expect(out).toMatch(/✗ GMX  alice@example\.org +FAILED\n {2}imap-11112222 · imap \(gmx\) · since 2026-10-20\n {2}Internal error \(details withheld\)\n/);
    expect(out).toMatch(/Send ledger {3}█+  1000 \/ 1000 records\n {14}2 pending/);
    expect(out).toMatch(/Audit {9}12 events \(\+3 rotated out\) · last activity 2026-10-20 20:45 UTC/);
    expect(out.trimEnd().split('\n').pop()).toBe('✗ 1 check(s) failed');
    const skipped = render({ ...baseReport(), checked: false, accounts: baseReport().accounts.map(({ check: _c, ...a }) => a) }, baseStore());
    expect(skipped).toMatch(/☑ GMX  alice@example\.org +not checked/);
    expect(skipped.trimEnd().split('\n').pop()).toBe('· live checks skipped');
  });

  it('plain renderer: Google is one line when nothing is connected', () => {
    expect(formatStatusText(baseReport())).toBe(
      [
        'Perch 0.1.0 · namespace root · 2026-10-20 20:45 UTC',
        '',
        'Google (Drive, Gmail, Calendar, Contacts): none',
        'Notion: none',
        'Mail',
        '  ✓ imap-11112222  "GMX"  alice@example.org  [imap (gmx): read, draft, send]  since 2026-10-20  ok (732 ms)',
        'Slack: none',
        'WhatsApp',
        '  ✓ whatsapp-55556666  "Whatsapp"  +4366012345678  [gowa: read, send]  since 2026-10-20  ok (16 ms)',
        'Luma: none',
        'X: none',
        '',
        'Client grants',
        '  client-33334444  "Claude Code Mac"  FULL access → every account (also later ones)',
        '',
        'WhatsApp bridge: http://127.0.0.1:3000',
        '',
        'Send ledger: 0 / 1000 records used',
        'Audit: 0 events',
        'Public access: not set up · Perch code missing · 0 allowed Google account(s) · 0 active device(s)',
        '',
        'All checks passed.',
        '',
      ].join('\n'),
    );
  });

  it('one block per Google account group: services with ☑/☐ rights and perch google access hints', () => {
    const { d, r } = withGroup();
    const out = render(r, d);
    expect(out).toContain(
      [
        '── Google · Private ' + '─'.repeat(60),
        '☑ Private  alice@example.test                             one login · 3 services',
        '  ggroup-1a2b3c4d · since 2026-10-20',
        '  ☑ Drive      google-11111111                                         ok · 5 ms',
        '    ☑ read   ☐ write',
        '      perch google access ggroup-1a2b3c4d --service drive --write',
        '  ☑ Gmail      gmail-22222222                                          ok · 6 ms',
        '    ☑ read   ☑ drafts   ☑ send   ☑ organize',
        '  ☑ Calendar   gprod-33333333                                          ok · 7 ms',
        '    ☑ read   ☐ write',
        '      perch google access ggroup-1a2b3c4d --service calendar --write',
        '  ☐ Contacts   not connected (read contacts)',
        '      perch google access ggroup-1a2b3c4d --add contacts',
        '',
      ].join('\n'),
    );
    // No per-family sections, no unconnected Google line, no re-add or remove hints for group members.
    expect(out).not.toMatch(/── (Google Drive|Mail · Gmail|Google Calendar\/Contacts) ─/);
    expect(out).not.toContain('☐ Google (Drive');
    expect(out).not.toMatch(/perch google add|perch google remove|--services/);
    for (const secret of [...SECRETS, 'DUMMY-group-refresh', 'DUMMY-group-secret']) expect(out).not.toContain(secret);
    for (const line of out.split('\n')) if (!line.trimStart().startsWith('perch ')) expect([...line].length, line).toBeLessThanOrEqual(80);
    // Partial Gmail write (send only): the missing rights point to the one write command.
    d.gmail[0]!.scopes = [GMAIL_READONLY_SCOPE, 'https://www.googleapis.com/auth/gmail.send'];
    expect(render(r, d)).toContain('    ☑ read   ☐ drafts   ☑ send   ☐ organize\n      perch google access ggroup-1a2b3c4d --service gmail --write\n');
  });

  it('a failed member check marks only that service of the group', () => {
    const { d, r } = withGroup();
    r.accounts.find((a) => a.id === 'gmail-22222222')!.check = { state: 'error', message: 'Google refused the login (invalid_grant)', ms: 3 };
    const out = render(r, d, { tty: true });
    expect(out).toContain('\u001b[31m✗\u001b[0m Private  alice@example.test');
    expect(out).toMatch(/ {2}\u001b\[31m✗\u001b\[0m Gmail {6}gmail-22222222 +\u001b\[31mFAILED\u001b\[0m\n {4}\u001b\[31mGoogle refused the login \(invalid_grant\)\u001b\[0m\n/);
    expect(out).toMatch(/ {2}\u001b\[32m☑\u001b\[0m Drive /);
  });

  it('separately connected Google accounts keep their own sections and hints; no unconnected Google line', () => {
    const d = baseStore();
    d.gmail.push({ id: 'gmail-0000000a', label: 'Old', email: 'w@example.test', clientId: 'c', clientSecret: 'DUMMY-secret', refreshToken: SECRETS[2]!, scopes: [GMAIL_READONLY_SCOPE], createdAt: AT, updatedAt: AT });
    const r = baseReport();
    r.accounts.push({ family: 'mail', id: 'gmail-0000000a', label: 'Old', provider: 'gmail', identity: 'w@example.test', permissions: 'read', connectedAt: AT });
    const out = render(r, d);
    expect(out).toMatch(/── Mail · Gmail ─+\n☑ Old  w@example\.test/);
    expect(out).toContain('    perch gmail remove gmail-0000000a && perch google add --label Old --services gmail --allow-drafts --login-hint w@example.test\n');
    expect(out).not.toContain('☐ Google (Drive');
    expect(out).not.toContain('perch google access');
    expect(formatStatusText(r)).not.toContain('Google (Drive, Gmail, Calendar, Contacts): none');
  });

  it('plain renderer lists a group with its members and no empty Google family lines', () => {
    const { r } = withGroup();
    const plain = formatStatusText(r);
    expect(plain).toContain('Google accounts (one login each)\n  ggroup-1a2b3c4d  "Private"  alice@example.test  services: drive, gmail, calendar  since 2026-10-20\n');
    expect(plain).toContain('    Mail: ✓ gmail-22222222  "Private"  alice@example.test  [gmail: read, draft, send]');
    expect(plain).not.toMatch(/^(Google Drive|Google Calendar\/Contacts|Google \(Drive)/m);
  });
});

/** baseStore/baseReport plus one Google account group: Drive read, Gmail write, Calendar read, no Contacts. */
function withGroup(): { d: StoreData; r: StatusReport } {
  const d = baseStore();
  const gid = 'ggroup-1a2b3c4d';
  const member = { label: 'Private', email: 'alice@example.test', groupId: gid, createdAt: AT, updatedAt: AT };
  d.googleGroups.push({ id: gid, label: 'Private', email: 'alice@example.test', sub: '1001', clientId: 'c', clientSecret: 'DUMMY-group-secret', refreshToken: 'DUMMY-group-refresh', scopes: [], createdAt: AT, updatedAt: AT });
  d.google.push({ id: 'google-11111111', ...member, scopes: ['https://www.googleapis.com/auth/drive.readonly'] });
  d.gmail.push({ id: 'gmail-22222222', ...member, scopes: [GMAIL_READONLY_SCOPE, 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.modify'] });
  d.googleProductivity.push({ id: 'gprod-33333333', ...member, sub: '1001', scopes: ['openid', 'https://www.googleapis.com/auth/calendar.readonly'], services: ['calendar'], allowCalendarWrite: false });
  const r = baseReport();
  const acc = { label: 'Private', identity: 'alice@example.test', connectedAt: AT, groupId: gid };
  r.accounts.push(
    { family: 'drive', id: 'google-11111111', provider: 'google', permissions: 'read', ...acc, check: { state: 'ok', ms: 5 } },
    { family: 'mail', id: 'gmail-22222222', provider: 'gmail', permissions: 'read, draft, send', ...acc, check: { state: 'ok', ms: 6 } },
    { family: 'calendar', id: 'gprod-33333333', provider: 'google', permissions: 'calendar read', ...acc, check: { state: 'ok', ms: 7 } },
  );
  r.googleGroups = [{ id: gid, label: 'Private', email: 'alice@example.test', services: ['drive', 'gmail', 'calendar'], accountIds: ['google-11111111', 'gmail-22222222', 'gprod-33333333'], connectedAt: AT }];
  return { d, r };
}
