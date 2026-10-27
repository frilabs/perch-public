import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PerchContext } from '../src/context.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
import { collectStatus, formatStatusText } from '../src/status/status.js';
import { renderStatusPage } from '../src/status/page.js';
import { accountCapabilities, formatStatusTerminal } from '../src/status/terminal.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs } from './support/fixtures.js';

const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0)) await cleanup(); });
async function fixture() {
  const dirs = await makeTempDirs(); cleanups.push(dirs.cleanup);
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const group = MicrosoftSessionGroupSchema.parse({
    id: 'mgroup-12345678', label: 'Work account', email: 'dummy@example.test', profileId: 'ms-session-0123456789abcdef01234567',
    identity: { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' },
    members: { teams: 'msteams-12345678', mail: 'msmail-12345678', calendar: 'mscalendar-12345678', files: 'msfiles-12345678' },
    services: {
      teams: { enabled: true, write: true, invite: false, status: 'ready', checkedAt: '2026-10-25T12:00:00.000Z' },
      mail: { enabled: true, write: false, invite: false, status: 'reauth_required', checkedAt: '2026-10-25T12:01:00.000Z' },
      calendar: { enabled: true, write: true, invite: false, status: 'unverified' },
      files: { enabled: false, write: true, invite: true, status: 'unavailable' },
    },
    sites: [], createdAt: '2026-10-24T00:00:00.000Z', updatedAt: '2026-10-25T00:00:00.000Z', revision: '12345678',
  });
  await store.update((data) => { data.microsoftSessions = [group]; });
  const execute = vi.fn(), probeProfile = vi.fn();
  const ctx = { store, microsoftSession: { execute }, microsoftSessionRuntime: { probeProfile } } as unknown as PerchContext;
  return { store, group, ctx, execute, probeProfile };
}

describe('Microsoft session stored status', () => {
  it('reports group/service permissions and previous probe times without starting a browser', async () => {
    const f = await fixture();
    const report = await collectStatus(f.ctx, { live: true });
    expect(report.microsoftGroups).toEqual([expect.objectContaining({ id: f.group.id, label: 'Work account', email: f.group.email, services: [
      expect.objectContaining({ service: 'teams', accountId: f.group.members.teams, enabled: true, write: true, invite: false, status: 'ready', checkedAt: '2026-10-25T12:00:00.000Z' }),
      expect.objectContaining({ service: 'mail', accountId: f.group.members.mail, enabled: true, write: false, status: 'reauth_required' }),
      expect.objectContaining({ service: 'calendar', status: 'unverified' }),
      expect.objectContaining({ service: 'files', enabled: false, write: false, invite: false }),
    ] })]);
    expect(report.accounts).toHaveLength(3);
    expect(report.accounts.every((account) => account.check?.state === 'skipped')).toBe(true);
    expect(f.execute).not.toHaveBeenCalled();
    expect(f.probeProfile).not.toHaveBeenCalled();
    expect(JSON.stringify(report)).not.toContain(f.group.profileId);
    expect(JSON.stringify(report)).not.toContain(f.group.identity.objectId);
  });

  it('distinguishes local rights from last probe state and keeps invite permission separate', async () => {
    const f = await fixture(), data = await f.store.read();
    const caps = accountCapabilities(data);
    const enabled = (id: string, name: string) => caps[id]!.find((cap) => cap.name === name)!.enabled;
    expect(enabled(f.group.members.teams, 'send')).toBe(true);
    expect(enabled(f.group.members.mail, 'read')).toBe(true);
    for (const name of ['drafts', 'send', 'organize']) expect(enabled(f.group.members.mail, name)).toBe(false);
    expect(enabled(f.group.members.calendar, 'write')).toBe(true);
    expect(enabled(f.group.members.calendar, 'invitations')).toBe(false);
    expect(caps[f.group.members.files]!.every((cap) => !cap.enabled)).toBe(true);
    expect(caps[f.group.members.calendar]!.find((cap) => cap.name === 'invitations')!.enable).toBe(`perch microsoft access ${f.group.id}`);
    data.microsoftSessions![0]!.services.calendar.invite = true;
    expect(accountCapabilities(data)[f.group.members.calendar]!.find((cap) => cap.name === 'invitations')!.enabled).toBe(true);
    data.microsoftSessions![0]!.services.calendar.write = false;
    expect(accountCapabilities(data)[f.group.members.calendar]!.find((cap) => cap.name === 'invitations')!.enabled).toBe(false);
  });

  it('renders a grouped terminal/plain report with explicit last-probe labels and doctor command', async () => {
    const f = await fixture(), report = await collectStatus(f.ctx, { live: true });
    const terminal = formatStatusTerminal(report, accountCapabilities(await f.store.read()), { tty: false, columns: 80, env: {} });
    const plain = formatStatusText(report);
    for (const output of [terminal, plain]) {
      expect(output).toContain('Microsoft');
      expect(output).toContain('Work account');
      expect(output).toContain('last probe');
      expect(output).toContain('2026-10-25');
      expect(output).toContain('reauth_required');
      expect(output).toContain('unverified');
      expect(output).toContain(`perch microsoft doctor ${f.group.id}`);
      expect(output).not.toContain('All checks passed');
      expect(output).not.toContain('ERROR: undefined');
      expect(output).not.toContain('only in Google account groups');
    }
    expect(terminal).toContain('disabled');
    expect(terminal).toContain('☐ invitations');
    expect(terminal).not.toMatch(/Mail · IMAP.*msmail/s);
    // Existing setup commands intentionally remain whole for copy/paste.
    for (const line of terminal.split('\n')) if (!line.trimStart().startsWith('perch ')) expect([...line].length).toBeLessThanOrEqual(80);
  });

  it('does not invent last probe times for an unverified connection', async () => {
    const f = await fixture();
    const report = await collectStatus(f.ctx, { live: false });
    const service = report.microsoftGroups![0]!.services.find((item) => item.service === 'calendar')!;
    expect(service.checkedAt).toBeUndefined();
    expect(formatStatusText(report)).toContain('last probe: never');
  });
  it('colors only enabled ready services green and keeps probe times beside them', async () => {
    const f = await fixture(), report = await collectStatus(f.ctx, { live: false });
    report.microsoftGroups![0]!.services.find(s => s.service === 'files')!.status = 'ready';
    const render = (columns: number) => formatStatusTerminal(report, {}, { tty: true, columns, env: {} });
    for (const columns of [60, 80, 120]) {
      const lines = render(columns).split('\n');
      const teams = lines.find(line => line.includes('teams '))!;
      expect(teams).toContain('\x1b[32m☑\x1b[0m');
      expect(teams).toContain('\x1b[32mready');
      if (columns >= 80) expect(teams).toContain('last probe: 2026-10-25 12:00 UTC');
      expect(lines.find(line => line.includes('mail '))).toContain('\x1b[33m✗');
      for (const name of ['calendar', 'files', 'Work account']) expect(lines.find(line => line.includes(name))).not.toContain('\x1b[32m');
      for (const line of lines) if (!line.trimStart().startsWith('perch ')) expect([...line.replace(/\x1b\[[0-9;]*m/g, '')].length).toBeLessThanOrEqual(columns);
    }
    expect(f.probeProfile).not.toHaveBeenCalled();
  });
  it('colors the Microsoft group green only when it has enabled services and all are ready', async () => {
    const f = await fixture(), report = await collectStatus(f.ctx, { live: false });
    const group = report.microsoftGroups![0]!;
    for (const service of group.services) service.status = 'ready';
    const line = (env = {}, tty = true) => formatStatusTerminal(report, {}, { tty, columns: 120, env }).split('\n').find(line => line.includes('Work account  dummy'))!;
    expect(line()).toContain('\x1b[32m☑\x1b[0m');
    expect(line()).toContain('\x1b[32mready\x1b[0m');
    expect(line({ NO_COLOR: '1' })).not.toContain('\x1b[');
    expect(line({}, false)).not.toContain('\x1b[');
    for (const service of group.services) service.enabled = false;
    expect(line()).not.toContain('\x1b[32m');
  });
  it('renders skipped Microsoft probes as stored status on the web page, without false success or failure', async () => {
    const f = await fixture(), report = await collectStatus(f.ctx, { live: true });
    const html = renderStatusPage(report);
    expect(html).toContain('Stored probe');
    expect(html).toContain('Microsoft session status is stored');
    expect(html).not.toContain('All checks passed');
    expect(html).not.toContain('pill bad');
    expect(html).toContain(`perch microsoft doctor ${f.group.id}`);
  });
});
