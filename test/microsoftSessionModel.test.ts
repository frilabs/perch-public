import { describe, expect, it } from 'vitest';
import { MicrosoftSessionGroupSchema, sessionMailAccounts } from '../src/microsoft/session/model.js';

const group = () => ({
  id: 'mgroup-12345678', label: 'Work', email: 'test@example.test', displayName: 'Test',
  profileId: 'ms-session-0123456789abcdef01234567',
  identity: { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', mailboxId: 'mailbox-1', kind: 'organization' },
  members: { teams: 'msteams-12345678', mail: 'msmail-12345678', calendar: 'mscalendar-12345678', files: 'msfiles-12345678' },
  services: Object.fromEntries(['teams','mail','calendar','files'].map(k => [k, { enabled: true, write: false, invite: false, status: 'unverified' }])),
  sites: [], createdAt: '2026-10-26T00:00:00.000Z', updatedAt: '2026-10-26T00:00:00.000Z', revision: '12345678',
});
describe('Microsoft session group model', () => {
  it('holds one identity and stable service members without OAuth secrets', () => {
    const parsed = MicrosoftSessionGroupSchema.parse(group());
    expect(parsed.members.mail).toBe('msmail-12345678');
    expect(parsed).not.toHaveProperty('refreshToken');
    expect(sessionMailAccounts([parsed])[0]).toMatchObject({ id: 'msmail-12345678', groupId: 'mgroup-12345678', email: 'test@example.test' });
  });
  it('rejects profile traversal, mixed member prefixes, and malformed stable identity', () => {
    expect(() => MicrosoftSessionGroupSchema.parse({ ...group(), profileId: '../../x' })).toThrow();
    expect(() => MicrosoftSessionGroupSchema.parse({ ...group(), members: { ...group().members, files: 'google-12345678' } })).toThrow();
    expect(() => MicrosoftSessionGroupSchema.parse({ ...group(), identity: { ...group().identity, objectId: '' } })).toThrow();
  });
  it('does not expose disabled mail as a connected mail account', () => {
    const value = group(); value.services.mail!.enabled = false;
    expect(sessionMailAccounts([MicrosoftSessionGroupSchema.parse(value)])).toEqual([]);
  });
});

import { initStore, CredentialStore } from '../src/store/credentialStore.js';
import { createClientGrant, createDeviceGrant, principalFromGrant, assertMicrosoftSessionCapability, READONLY_PRINCIPAL, parseCapabilities } from '../src/auth/grants.js';
import { makeTempDirs } from './support/fixtures.js';
it('persists groups without changing Graph accounts and confines service capabilities to selected members', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    await store.update((d) => { d.microsoftSessions = [MicrosoftSessionGroupSchema.parse(group())]; });
    expect((await store.read()).microsoft).toEqual([]);
    expect((await store.read()).microsoftSessions).toHaveLength(1);
    const caps = parseCapabilities(['microsoft_teams_read']);
    const grant = await createDeviceGrant(store, { label: 'Teams', capabilities: caps, accountIds: ['msteams-12345678'] });
    const principal = principalFromGrant(grant);
    expect(() => assertMicrosoftSessionCapability(principal, 'teams', 'msteams-12345678', 'microsoft_teams_read')).not.toThrow();
    expect(() => assertMicrosoftSessionCapability(principal, 'teams', 'msteams-ffffffff', 'microsoft_teams_read')).toThrow();
    expect(() => assertMicrosoftSessionCapability(principal, 'files', 'msfiles-12345678', 'microsoft_files_read')).toThrow();
    expect(() => assertMicrosoftSessionCapability(READONLY_PRINCIPAL, 'teams', 'msteams-12345678', 'microsoft_teams_send')).toThrow();
    await expect(createDeviceGrant(store, { label: 'Bad', capabilities: caps, accountIds: ['msfiles-12345678'] })).rejects.toThrow();
  } finally { await dirs.cleanup(); }
});

import path from 'node:path';
import { createPerchContext } from '../src/context.js';
it('read-all includes Microsoft members in its snapshot and discovers later accounts without write rights', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs);
    const store = await CredentialStore.open(dirs);
    const first = MicrosoftSessionGroupSchema.parse(group());
    for (const service of Object.values(first.services)) { service.write = true; service.invite = true; }
    await store.update(data => { data.microsoftSessions = [first]; });
    const { client: grant } = await createClientGrant(store, { label: 'Reader', capabilities: [], accountIds: [], readAll: true, tokenFile: path.join(dirs.dataDir, 'reader.token') });
    expect(grant.accountIds).toEqual(expect.arrayContaining(Object.values(first.members)));
    const principal = principalFromGrant(grant);
    const service = createPerchContext(store).microsoftSession;
    const initial = await service.listAccounts(principal);
    expect(initial.map(account => account.service).sort()).toEqual(['calendar', 'files', 'teams']);
    expect(initial.every(account => !account.canWrite && !account.canInvite)).toBe(true);
    for (const kind of ['teams', 'calendar', 'files'] as const) {
      expect(() => assertMicrosoftSessionCapability(principal, kind, first.members[kind], `microsoft_${kind}_read`)).not.toThrow();
      expect(() => assertMicrosoftSessionCapability(principal, kind, first.members[kind], kind === 'teams' ? 'microsoft_teams_send' : `microsoft_${kind}_write`)).toThrow();
    }
    const later = MicrosoftSessionGroupSchema.parse({ ...first, id: 'mgroup-87654321', label: 'Later', profileId: 'ms-session-abcdef0123456789abcdef01', members: { teams: 'msteams-87654321', mail: 'msmail-87654321', calendar: 'mscalendar-87654321', files: 'msfiles-87654321' } });
    later.services.files.enabled = false;
    await store.update(data => { data.microsoftSessions!.push(later); });
    const discovered = await service.listAccounts(principal);
    expect(discovered.map(account => account.accountId)).toEqual(expect.arrayContaining([later.members.teams, later.members.calendar]));
    expect(discovered.map(account => account.accountId)).not.toContain(later.members.files);
    expect(discovered).toHaveLength(5);
  } finally { await dirs.cleanup(); }
});
