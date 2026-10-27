import { PerchError } from '../errors.js';
import { validateLabel } from '../ids.js';
import type { CredentialStore, StoreData } from './credentialStore.js';

/** Store sections whose records carry a user-chosen `label` (accounts, groups and client grants). */
const LABELLED = ['googleGroups', 'google', 'notion', 'gmail', 'microsoft', 'imap', 'googleProductivity', 'slack', 'whatsapp', 'luma', 'x', 'clients'] as const;

type Labelled = { id: string; label: string; updatedAt?: string; groupId?: string };

/**
 * `perch rename ID LABEL`: changes only the label (ids, credentials and grants stay the same).
 * A Google account group (`ggroup-…`) renames the group and all of its services; a single group
 * member is refused so the services of one login keep one name.
 */
export async function renameRecord(store: CredentialStore, id: string, rawLabel: string): Promise<{ id: string; label: string; renamed: string[] }> {
  const label = validateLabel(rawLabel);
  return store.update((data: StoreData) => {
    const now = new Date().toISOString();
    const sections = LABELLED.map((k) => (data[k] ?? []) as Labelled[]);
    const record = sections.flat().find((r) => r.id === id);
    if (!record) throw new PerchError(`Unknown id ${id} (see perch accounts or perch client list)`, 'unknown_account');
    if (record.groupId) {
      throw new PerchError(`${id} belongs to the Google account group ${record.groupId}; rename the group: perch rename ${record.groupId} "${label}"`, 'usage');
    }
    const targets = [record, ...(id.startsWith('ggroup-') ? sections.flat().filter((r) => r.groupId === id) : [])];
    for (const r of targets) {
      r.label = label;
      if ('updatedAt' in r) r.updatedAt = now;
    }
    return { id, label, renamed: targets.map((r) => r.id) };
  });
}
