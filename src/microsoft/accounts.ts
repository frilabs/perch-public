import { PerchError } from '../errors.js';
import type { CredentialStore } from '../store/credentialStore.js';

/** Explicit local removal of a retained legacy OAuth credential; never refresh or use it. */
export async function removeMicrosoftAccount(store: CredentialStore, id: string): Promise<void> {
  await store.update((data) => {
    if (!data.microsoft.some((m) => m.id === id)) throw new PerchError(`Unknown Microsoft account: ${id}`, 'unknown_account');
    data.microsoft = data.microsoft.filter((m) => m.id !== id);
  });
}
