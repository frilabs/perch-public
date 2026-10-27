import { yes } from './onboarding.js';

export const NOTION_INTEGRATIONS_URL = 'https://www.notion.so/profile/integrations';

interface Io {
  stdout: (s: string) => void;
  readLine?: (prompt: string) => Promise<string>;
}

/**
 * Guide before the Notion token prompt (docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §2): where to create the
 * internal integration, which capabilities, which secret, and that pages must be shared with it.
 * Same rules as the Slack guide: skipped with --skip-guide and without a terminal, asked ("[y/N]") when a
 * workspace is already connected. Returns true when the guide was shown.
 */
export async function maybeShowNotionGuide(io: Io, opts: { skip: boolean; hasWorkspace: boolean }): Promise<boolean> {
  const ask = io.readLine;
  if (opts.skip || !ask) return false;
  if (opts.hasWorkspace && !yes(await ask('Show the steps for this Notion workspace? [y/N] '))) return false;
  io.stdout(
    '\nCreate a Notion integration for this workspace.\n\n' +
      `1. Open ${NOTION_INTEGRATIONS_URL}\n` +
      '2. "New integration": name "Perch", pick the workspace, type "Internal", Save.\n' +
      '3. Capabilities: Read content, Update content, Insert content,\n' +
      '   Read comments, Insert comments. Save changes.\n' +
      '4. Copy the "Internal Integration Secret" (starts with ntn_).\n\n' +
      'Share each page with Perch:\n' +
      '••• → Connections → Perch (subpages inherit access).\n' +
      'If only workspace owners can create integrations, ask an owner to do this.\n\n',
  );
  await ask('Press Enter after copying the secret. ');
  return true;
}
