export const SLACK_WEB_CLIENT_URL = 'https://app.slack.com/client';

interface Io {
  stdout: (s: string) => void;
}

export const SLACK_SESSION_WARNING = 'Perch stores your Slack browser session encrypted.\n';

/**
 * Browser console line that prints the name and the session token (xoxc-…) of the workspace open in the tab.
 * The Slack web client keeps its teams in localStorage.localConfig_v2, keyed by team id; the open team is the
 * id in the address (/client/T…/…), else the last active one.
 */
export const SLACK_TOKEN_CONSOLE_LINE =
  "c = JSON.parse(localStorage.localConfig_v2); t = c.teams[location.pathname.split('/')[2]] || c.teams[c.lastActiveTeamId]; console.log(t.name + '\\n' + t.token)";

/** Essential browser steps; credentials are collected by the caller's masked prompts. */
export function showSlackSessionGuide(io: Io, opts: { skip: boolean }): void {
  if (opts.skip) return;
  io.stdout(
    `\n1. Open ${SLACK_WEB_CLIENT_URL} and sign in to the workspace.\n` +
      '2. Open developer tools: Cmd+Opt+I (Windows/Linux: Ctrl+Shift+I).\n' +
      '   Safari: enable Settings > Advanced > Show features for web developers first.\n' +
      '3. Application (Firefox/Safari: Storage) > Cookies > https://app.slack.com:\n' +
      '   copy the value of "d" (starts with xoxd-).\n' +
      '4. In Console, run this line to get the workspace name and token (xoxc-):\n\n' +
      `${SLACK_TOKEN_CONSOLE_LINE}\n\n` +
      'Check the workspace name, then paste the cookie and token below.\n\n',
  );
}
