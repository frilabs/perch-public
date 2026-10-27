import { SLACK_USER_SCOPES } from './slack.js';

/**
 * Manifest of the internal Slack app to create once per workspace (api.slack.com/apps > Create New App >
 * From a manifest). Only user scopes: the installing user's token (xoxp-…) reads what that user can see
 * and posts as that user. Token rotation stays off, so the token does not expire. Identical to
 * docs/slack-app-manifest.json (a test keeps both in sync).
 */
export const SLACK_APP_MANIFEST = {
  display_information: {
    name: 'Perch',
    description: 'Personal MCP connector: lets my own AI tools read and post Slack messages as me.',
  },
  oauth_config: {
    scopes: { user: [...SLACK_USER_SCOPES] },
  },
  settings: {
    org_deploy_enabled: false,
    socket_mode_enabled: false,
    token_rotation_enabled: false,
  },
};
