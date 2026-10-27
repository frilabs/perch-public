// The root URL can show an anonymous product page instead of starting sign-in.
// https://support.microsoft.com/en-us/accounts-billing/subscriptions/i-forgot-the-account-i-use-with-microsoft-365
export const MICROSOFT_SIGN_IN_URL = 'https://www.microsoft365.com/signin';

// Exact authentication hosts only; static CDNs must not gain POST exceptions.
export const MICROSOFT_LOGIN_HOSTS = [
  'login.microsoftonline.com', 'login.microsoft.com', 'login.live.com', 'account.live.com',
] as const;
