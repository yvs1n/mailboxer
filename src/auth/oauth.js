/**
 * Mailboxer OAuth 2.0 Engine for Google & Microsoft
 *
 * Implements one-click OAuth authentication for Google Mail and Microsoft Outlook / 365.
 * Handles authorization URLs, code-for-token exchanges, user profile retrieval,
 * and transparent background token refreshing for permanent logins.
 *
 * Zero-dependency native Node.js 22 implementation using built-in fetch and node:crypto.
 *
 * @module auth/oauth
 */

import crypto from 'node:crypto';

export const OAUTH_CONFIGS = Object.freeze({
  gmail: {
    name: 'Google Mail',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: [
      'https://mail.google.com/',
      'openid',
      'email',
      'profile'
    ],
    defaultClientId: () => process.env.GOOGLE_CLIENT_ID || '',
    defaultClientSecret: () => process.env.GOOGLE_CLIENT_SECRET || ''
  },
  outlook: {
    name: 'Microsoft Outlook',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    scopes: [
      'offline_access',
      'https://outlook.office.com/IMAP.AccessAsUser.All',
      'https://outlook.office.com/SMTP.Send',
      'User.Read'
    ],
    defaultClientId: () => process.env.MICROSOFT_CLIENT_ID || '',
    defaultClientSecret: () => process.env.MICROSOFT_CLIENT_SECRET || ''
  }
});

export class OAuthManager {
  constructor(options = {}) {
    this.configs = {
      gmail: {
        clientId: options.googleClientId || process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: options.googleClientSecret || process.env.GOOGLE_CLIENT_SECRET || ''
      },
      outlook: {
        clientId: options.microsoftClientId || process.env.MICROSOFT_CLIENT_ID || '',
        clientSecret: options.microsoftClientSecret || process.env.MICROSOFT_CLIENT_SECRET || ''
      }
    };
    // Must match the public URL registered with Google / Microsoft (e.g. https://mail.example.com)
    this.redirectBase = (options.redirectBase || process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
    this._inFlightRefreshes = new Map();
    this._pendingStates = new Map();
  }

  /**
   * Sets or updates OAuth credentials dynamically.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {{ clientId: string, clientSecret: string }} creds
   */
  setCredentials(provider, { clientId, clientSecret }) {
    if (this.configs[provider]) {
      this.configs[provider].clientId = clientId;
      this.configs[provider].clientSecret = clientSecret;
    }
  }

  /**
   * Checks whether OAuth credentials are configured for a given provider.
   *
   * @param {'gmail'|'outlook'} provider
   * @returns {boolean}
   */
  isConfigured(provider) {
    const conf = this.configs[provider];
    return Boolean(conf && conf.clientId && conf.clientId.trim().length > 0);
  }

  /**
   * Generates standard authorization URL for the browser popup.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {string} [state] - Random state for CSRF defense
   * @returns {{ url: string, state: string, redirectUri: string }}
   */
  getAuthorizationUrl(provider, state = crypto.randomUUID()) {
    const config = OAUTH_CONFIGS[provider];
    if (!config) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    const client = this.configs[provider];
    if (!client.clientId) {
      throw new Error(`Missing OAuth Client ID for ${config.name}. Set ${provider === 'gmail' ? 'GOOGLE_CLIENT_ID' : 'MICROSOFT_CLIENT_ID'}.`);
    }

    // Register state for CSRF protection with 10-minute TTL
    this._pendingStates.set(state, {
      provider,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    const redirectUri = `${this.redirectBase}/api/auth/${provider}/callback`;
    const params = new URLSearchParams({
      client_id: client.clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: config.scopes.join(' '),
      state,
      access_type: 'offline', // Essential for Google refresh token
      prompt: 'consent' // Forces Google to return a refresh token
    });

    if (provider === 'outlook') {
      params.set('response_mode', 'query');
    }

    return {
      url: `${config.authUrl}?${params.toString()}`,
      state,
      redirectUri
    };
  }

  /**
   * Validates and consumes an OAuth CSRF state parameter.
   * Single-use token: once validated, it is immediately deleted.
   *
   * @param {string} state - The state parameter returned in callback query
   * @param {'gmail'|'outlook'} [expectedProvider] - Optional expected provider
   * @returns {{ valid: boolean, error?: string }}
   */
  validateAndConsumeState(state, expectedProvider) {
    if (!state || typeof state !== 'string') {
      return { valid: false, error: 'Missing OAuth state parameter (CSRF protection)' };
    }

    const now = Date.now();
    for (const [s, data] of this._pendingStates.entries()) {
      if (data.expiresAt < now) {
        this._pendingStates.delete(s);
      }
    }

    const recorded = this._pendingStates.get(state);
    if (!recorded) {
      return { valid: false, error: 'Invalid or expired OAuth state parameter' };
    }

    if (expectedProvider && recorded.provider !== expectedProvider) {
      return { valid: false, error: `OAuth state mismatch: expected ${recorded.provider}, got ${expectedProvider}` };
    }

    this._pendingStates.delete(state);
    return { valid: true };
  }

  /**
   * Checks if there are any active pending states.
   * @returns {boolean}
   */
  hasPendingStates() {
    const now = Date.now();
    for (const [s, data] of this._pendingStates.entries()) {
      if (data.expiresAt < now) {
        this._pendingStates.delete(s);
      }
    }
    return this._pendingStates.size > 0;
  }

  /**
   * Clears pending states.
   */
  clearPendingStates() {
    this._pendingStates.clear();
  }

  /**
   * Exchanges authorization code for access and refresh tokens.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {string} code - The authorization code from query params
   * @param {string} [customRedirectUri]
   * @returns {Promise<{ accessToken: string, refreshToken: string, expiresIn: number, expiresAt: number, scope: string }>}
   */
  async exchangeCodeForTokens(provider, code, customRedirectUri) {
    const config = OAUTH_CONFIGS[provider];
    if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);

    const client = this.configs[provider];
    const redirectUri = customRedirectUri || `${this.redirectBase}/api/auth/${provider}/callback`;

    const bodyParams = new URLSearchParams({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    const res = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString()
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`OAuth token endpoint (${provider}) returned HTTP ${res.status}: ${res.statusText || 'Invalid JSON response'}`);
    }

    if (!res.ok || data.error) {
      const msg = data.error_description || data.error || 'Token exchange failed';
      throw new Error(`OAuth token error (${provider}): ${msg}`);
    }

    const expiresIn = Number(data.expires_in) || 3600;
    const expiresAt = Date.now() + (expiresIn * 1000);

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || '',
      expiresIn,
      expiresAt,
      scope: data.scope || ''
    };
  }

  /**
   * Fetches user profile (email and display name) using the access token.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {string} accessToken
   * @returns {Promise<{ email: string, name: string, picture?: string }>}
   */
  async getUserInfo(provider, accessToken) {
    const config = OAUTH_CONFIGS[provider];
    if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);

    const res = await fetch(config.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`OAuth userinfo endpoint (${provider}) returned HTTP ${res.status}: ${res.statusText || 'Invalid JSON response'}`);
    }

    if (!res.ok) {
      throw new Error(`Failed to fetch user profile: ${data.error?.message || res.statusText}`);
    }

    if (provider === 'gmail') {
      return {
        email: (data.email || '').toLowerCase().trim(),
        name: data.name || data.given_name || data.email,
        picture: data.picture || ''
      };
    } else if (provider === 'outlook') {
      const email = (data.mail || data.userPrincipalName || '').toLowerCase().trim();
      return {
        email,
        name: data.displayName || data.mail || data.userPrincipalName,
        picture: ''
      };
    }

    return { email: '', name: '' };
  }

  /**
   * Refreshes an expired access token using the stored refresh token.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {string} refreshToken
   * @returns {Promise<{ accessToken: string, refreshToken?: string, expiresIn: number, expiresAt: number }>}
   */
  async refreshAccessToken(provider, refreshToken) {
    if (!refreshToken) {
      throw new Error(`Cannot refresh token for ${provider}: no refresh token available`);
    }

    const config = OAUTH_CONFIGS[provider];
    const client = this.configs[provider];

    const bodyParams = new URLSearchParams({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    });

    const res = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString()
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`OAuth refresh endpoint (${provider}) returned HTTP ${res.status}: ${res.statusText || 'Invalid JSON response'}`);
    }

    if (!res.ok || data.error) {
      const msg = data.error_description || data.error || 'Token refresh failed';
      throw new Error(`Failed to refresh OAuth token (${provider}): ${msg}`);
    }

    const expiresIn = Number(data.expires_in) || 3600;
    const expiresAt = Date.now() + (expiresIn * 1000);

    return {
      accessToken: data.access_token,
      // If server returned a new rolling refresh token, keep it
      refreshToken: data.refresh_token || refreshToken,
      expiresIn,
      expiresAt
    };
  }

  /**
   * Ensures an account has an active, valid access token.
   * Automatically refreshes expired or soon-to-expire tokens and updates the vault.
   * Guarantees permanent login and de-duplicates in-flight refresh requests.
   *
   * @param {object} account - Account configuration from vault
   * @param {object} [vault] - CredentialVault instance to persist new tokens
   * @returns {Promise<object>} The account with guaranteed valid accessToken
   */
  async ensureValidToken(account, vault) {
    if (account.auth?.type !== 'oauth2') {
      return account;
    }

    const now = Date.now();
    const expiresAt = account.auth.expiresAt || 0;
    const bufferMs = 5 * 60 * 1000; // 5-minute safety threshold

    if (now + bufferMs < expiresAt && account.auth.accessToken) {
      return account; // Token is still fresh
    }

    // Token is expired or expiring soon -> Refresh it transparently
    const provider = account.provider;
    const refreshToken = account.auth.refreshToken;

    if (!refreshToken) {
      throw new Error(`Cannot refresh token for ${provider} account (${account.email || account.id || 'unknown'}): no refresh token available`);
    }

    const refreshKey = `${account.id || account.email || provider}:${refreshToken}`;
    let refreshPromise = this._inFlightRefreshes.get(refreshKey);

    if (!refreshPromise) {
      refreshPromise = (async () => {
        try {
          const refreshed = await this.refreshAccessToken(provider, refreshToken);

          account.auth.accessToken = refreshed.accessToken;
          account.auth.expiresAt = refreshed.expiresAt;
          if (refreshed.refreshToken) {
            account.auth.refreshToken = refreshed.refreshToken;
          }
          account.lastVerifiedAt = new Date().toISOString();

          if (vault && typeof vault.saveAccount === 'function') {
            await vault.saveAccount(account);
          }

          return account;
        } finally {
          this._inFlightRefreshes.delete(refreshKey);
        }
      })();
      this._inFlightRefreshes.set(refreshKey, refreshPromise);
    }

    return refreshPromise;
  }
}

export const defaultOAuthManager = new OAuthManager();
