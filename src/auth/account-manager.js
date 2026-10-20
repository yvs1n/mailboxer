/**
 * Mailboxer Account Management & Onboarding Hub
 *
 * Coordinates credential storage in the CredentialVault, OAuth 2.0 lifecycle,
 * and guided App-Specific Password onboarding for Apple Mail and Custom accounts.
 *
 * Enforces permanent login: accounts are only logged out when the user explicitly
 * clicks "Log Out" or removes the account.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module auth/account-manager
 */

import { defaultVault } from './vault.js';
import { defaultOAuthManager } from './oauth.js';
import { getPreset } from '../config/presets.js';
import { resolveAccountConfig, normalizeAppPassword, isValidEmail } from '../config/schema.js';
import { ImapClient } from '../connection/imap-client.js';

export class AccountManager {
  /**
   * @param {object} [options={}]
   * @param {CredentialVault} [options.vault]
   * @param {OAuthManager} [options.oauth]
   */
  constructor(options = {}) {
    this.vault = options.vault || defaultVault;
    this.oauth = options.oauth || defaultOAuthManager;
    this.transport = options.transport;
    this.imapClientFactory = options.imapClientFactory;
    this.store = options.store;
  }

  /**
   * Creates an ImapClient instance for an account configuration.
   * Supports injected transport or client factory for hermetic testing.
   *
   * @param {object} resolved - Resolved AccountConfig
   * @returns {ImapClient}
   * @private
   */
  _createImapClient(resolved) {
    if (this.imapClientFactory) {
      return this.imapClientFactory(resolved);
    }
    const transport = typeof this.transport === 'function' ? this.transport(resolved) : this.transport;
    return new ImapClient({ accountConfig: resolved, transport });
  }

  /**
   * Mirrors an account record to SQLite store if store is injected.
   * @param {object} saved
   * @private
   */
  _mirrorAccountToStore(saved) {
    if (this.store?.upsertAccount && saved) {
      try {
        this.store.upsertAccount({
          id: saved.id,
          email: saved.email,
          provider: saved.provider,
          name: saved.label
        });
      } catch {}
    }
  }

  /**
   * Initializes the manager and underlying vault.
   */
  async init() {
    await this.vault.init();
    if (this.store?.upsertAccount) {
      try {
        const publicAccounts = await this.vault.getPublicList();
        for (const acc of publicAccounts) {
          this.store.upsertAccount({
            id: acc.id,
            email: acc.email,
            provider: acc.provider,
            name: acc.label
          });
        }
      } catch {}
    }
  }

  /**
   * Lists all connected accounts for public display (secrets stripped).
   *
   * @returns {Promise<Array<object>>}
   */
  async listAccounts() {
    return this.vault.getPublicList();
  }

  /**
   * Connects an Apple Mail account using a 16-character App-Specific Password.
   * Runs an immediate live verification test against Apple's IMAP server before saving.
   *
   * @param {object} params
   * @param {string} params.email - Apple ID (@icloud.com, @me.com, @mac.com)
   * @param {string} params.appPassword - 16-character app-specific password
   * @param {string} [params.label] - Friendly display label (default: "Apple Mail")
   * @returns {Promise<{ account: object, testResult: object }>}
   */
  async addAppleAccount({ email, appPassword, label = 'Apple Mail (iCloud)' } = {}) {
    if (!email || !appPassword || typeof email !== 'string' || typeof appPassword !== 'string' || !email.trim() || !appPassword.trim()) {
      const err = new Error('Email address and Apple App-Specific Password are required');
      err.code = 'VALIDATION_ERROR';
      throw err;
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanPass = normalizeAppPassword(appPassword).toLowerCase();

    if (!isValidEmail(cleanEmail)) {
      const err = new Error('Please enter a valid email address (e.g. name@icloud.com)');
      err.code = 'INVALID_CREDENTIALS';
      err.remediationAdvice = 'Check your email address spelling and format.';
      throw err;
    }

    if (cleanPass.length !== 16) {
      const err = new Error('Apple App-Specific Password must be exactly 16 characters (e.g. xxxx-xxxx-xxxx-xxxx)');
      err.code = 'INVALID_CREDENTIALS';
      err.remediationAdvice = 'Generate a 16-character App-Specific Password at https://appleid.apple.com';
      throw err;
    }

    const resolved = resolveAccountConfig({
      provider: 'apple',
      email: cleanEmail,
      password: cleanPass,
      label
    });

    // Pre-flight connection test against Apple IMAP
    const client = this._createImapClient(resolved);
    const testResult = await client.verify(resolved);

    if (!testResult.success) {
      const err = new Error(testResult.error?.message || 'Failed to authenticate with Apple Mail');
      err.code = testResult.error?.code || 'AUTH_FAILED';
      err.remediationAdvice = testResult.error?.remediationAdvice || 'Ensure your Apple App-Specific Password was created at https://appleid.apple.com';
      throw err;
    }

    // Save permanently to encrypted vault
    const accountToStore = {
      ...resolved,
      lastVerifiedAt: new Date().toISOString(),
      connected: true,
      inboxStatus: testResult.inboxStatus
    };

    const saved = await this.vault.saveAccount(accountToStore);
    this._mirrorAccountToStore(saved);
    return {
      account: {
        id: saved.id,
        provider: saved.provider,
        label: saved.label,
        email: saved.email,
        authType: 'app_password',
        connected: true,
        lastVerifiedAt: saved.lastVerifiedAt,
        inboxStatus: testResult.inboxStatus
      },
      testResult
    };
  }

  /**
   * Connects a Google Mail account using a 16-character App Password.
   * Runs an immediate live verification test against Gmail's IMAP server before saving.
   *
   * @param {object} params
   * @param {string} params.email - Google account email (e.g. name@gmail.com)
   * @param {string} params.appPassword - 16-character Google App Password
   * @param {string} [params.label] - Friendly display label (default: "Google Mail")
   * @returns {Promise<{ account: object, testResult: object }>}
   */
  async addGoogleAccount({ email, appPassword, label = 'Google Mail' } = {}) {
    if (!email || !appPassword || typeof email !== 'string' || typeof appPassword !== 'string' || !email.trim() || !appPassword.trim()) {
      const err = new Error('Email address and Google App Password are required');
      err.code = 'VALIDATION_ERROR';
      throw err;
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanPass = normalizeAppPassword(appPassword).toLowerCase();

    if (!isValidEmail(cleanEmail)) {
      const err = new Error('Please enter a valid email address (e.g. name@gmail.com)');
      err.code = 'INVALID_CREDENTIALS';
      err.remediationAdvice = 'Check your email address spelling and format.';
      throw err;
    }

    if (cleanPass.length !== 16) {
      const err = new Error('Google App Password must be exactly 16 characters (e.g. xxxx-xxxx-xxxx-xxxx)');
      err.code = 'INVALID_CREDENTIALS';
      err.remediationAdvice = 'Generate a 16-character App Password at https://myaccount.google.com/apppasswords (requires 2-Step Verification enabled).';
      throw err;
    }

    const resolved = resolveAccountConfig({
      provider: 'gmail',
      email: cleanEmail,
      password: cleanPass,
      label
    });

    // Pre-flight connection test against Gmail IMAP
    const client = this._createImapClient(resolved);
    const testResult = await client.verify(resolved);

    if (!testResult.success) {
      const err = new Error(testResult.error?.message || 'Failed to authenticate with Google Mail');
      err.code = testResult.error?.code || 'AUTH_FAILED';
      err.remediationAdvice = testResult.error?.remediationAdvice || 'Ensure your Google App Password was generated at https://myaccount.google.com/apppasswords and IMAP is enabled in Gmail settings.';
      throw err;
    }

    // Save permanently to encrypted vault
    const accountToStore = {
      ...resolved,
      lastVerifiedAt: new Date().toISOString(),
      connected: true,
      inboxStatus: testResult.inboxStatus
    };

    const saved = await this.vault.saveAccount(accountToStore);
    this._mirrorAccountToStore(saved);
    return {
      account: {
        id: saved.id,
        provider: saved.provider,
        label: saved.label,
        email: saved.email,
        authType: 'app_password',
        connected: true,
        lastVerifiedAt: saved.lastVerifiedAt,
        inboxStatus: testResult.inboxStatus
      },
      testResult
    };
  }

  /**
   * Alias for addGoogleAccount
   *
   * @param {object} params
   * @returns {Promise<{ account: object, testResult: object }>}
   */
  async addGmailAccount(params) {
    return this.addGoogleAccount(params);
  }

  /**
   * Connects a Microsoft Outlook / Office 365 account using password or app password.
   * Runs an immediate live verification test against Outlook's IMAP server before saving.
   *
   * @param {object} params
   * @param {string} params.email - Outlook / Office 365 email (e.g. name@outlook.com or university email)
   * @param {string} [params.password] - Standard account password or app password
   * @param {string} [params.appPassword] - Optional app password alias
   * @param {string} [params.label] - Friendly display label (default: "Microsoft Outlook")
   * @returns {Promise<{ account: object, testResult: object }>}
   */
  async addOutlookAccount({ email, password, appPassword, label = 'Microsoft Outlook' } = {}) {
    const rawPass = password || appPassword;
    if (!email || !rawPass || typeof email !== 'string' || typeof rawPass !== 'string' || !email.trim() || !rawPass.trim()) {
      const err = new Error('Email address and password (or App Password) are required');
      err.code = 'VALIDATION_ERROR';
      throw err;
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!isValidEmail(cleanEmail)) {
      const err = new Error('Please enter a valid email address (e.g. name@outlook.com or university email)');
      err.code = 'INVALID_CREDENTIALS';
      err.remediationAdvice = 'Check your email address spelling and format.';
      throw err;
    }

    let cleanPass = rawPass.trim();
    const stripped = normalizeAppPassword(cleanPass);
    const is16CharAppPassword = Boolean(appPassword || (stripped.length === 16 && /^[a-zA-Z0-9]{16}$/.test(stripped) && /[-\s]/.test(cleanPass)));
    if (is16CharAppPassword) {
      cleanPass = stripped;
    }

    const authType = is16CharAppPassword ? 'app_password' : 'password';

    const resolved = resolveAccountConfig({
      provider: 'outlook',
      email: cleanEmail,
      password: cleanPass,
      label,
      auth: {
        type: authType,
        user: cleanEmail,
        pass: cleanPass
      }
    });

    // Pre-flight connection test against Outlook IMAP
    const client = this._createImapClient(resolved);
    const testResult = await client.verify(resolved);

    if (!testResult.success) {
      const err = new Error(testResult.error?.message || 'Failed to authenticate with Microsoft Outlook');
      err.code = testResult.error?.code || 'AUTH_FAILED';
      err.remediationAdvice = testResult.error?.remediationAdvice || 'Ensure your Outlook credentials are correct. For personal accounts with 2FA, create an App Password at https://account.live.com/proofs/manage/additional.';
      throw err;
    }

    // Save permanently to encrypted vault
    const accountToStore = {
      ...resolved,
      lastVerifiedAt: new Date().toISOString(),
      connected: true,
      inboxStatus: testResult.inboxStatus
    };

    const saved = await this.vault.saveAccount(accountToStore);
    this._mirrorAccountToStore(saved);
    return {
      account: {
        id: saved.id,
        provider: saved.provider,
        label: saved.label,
        email: saved.email,
        authType: resolved.auth?.type || authType,
        connected: true,
        lastVerifiedAt: saved.lastVerifiedAt,
        inboxStatus: testResult.inboxStatus
      },
      testResult
    };
  }

  /**
   * Connects a custom or university IMAP account with manual credentials.
   *
   * @param {object} config - Custom account input
   * @returns {Promise<{ account: object, testResult: object }>}
   */
  async addCustomAccount(config = {}) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      const err = new Error('Custom account configuration must be an object');
      err.code = 'VALIDATION_ERROR';
      throw err;
    }
    if (!config.email || typeof config.email !== 'string' || !config.email.trim()) {
      const err = new Error('Email address is required for custom accounts');
      err.code = 'VALIDATION_ERROR';
      throw err;
    }
    const resolved = resolveAccountConfig(config);

    const client = this._createImapClient(resolved);
    const testResult = await client.verify(resolved);

    if (!testResult.success) {
      const err = new Error(testResult.error?.message || 'Connection test failed');
      err.code = testResult.error?.code || 'CONNECTION_FAILED';
      err.remediationAdvice = testResult.error?.remediationAdvice || '';
      throw err;
    }

    const accountToStore = {
      ...resolved,
      lastVerifiedAt: new Date().toISOString(),
      connected: true,
      inboxStatus: testResult.inboxStatus
    };

    const saved = await this.vault.saveAccount(accountToStore);
    this._mirrorAccountToStore(saved);
    return {
      account: {
        id: saved.id,
        provider: saved.provider,
        label: saved.label,
        email: saved.email,
        authType: resolved.auth?.type || 'password',
        connected: true,
        lastVerifiedAt: saved.lastVerifiedAt,
        inboxStatus: testResult.inboxStatus
      },
      testResult
    };
  }

  /**
   * Handles the OAuth callback after user approves in browser popup.
   * Exchanges authorization code, fetches profile, and saves account permanently.
   *
   * @param {'gmail'|'outlook'} provider
   * @param {string} code - Authorization code from query params
   * @param {string} [customRedirectUri]
   * @returns {Promise<object>} Public account summary
   */
  async handleOAuthCallback(provider, code, customRedirectUri) {
    if (!code || typeof code !== 'string' || !code.trim()) {
      throw new Error('Authorization code is required');
    }

    // 1. Exchange code for access & refresh tokens
    const tokens = await this.oauth.exchangeCodeForTokens(provider, code.trim(), customRedirectUri);

    // 2. Fetch user profile
    const userInfo = await this.oauth.getUserInfo(provider, tokens.accessToken);
    if (!userInfo.email) {
      throw new Error(`Failed to retrieve verified email address from ${provider}`);
    }

    const normalizedEmail = userInfo.email.trim().toLowerCase();

    // 3. Resolve account configuration
    const preset = getPreset(provider);
    const defaultLabel = provider === 'gmail' ? 'Google Mail' : 'Microsoft Outlook';

    const accountConfig = {
      provider,
      label: userInfo.name ? `${defaultLabel} (${userInfo.name})` : defaultLabel,
      email: normalizedEmail,
      imap: {
        host: preset.imap.host,
        port: preset.imap.port,
        secure: preset.imap.secure,
        tls: { ...preset.imap.tls }
      },
      smtp: preset.smtp ? {
        host: preset.smtp.host,
        port: preset.smtp.port,
        secure: preset.smtp.secure
      } : undefined,
      auth: {
        type: 'oauth2',
        user: userInfo.email,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt,
        scope: tokens.scope
      },
      lastVerifiedAt: new Date().toISOString(),
      connected: true
    };

    // 4. Save to vault permanently
    const saved = await this.vault.saveAccount(accountConfig);
    this._mirrorAccountToStore(saved);

    return {
      id: saved.id,
      provider: saved.provider,
      label: saved.label,
      email: saved.email,
      authType: 'oauth2',
      connected: true,
      lastVerifiedAt: saved.lastVerifiedAt
    };
  }

  /**
   * Retrieves decrypted IMAP configuration for an account (SyncEngine contract compatibility).
   * @param {string} id - Account ID
   * @returns {Promise<object>} Resolved AccountConfig
   */
  async getAccount(id) {
    try {
      return await this.getImapConfig(id);
    } catch {
      return null;
    }
  }

  /**
   * Retrieves all decrypted IMAP configurations for active accounts.
   * @returns {Promise<Array<object>>}
   */
  async getAccounts() {
    const publicList = await this.vault.getPublicList();
    const accounts = [];
    for (const acc of publicList) {
      try {
        const full = await this.getImapConfig(acc.id);
        if (full) accounts.push(full);
      } catch {}
    }
    return accounts;
  }

  /**
   * Retrieves decrypted IMAP configuration for an account, automatically refreshing
   * OAuth access tokens if needed.
   *
   * @param {string} id - Account ID
   * @returns {Promise<object>} Resolved AccountConfig
   */
  async getImapConfig(id) {
    const account = await this.vault.getById(id);
    if (!account) {
      throw new Error(`Account not found: ${id}`);
    }

    // Transparently refresh token if it's an OAuth account
    if (account.auth?.type === 'oauth2') {
      await this.oauth.ensureValidToken(account, this.vault);
    }

    return account;
  }

  /**
   * Tests connection for an existing account in the vault.
   *
   * @param {string} id - Account ID
   * @returns {Promise<object>} Diagnostic test result
   */
  async testAccount(id) {
    const config = await this.getImapConfig(id);
    const client = new ImapClient({ accountConfig: config });
    const result = await client.verify(config);

    if (result.success) {
      config.lastVerifiedAt = new Date().toISOString();
      config.inboxStatus = result.inboxStatus;
      await this.vault.saveAccount(config);
    }

    return result;
  }

  /**
   * Explicitly removes an account (user logs out).
   *
   * @param {string} id - Account ID
   * @returns {Promise<boolean>}
   */
  async logoutAccount(id) {
    if (this.store?.deleteAccount) {
      try {
        this.store.deleteAccount(id);
      } catch {}
    }
    return this.vault.removeAccount(id);
  }
}

export const defaultAccountManager = new AccountManager();
