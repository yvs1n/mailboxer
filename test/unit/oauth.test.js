/**
 * OAuth Manager Unit Test Suite (test/unit/oauth.test.js)
 *
 * Tests:
 * - Google and Microsoft authorization URL generation
 * - Parameter and scope correctness (offline_access, prompt=consent)
 * - Auto-refresh threshold calculation (ensureValidToken)
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OAuthManager } from '../../src/auth/oauth.js';

describe('OAuth 2.0 Manager (src/auth/oauth.js)', () => {
  it('generates valid Google OAuth 2.0 authorization URL with offline access', () => {
    const oauth = new OAuthManager({
      googleClientId: 'google-client-123.apps.googleusercontent.com',
      redirectBase: 'http://localhost:3000'
    });

    const { url, state, redirectUri } = oauth.getAuthorizationUrl('gmail', 'test-state-abc');

    assert.strictEqual(redirectUri, 'http://localhost:3000/api/auth/gmail/callback');
    assert.strictEqual(state, 'test-state-abc');

    const parsed = new URL(url);
    assert.strictEqual(parsed.origin, 'https://accounts.google.com');
    assert.strictEqual(parsed.pathname, '/o/oauth2/v2/auth');
    assert.strictEqual(parsed.searchParams.get('client_id'), 'google-client-123.apps.googleusercontent.com');
    assert.strictEqual(parsed.searchParams.get('access_type'), 'offline');
    assert.strictEqual(parsed.searchParams.get('prompt'), 'consent');
    assert.ok(parsed.searchParams.get('scope').includes('https://mail.google.com/'));
  });

  it('generates valid Microsoft OAuth 2.0 authorization URL with offline_access scope', () => {
    const oauth = new OAuthManager({
      microsoftClientId: 'ms-app-id-789',
      redirectBase: 'http://localhost:3000'
    });

    const { url } = oauth.getAuthorizationUrl('outlook');
    const parsed = new URL(url);

    assert.strictEqual(parsed.origin, 'https://login.microsoftonline.com');
    assert.strictEqual(parsed.pathname, '/common/oauth2/v2.0/authorize');
    assert.strictEqual(parsed.searchParams.get('client_id'), 'ms-app-id-789');
    assert.ok(parsed.searchParams.get('scope').includes('offline_access'));
    assert.ok(parsed.searchParams.get('scope').includes('https://outlook.office.com/IMAP.AccessAsUser.All'));
  });

  it('returns false for isConfigured when client ID is missing', () => {
    const oauth = new OAuthManager({ googleClientId: '' });
    assert.strictEqual(oauth.isConfigured('gmail'), false);
    assert.strictEqual(oauth.isConfigured('outlook'), false);
  });

  it('preserves valid access tokens when not expired', async () => {
    const oauth = new OAuthManager();
    const account = {
      provider: 'gmail',
      auth: {
        type: 'oauth2',
        accessToken: 'fresh-token',
        refreshToken: 'refresh-token',
        expiresAt: Date.now() + 3600 * 1000 // 1 hour in future
      }
    };

    const validated = await oauth.ensureValidToken(account);
    assert.strictEqual(validated.auth.accessToken, 'fresh-token');

    // Also verify transparent refresh when token is expired
    oauth.refreshAccessToken = async (provider, token) => ({
      accessToken: 'auto-refreshed-token',
      refreshToken: token,
      expiresIn: 3600,
      expiresAt: Date.now() + 3600000
    });

    let savedInVault = false;
    const mockVault = {
      saveAccount: async (acc) => {
        savedInVault = true;
        return acc;
      }
    };

    const expiredAccount = {
      provider: 'gmail',
      auth: {
        type: 'oauth2',
        accessToken: 'expired-token',
        refreshToken: 'refresh-token-xyz',
        expiresAt: Date.now() - 10000
      }
    };

    const refreshed = await oauth.ensureValidToken(expiredAccount, mockVault);
    assert.strictEqual(refreshed.auth.accessToken, 'auto-refreshed-token');
    assert.strictEqual(savedInVault, true);
  });

  it('de-duplicates concurrent in-flight token refresh calls for the same account', async () => {
    const oauth = new OAuthManager();
    let refreshCount = 0;

    oauth.refreshAccessToken = async (provider, token) => {
      refreshCount++;
      // Simulate network latency
      await new Promise((r) => setTimeout(r, 20));
      return {
        accessToken: `refreshed-token-${refreshCount}`,
        refreshToken: token,
        expiresIn: 3600,
        expiresAt: Date.now() + 3600000
      };
    };

    const account = {
      id: 'acc-concurrent-oauth',
      provider: 'outlook',
      auth: {
        type: 'oauth2',
        accessToken: 'expired-token',
        refreshToken: 'shared-refresh-token',
        expiresAt: Date.now() - 50000
      }
    };

    // Dispatch 3 concurrent ensureValidToken calls
    const [res1, res2, res3] = await Promise.all([
      oauth.ensureValidToken(account),
      oauth.ensureValidToken(account),
      oauth.ensureValidToken(account)
    ]);

    assert.strictEqual(refreshCount, 1, 'refreshAccessToken must only be called once for concurrent requests');
    assert.strictEqual(res1.auth.accessToken, 'refreshed-token-1');
    assert.strictEqual(res2.auth.accessToken, 'refreshed-token-1');
    assert.strictEqual(res3.auth.accessToken, 'refreshed-token-1');
  });

  it('throws descriptive error if refresh token is missing when attempting token refresh', async () => {
    const oauth = new OAuthManager();
    const accountWithoutRefresh = {
      id: 'acc-no-refresh',
      provider: 'gmail',
      email: 'norefresh@gmail.com',
      auth: {
        type: 'oauth2',
        accessToken: 'expired-token',
        refreshToken: '',
        expiresAt: Date.now() - 10000
      }
    };

    await assert.rejects(
      () => oauth.ensureValidToken(accountWithoutRefresh),
      /no refresh token available/
    );
  });

  it('registers, validates, and consumes OAuth CSRF state parameter strictly once', () => {
    const oauth = new OAuthManager({
      googleClientId: 'test-google-id',
      microsoftClientId: 'test-ms-id'
    });

    const { state: state1 } = oauth.getAuthorizationUrl('gmail');
    assert.ok(state1);
    assert.strictEqual(oauth.hasPendingStates(), true);

    // Valid state for gmail
    const validCheck = oauth.validateAndConsumeState(state1, 'gmail');
    assert.strictEqual(validCheck.valid, true);

    // State cannot be re-used (single-use token)
    const reuseCheck = oauth.validateAndConsumeState(state1, 'gmail');
    assert.strictEqual(reuseCheck.valid, false);
    assert.ok(reuseCheck.error.includes('Invalid or expired'));

    // Missing state
    const missingCheck = oauth.validateAndConsumeState('', 'gmail');
    assert.strictEqual(missingCheck.valid, false);

    // Unknown random state
    const unknownCheck = oauth.validateAndConsumeState('completely-fake-state', 'gmail');
    assert.strictEqual(unknownCheck.valid, false);

    // Provider mismatch: state generated for outlook validated against gmail
    const { state: stateOutlook } = oauth.getAuthorizationUrl('outlook');
    const mismatchCheck = oauth.validateAndConsumeState(stateOutlook, 'gmail');
    assert.strictEqual(mismatchCheck.valid, false);
    assert.ok(mismatchCheck.error.includes('mismatch'));

    // Expired state eviction
    const { state: expiredState } = oauth.getAuthorizationUrl('gmail');
    oauth._pendingStates.get(expiredState).expiresAt = Date.now() - 1000;
    const expiredCheck = oauth.validateAndConsumeState(expiredState, 'gmail');
    assert.strictEqual(expiredCheck.valid, false);
  });
});
