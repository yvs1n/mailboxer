/**
 * Web Server Integration Test Suite (test/integration/web-server.test.js)
 *
 * Tests the native HTTP server, static asset serving, and REST API endpoints:
 * - Static file serving (index.html, style.css, app.js)
 * - /api/accounts listing
 * - /api/oauth/status check
 * - /api/oauth/credentials configuration
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { WebServer } from '../../src/server/web-server.js';
import { AccountManager } from '../../src/auth/account-manager.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { OAuthManager } from '../../src/auth/oauth.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { MockImapServer } from '../helpers/mock-socket.js';

describe('Web Server & Gateway Integration (src/server/web-server.js)', () => {
  let tempDir;
  let server;
  let baseUrl;

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-server-test-'));
    const vault = new CredentialVault({
      dataDir: tempDir,
      masterKey: crypto.randomBytes(32)
    });
    const oauth = new OAuthManager();
    const accountManager = new AccountManager({
      vault,
      oauth,
      imapClientFactory: (resolved) => {
        const mockServer = new MockImapServer({ scenario: 'happy_path', messageCount: 120, unseenCount: 6 });
        return new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        });
      }
    });

    // Use random high port for isolated test execution
    const randomPort = 10000 + Math.floor(Math.random() * 40000);
    server = new WebServer({
      port: randomPort,
      accountManager
    });

    baseUrl = await server.start();
  });

  after(async () => {
    if (server) {
      await server.stop();
    }
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('serves static HTML index with 200 OK and renders 3 direct generator links', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers.get('content-type').includes('text/html'));

    const html = await res.text();
    assert.ok(html.includes('Mailboxer'));
    assert.ok(html.includes('Apple Mail (iCloud)'));
    assert.ok(html.includes('Google Mail (Gmail)'));
    assert.ok(html.includes('Microsoft Outlook'));
    // 3 official 30-second generator links
    assert.ok(html.includes('https://appleid.apple.com/account/manage/section/passwords'));
    assert.ok(html.includes('https://myaccount.google.com/apppasswords'));
    assert.ok(html.includes('https://account.live.com/proofs/manage/additional'));
    assert.ok(html.includes('https://account.live.com'));
    assert.ok(html.includes('Connect with Google'));
    assert.ok(html.includes('Connect with Microsoft'));
  });

  it('serves static CSS stylesheet with 200 OK', async () => {
    const res = await fetch(`${baseUrl}/style.css`);
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers.get('content-type').includes('text/css'));

    const css = await res.text();
    assert.ok(css.includes('--bg-app'));
  });

  it('serves static JS application script with 200 OK', async () => {
    const res = await fetch(`${baseUrl}/app.js`);
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers.get('content-type').includes('javascript'));

    const js = await res.text();
    assert.ok(js.includes('loadAccounts'));
  });

  it('returns empty accounts list on clean initial setup', async () => {
    const res = await fetch(`${baseUrl}/api/accounts`);
    assert.strictEqual(res.status, 200);

    const data = await res.json();
    assert.ok(Array.isArray(data.accounts));
    assert.strictEqual(data.accounts.length, 0);

    // Verify secret isolation and account removal via DELETE /api/accounts/:id
    await server.accountManager.vault.saveAccount({
      id: 'test-purge-id',
      provider: 'apple',
      email: 'purge@icloud.com',
      auth: { type: 'app_password', pass: 'secret-pass-1234' }
    });

    const listRes = await fetch(`${baseUrl}/api/accounts`);
    const listData = await listRes.json();
    assert.strictEqual(listData.accounts.length, 1);
    assert.strictEqual(listData.accounts[0].email, 'purge@icloud.com');
    assert.strictEqual(listData.accounts[0].auth, undefined);

    const deleteRes = await fetch(`${baseUrl}/api/accounts/test-purge-id`, { method: 'DELETE' });
    assert.strictEqual(deleteRes.status, 200);
    const deleteData = await deleteRes.json();
    assert.strictEqual(deleteData.success, true);

    const afterPurge = await server.accountManager.vault.getById('test-purge-id');
    assert.strictEqual(afterPurge, null);

    const notFoundRes = await fetch(`${baseUrl}/api/accounts/test-purge-id`, { method: 'DELETE' });
    assert.strictEqual(notFoundRes.status, 404);
  });

  it('checks OAuth configuration status via /api/oauth/status', async () => {
    const res = await fetch(`${baseUrl}/api/oauth/status`);
    assert.strictEqual(res.status, 200);

    const data = await res.json();
    assert.strictEqual(typeof data.gmail, 'boolean');
    assert.strictEqual(typeof data.outlook, 'boolean');
  });

  it('updates OAuth credentials via /api/oauth/credentials', async () => {
    const res = await fetch(`${baseUrl}/api/oauth/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'gmail',
        clientId: 'custom-google-id.apps.googleusercontent.com',
        clientSecret: 'secret-123'
      })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);

    // Verify status endpoint reflects update
    const checkRes = await fetch(`${baseUrl}/api/oauth/status`);
    const statusData = await checkRes.json();
    assert.strictEqual(statusData.gmail, true);
  });

  it('generates OAuth authorization URL via /api/auth/:provider/url', async () => {
    // Gmail was configured in previous test
    const res = await fetch(`${baseUrl}/api/auth/gmail/url`);
    assert.strictEqual(res.status, 200);

    const data = await res.json();
    assert.ok(data.url);
    assert.ok(data.url.includes('accounts.google.com'));
    assert.ok(data.url.includes('access_type=offline'));
    assert.ok(data.state);

    // Outlook is not configured yet -> should return 400 with configured: false
    const unconfRes = await fetch(`${baseUrl}/api/auth/outlook/url`);
    assert.strictEqual(unconfRes.status, 400);
    const unconfData = await unconfRes.json();
    assert.strictEqual(unconfData.configured, false);
  });

  it('handles OAuth callback error safely without reflected XSS', async () => {
    const xssPayload = '<script>alert("xss")</script>';
    const callbackUrl = `${baseUrl}/api/auth/gmail/callback?error=access_denied&error_description=${encodeURIComponent(xssPayload)}`;

    const res = await fetch(callbackUrl);
    assert.strictEqual(res.status, 200);

    const html = await res.text();
    // Verify payload is safely HTML entity escaped
    assert.ok(html.includes('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'));
    // Verify raw unescaped script tag is NOT in HTML body
    assert.ok(!html.includes('<p style="color:#94a3b8;font-size:14px;margin-top:8px;"><script>'));
    // Verify localStorage fallback is present for COOP resilience
    assert.ok(html.includes("localStorage.setItem('mailboxer_oauth_result'"));
  });

  it('validates Apple account password length before connection attempt', async () => {
    const res = await fetch(`${baseUrl}/api/accounts/apple`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'user@icloud.com',
        appPassword: 'too-short-pass' // only 12 chars
      })
    });

    assert.strictEqual(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('16 characters'));
    assert.strictEqual(data.code, 'INVALID_CREDENTIALS');
  });

  it('rejects start() cleanly when port is already in use without unhandled event', async () => {
    const conflictingServer = new WebServer({
      port: server.port,
      accountManager: server.accountManager
    });

    await assert.rejects(
      async () => {
        await conflictingServer.start();
      },
      (err) => {
        assert.strictEqual(err.code, 'EADDRINUSE');
        return true;
      }
    );
  });

  it('handles malformed JSON body gracefully returning HTTP 400 Bad Request', async () => {
    const res = await fetch(`${baseUrl}/api/accounts/apple`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"invalid": json syntax missing closing'
    });

    assert.strictEqual(res.status, 400);
    const data = await res.json();
    assert.strictEqual(data.code, 'INVALID_JSON');
    assert.ok(data.error.includes('Invalid JSON'));
  });

  it('rejects oversized payload with HTTP 413 Payload Too Large', async () => {
    // Generate > 1MB payload
    const largeString = 'x'.repeat(1024 * 1024 + 100);
    const res = await fetch(`${baseUrl}/api/accounts/apple`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@icloud.com', appPassword: largeString })
    });

    assert.strictEqual(res.status, 413);
    const data = await res.json();
    assert.strictEqual(data.code, 'PAYLOAD_TOO_LARGE');
  });

  it('validates provider and clientId in /api/oauth/credentials', async () => {
    // Invalid provider
    const badProviderRes = await fetch(`${baseUrl}/api/oauth/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'unsupported_provider', clientId: '123' })
    });
    assert.strictEqual(badProviderRes.status, 400);
    const badProvData = await badProviderRes.json();
    assert.strictEqual(badProvData.code, 'INVALID_PROVIDER');

    // Missing clientId
    const missingIdRes = await fetch(`${baseUrl}/api/oauth/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', clientId: '' })
    });
    assert.strictEqual(missingIdRes.status, 400);
    const missingIdData = await missingIdRes.json();
    assert.strictEqual(missingIdData.code, 'MISSING_CLIENT_ID');
  });

  it('routes account endpoints correctly for IDs containing dots and email addresses', async () => {
    const specialId = 'user.name@sub.domain.edu';
    await server.accountManager.vault.saveAccount({
      id: specialId,
      provider: 'custom',
      email: specialId
    });

    // Delete with dots and @ symbol
    const deleteRes = await fetch(`${baseUrl}/api/accounts/${encodeURIComponent(specialId)}`, {
      method: 'DELETE'
    });
    assert.strictEqual(deleteRes.status, 200);
    const deleteData = await deleteRes.json();
    assert.strictEqual(deleteData.success, true);

    const lookup = await server.accountManager.vault.getById(specialId);
    assert.strictEqual(lookup, null);
  });

  it('enforces OAuth CSRF state parameter validation on callback', async () => {
    // 1. Generate auth URL to record state in server oauth manager
    const urlRes = await fetch(`${baseUrl}/api/auth/gmail/url`);
    const { state: validState } = await urlRes.json();
    assert.ok(validState);

    // 2. Callback with missing state when states are pending -> must fail CSRF validation
    const missingStateRes = await fetch(`${baseUrl}/api/auth/gmail/callback?code=mock-code`);
    assert.strictEqual(missingStateRes.status, 200);
    const missingStateHtml = await missingStateRes.text();
    assert.ok(missingStateHtml.includes('Authentication Failed'));
    assert.ok(missingStateHtml.includes('state'));

    // 3. Callback with forged state -> must fail
    const forgedStateRes = await fetch(`${baseUrl}/api/auth/gmail/callback?code=mock-code&state=forged-state-12345`);
    assert.strictEqual(forgedStateRes.status, 200);
    const forgedHtml = await forgedStateRes.text();
    assert.ok(forgedHtml.includes('Authentication Failed'));

    // 4. Clean up pending state
    server.accountManager.oauth.clearPendingStates();
  });

  it('prevents directory and path traversal outside PUBLIC_DIR', async () => {
    const traversalUrls = [
      `${baseUrl}/%2e%2e/package.json`,
      `${baseUrl}/..%2f.env`,
      `${baseUrl}/....//package.json`
    ];

    for (const url of traversalUrls) {
      const res = await fetch(url);
      const text = await res.text();
      // Must return 403 or 404, never 200
      assert.ok(res.status === 403 || res.status === 404);
      assert.ok(!text.includes('"name": "mailboxer"'));
      assert.ok(!text.includes('MAILBOXER_MASTER_KEY'));
    }
  });

  it('handles POST /api/auth/:provider/callback gracefully with standard errors on missing code or error query', async () => {
    // 1. Missing code returns HTTP 400 with code: MISSING_CODE
    const missingRes = await fetch(`${baseUrl}/api/auth/gmail/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.strictEqual(missingRes.status, 400);
    assert.strictEqual(missingRes.headers.get('content-type'), 'application/json; charset=utf-8');
    const missingData = await missingRes.json();
    assert.strictEqual(missingData.code, 'MISSING_CODE');
    assert.strictEqual(missingData.error, 'No authorization code received.');

    // 2. Error query parameter returns HTTP 400 with code: OAUTH_ERROR
    const errRes = await fetch(`${baseUrl}/api/auth/gmail/callback?error=access_denied&error_description=User%20declined%20consent`, {
      method: 'POST'
    });
    assert.strictEqual(errRes.status, 400);
    const errData = await errRes.json();
    assert.strictEqual(errData.code, 'OAUTH_ERROR');
    assert.strictEqual(errData.error, 'User declined consent');

    // 3. Form urlencoded body with error returns standard error
    const formRes = await fetch(`${baseUrl}/api/auth/outlook/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'error=invalid_grant&error_description=Code+expired'
    });
    assert.strictEqual(formRes.status, 400);
    const formData = await formRes.json();
    assert.strictEqual(formData.code, 'OAUTH_ERROR');
    assert.strictEqual(formData.error, 'Code expired');
  });

  it('sets application/json; charset=utf-8 on all JSON API endpoints and handles CORS preflight', async () => {
    // CORS OPTIONS
    const optRes = await fetch(`${baseUrl}/api/accounts`, { method: 'OPTIONS' });
    assert.strictEqual(optRes.status, 204);
    assert.strictEqual(optRes.headers.get('access-control-allow-origin'), '*');

    // JSON GET
    const getRes = await fetch(`${baseUrl}/api/accounts`);
    assert.strictEqual(getRes.headers.get('content-type'), 'application/json; charset=utf-8');

    // JSON POST 400
    const badRes = await fetch(`${baseUrl}/api/oauth/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'invalid' })
    });
    assert.strictEqual(badRes.headers.get('content-type'), 'application/json; charset=utf-8');
  });

  it('supports GET /api/accounts/:id and returns 404 for non-existent accounts', async () => {
    // Save account
    const acc = await server.accountManager.vault.saveAccount({
      id: 'test-get-single',
      provider: 'gmail',
      email: 'single@gmail.com',
      auth: { type: 'oauth2', accessToken: 'secret-token-123' }
    });

    const getRes = await fetch(`${baseUrl}/api/accounts/test-get-single`);
    assert.strictEqual(getRes.status, 200);
    const getData = await getRes.json();
    assert.strictEqual(getData.account.id, 'test-get-single');
    assert.strictEqual(getData.account.email, 'single@gmail.com');
    // Secrets must NOT be returned
    assert.strictEqual(getData.account.auth, undefined);

    // Non-existent account returns 404
    const notFoundRes = await fetch(`${baseUrl}/api/accounts/does-not-exist-12345`);
    assert.strictEqual(notFoundRes.status, 404);
    const notFoundData = await notFoundRes.json();
    assert.strictEqual(notFoundData.code, 'ACCOUNT_NOT_FOUND');

    // Testing connection for non-existent account returns 404
    const testNotFoundRes = await fetch(`${baseUrl}/api/accounts/does-not-exist-12345/test`, { method: 'POST' });
    assert.strictEqual(testNotFoundRes.status, 404);
    const testNotFoundData = await testNotFoundRes.json();
    assert.strictEqual(testNotFoundData.code, 'ACCOUNT_NOT_FOUND');

    // Clean up
    await server.accountManager.vault.removeAccount('test-get-single');
  });

  it('validates Google account payload and connects via POST /api/accounts/gmail and /api/accounts/google', async () => {
    // 1. Missing fields
    const missingRes = await fetch(`${baseUrl}/api/accounts/gmail`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.strictEqual(missingRes.status, 400);
    const missingData = await missingRes.json();
    assert.strictEqual(missingData.code, 'VALIDATION_ERROR');

    // 2. Password not 16 characters
    const shortPassRes = await fetch(`${baseUrl}/api/accounts/gmail`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'user@gmail.com',
        appPassword: 'short-password'
      })
    });
    assert.strictEqual(shortPassRes.status, 400);
    const shortPassData = await shortPassRes.json();
    assert.strictEqual(shortPassData.code, 'INVALID_CREDENTIALS');
    assert.ok(shortPassData.remediationAdvice.includes('https://myaccount.google.com/apppasswords'));

    // 3. Invalid email format
    const badEmailRes = await fetch(`${baseUrl}/api/accounts/gmail`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'not-valid-email',
        appPassword: 'abcd efgh ijkl mnop'
      })
    });
    assert.strictEqual(badEmailRes.status, 400);
    const badEmailData = await badEmailRes.json();
    assert.strictEqual(badEmailData.code, 'INVALID_CREDENTIALS');

    // 4. Successful addition via POST /api/accounts/gmail
    const successRes = await fetch(`${baseUrl}/api/accounts/gmail`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'integration.user@gmail.com',
        appPassword: 'abcd-efgh-ijkl-mnop',
        label: 'My Integration Gmail'
      })
    });
    assert.strictEqual(successRes.status, 201);
    const successData = await successRes.json();
    assert.strictEqual(successData.account.provider, 'gmail');
    assert.strictEqual(successData.account.email, 'integration.user@gmail.com');
    assert.strictEqual(successData.account.authType, 'app_password');
    assert.strictEqual(successData.account.connected, true);
    assert.strictEqual(successData.testResult.success, true);
    // Secrets must NOT leak
    assert.strictEqual(successData.account.auth, undefined);
    assert.strictEqual(successData.account.password, undefined);

    // 5. Test alias /api/accounts/google
    const aliasRes = await fetch(`${baseUrl}/api/accounts/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'alias.integration@gmail.com',
        appPassword: 'xxxx-yyyy-zzzz-wwww'
      })
    });
    assert.strictEqual(aliasRes.status, 201);
    const aliasData = await aliasRes.json();
    assert.strictEqual(aliasData.account.email, 'alias.integration@gmail.com');

    // Clean up
    await server.accountManager.vault.removeAccount(successData.account.id);
    await server.accountManager.vault.removeAccount(aliasData.account.id);
  });

  it('validates Microsoft Outlook payload and connects via POST /api/accounts/outlook', async () => {
    // 1. Missing fields
    const missingRes = await fetch(`${baseUrl}/api/accounts/outlook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.strictEqual(missingRes.status, 400);
    const missingData = await missingRes.json();
    assert.strictEqual(missingData.code, 'VALIDATION_ERROR');

    // 2. Invalid email format
    const badEmailRes = await fetch(`${baseUrl}/api/accounts/outlook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'not-valid-email',
        password: 'ValidPassword123!'
      })
    });
    assert.strictEqual(badEmailRes.status, 400);
    const badEmailData = await badEmailRes.json();
    assert.strictEqual(badEmailData.code, 'INVALID_CREDENTIALS');

    // 3. Successful addition via POST /api/accounts/outlook
    const successRes = await fetch(`${baseUrl}/api/accounts/outlook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'student@university.edu',
        password: 'SecureUniPassword99!',
        label: 'My University Outlook'
      })
    });
    assert.strictEqual(successRes.status, 201);
    const successData = await successRes.json();
    assert.strictEqual(successData.account.provider, 'outlook');
    assert.strictEqual(successData.account.email, 'student@university.edu');
    assert.strictEqual(successData.account.label, 'My University Outlook');
    assert.strictEqual(successData.account.connected, true);
    assert.strictEqual(successData.testResult.success, true);
    // Secrets must NOT leak
    assert.strictEqual(successData.account.auth, undefined);
    assert.strictEqual(successData.account.password, undefined);

    // Clean up
    await server.accountManager.vault.removeAccount(successData.account.id);
  });

  describe('Regression: Malformed & Non-Object JSON Body Handling (DoS Prevention)', () => {
    const endpoints = [
      '/api/accounts/apple',
      '/api/accounts/gmail',
      '/api/accounts/outlook',
      '/api/accounts/custom',
      '/api/oauth/credentials'
    ];

    const testBodies = [
      { label: 'literal null', body: 'null' },
      { label: 'empty string', body: '' },
      { label: 'array', body: '[]' },
      { label: 'number', body: '123' },
      { label: 'boolean', body: 'true' }
    ];

    for (const ep of endpoints) {
      for (const { label, body } of testBodies) {
        it(`${ep} rejects ${label} body with HTTP 400 VALIDATION_ERROR in under 100ms without hanging`, async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 1000);
          const start = Date.now();

          try {
            const res = await fetch(`${baseUrl}${ep}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body,
              signal: controller.signal
            });
            const elapsed = Date.now() - start;
            assert.strictEqual(res.status, 400);
            assert.ok(elapsed < 200, `Expected response in < 200ms, took ${elapsed}ms`);
            const data = await res.json();
            assert.strictEqual(data.code, 'VALIDATION_ERROR');
            assert.ok(data.error);
          } finally {
            clearTimeout(timer);
          }
        });
      }
    }
  });
});
