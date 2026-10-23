/**
 * Web server authentication integration tests.
 *
 * Starts a real WebServer with a password set and checks that the API,
 * /health and CORS behave as locked down.
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
import { AuthGuard } from '../../src/server/auth.js';

async function startServer(tempDir, authOptions) {
  const vault = new CredentialVault({ dataDir: tempDir, masterKey: crypto.randomBytes(32) });
  const accountManager = new AccountManager({ vault, oauth: new OAuthManager() });
  const server = new WebServer({
    port: 0,
    host: '127.0.0.1',
    accountManager,
    auth: new AuthGuard({ secret: crypto.randomBytes(32), ...authOptions })
  });
  const baseUrl = await server.start();
  return { server, baseUrl };
}

describe('Web server authentication (password set)', () => {
  let tempDir;
  let server;
  let baseUrl;

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-auth-server-'));
    ({ server, baseUrl } = await startServer(tempDir, { password: 'correct horse', apiToken: 'tok_abc', production: false }));
  });

  after(async () => {
    await server?.stop();
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it('rejects API calls without a session', async () => {
    for (const [method, p] of [
      ['GET', '/api/accounts'],
      ['GET', '/api/messages'],
      ['GET', '/api/mailbox/summary'],
      ['POST', '/api/sync'],
      ['DELETE', '/api/accounts/x'],
      ['GET', '/api/auth/gmail/callback?code=abc']
    ]) {
      const res = await fetch(`${baseUrl}${p}`, { method });
      assert.equal(res.status, 401, `${method} ${p} should need login`);
      const body = await res.json();
      assert.equal(body.code, 'UNAUTHORIZED');
    }
  });

  it('rejects writes to OAuth credentials without a session', async () => {
    const res = await fetch(`${baseUrl}/api/oauth/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', clientId: 'attacker' })
    });
    assert.equal(res.status, 401);
  });

  it('still serves the static app shell and login page', async () => {
    assert.equal((await fetch(`${baseUrl}/`)).status, 200);
    assert.equal((await fetch(`${baseUrl}/login.html`)).status, 200);
  });

  it('reports session state publicly', async () => {
    const res = await fetch(`${baseUrl}/api/auth/session`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { authenticated: false, authRequired: true, configured: true });
  });

  it('returns only a minimal /health without login', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(Object.keys(body).sort(), ['status', 'timestamp']);
  });

  it('sends no CORS allow headers', async () => {
    const res = await fetch(`${baseUrl}/api/auth/session`, { headers: { Origin: 'https://evil.test' } });
    assert.equal(res.headers.get('access-control-allow-origin'), null);
    const pre = await fetch(`${baseUrl}/api/accounts`, { method: 'OPTIONS', headers: { Origin: 'https://evil.test' } });
    assert.equal(pre.headers.get('access-control-allow-origin'), null);
  });

  it('rejects a wrong password', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'nope' })
    });
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('set-cookie'), null);
  });

  it('logs in, uses the session, and logs out', async () => {
    const login = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'correct horse' })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];

    const accounts = await fetch(`${baseUrl}/api/accounts`, { headers: { cookie } });
    assert.equal(accounts.status, 200);

    const health = await (await fetch(`${baseUrl}/health`, { headers: { cookie } })).json();
    assert.ok(health.storage, 'full health details when signed in');

    const logout = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: { cookie } });
    assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  });

  it('accepts the bearer API token', async () => {
    const res = await fetch(`${baseUrl}/api/accounts`, { headers: { Authorization: 'Bearer tok_abc' } });
    assert.equal(res.status, 200);
  });

  it('blocks cross-site writes even with a valid session', async () => {
    const res = await fetch(`${baseUrl}/api/sync`, {
      method: 'POST',
      headers: { Authorization: 'Bearer tok_abc', Origin: 'https://evil.test' }
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).code, 'CROSS_SITE_FORBIDDEN');
  });
});

describe('Web server authentication (production, no password)', () => {
  let tempDir;
  let server;
  let baseUrl;

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-auth-locked-'));
    ({ server, baseUrl } = await startServer(tempDir, { password: '', production: true }));
  });

  after(async () => {
    await server?.stop();
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it('locks the API instead of running open', async () => {
    const res = await fetch(`${baseUrl}/api/accounts`);
    assert.equal(res.status, 503);
    assert.equal((await res.json()).code, 'AUTH_NOT_CONFIGURED');
  });

  it('keeps /health up for the container health check', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
  });
});
