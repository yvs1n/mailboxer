/**
 * AuthGuard unit tests (src/server/auth.js)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { AuthGuard, isCrossSiteRequest, SESSION_COOKIE } from '../../src/server/auth.js';

const secret = crypto.randomBytes(32);

function fakeReq({ cookie, authorization, ip = '1.2.3.4', headers = {}, method = 'GET' } = {}) {
  return {
    method,
    headers: { ...(cookie ? { cookie } : {}), ...(authorization ? { authorization } : {}), ...headers },
    socket: { remoteAddress: ip }
  };
}

function cookieValue(setCookie) {
  return setCookie.split(';')[0];
}

describe('AuthGuard (src/server/auth.js)', () => {
  it('is disabled without a password outside production, and locked in production', () => {
    const dev = new AuthGuard({ password: '', production: false, secret });
    assert.equal(dev.mode, 'disabled');
    assert.equal(dev.isAuthenticated(fakeReq()), true);

    const prod = new AuthGuard({ password: '', production: true, secret });
    assert.equal(prod.mode, 'locked');
    assert.equal(prod.isAuthenticated(fakeReq()), false);
    assert.equal(prod.login(fakeReq(), 'anything').status, 503);
  });

  it('issues a session cookie on the right password and accepts it', () => {
    const guard = new AuthGuard({ password: 'hunter2', secret });
    assert.equal(guard.isAuthenticated(fakeReq()), false);

    const result = guard.login(fakeReq(), 'hunter2');
    assert.equal(result.ok, true);
    assert.match(result.cookie, new RegExp(`^${SESSION_COOKIE}=`));
    assert.match(result.cookie, /HttpOnly/);
    assert.match(result.cookie, /SameSite=Lax/);

    assert.equal(guard.isAuthenticated(fakeReq({ cookie: cookieValue(result.cookie) })), true);
  });

  it('rejects wrong passwords, tampered tokens and expired tokens', () => {
    let now = 1_000_000;
    const guard = new AuthGuard({ password: 'hunter2', secret, sessionTtlMs: 1000, now: () => now });

    assert.equal(guard.login(fakeReq(), 'wrong').status, 401);
    assert.equal(guard.login(fakeReq(), undefined).status, 401);

    const token = guard.createSessionToken();
    assert.equal(guard.verifySessionToken(token), true);
    const [v, exp, sig] = token.split('.');
    assert.equal(guard.verifySessionToken(`${v}.${Number(exp) + 99999}.${sig}`), false);
    assert.equal(guard.verifySessionToken(`${v}.${exp}.${sig.slice(0, -2)}xx`), false);
    assert.equal(guard.verifySessionToken('garbage'), false);

    now += 2000;
    assert.equal(guard.verifySessionToken(token), false);
  });

  it('invalidates existing sessions when the password changes', () => {
    const before = new AuthGuard({ password: 'old-pass', secret });
    const token = before.createSessionToken();
    const after = new AuthGuard({ password: 'new-pass', secret });
    assert.equal(after.verifySessionToken(token), false);
  });

  it('accepts the bearer API token only when configured', () => {
    const guard = new AuthGuard({ password: 'hunter2', apiToken: 'tok_123', secret });
    assert.equal(guard.isAuthenticated(fakeReq({ authorization: 'Bearer tok_123' })), true);
    assert.equal(guard.isAuthenticated(fakeReq({ authorization: 'Bearer nope' })), false);

    const noToken = new AuthGuard({ password: 'hunter2', apiToken: '', secret });
    assert.equal(noToken.isAuthenticated(fakeReq({ authorization: 'Bearer ' })), false);
  });

  it('rate limits repeated failures per client, then resets after the window', () => {
    let now = 0;
    const guard = new AuthGuard({ password: 'hunter2', secret, now: () => now });
    for (let i = 0; i < 10; i++) {
      assert.equal(guard.login(fakeReq({ ip: '9.9.9.9' }), 'bad').status, 401);
    }
    const blocked = guard.login(fakeReq({ ip: '9.9.9.9' }), 'hunter2');
    assert.equal(blocked.status, 429);
    assert.ok(blocked.retryAfter > 0);

    // A different client is not blocked.
    assert.equal(guard.login(fakeReq({ ip: '8.8.8.8' }), 'hunter2').ok, true);

    now += 16 * 60 * 1000;
    assert.equal(guard.login(fakeReq({ ip: '9.9.9.9' }), 'hunter2').ok, true);
  });

  it('only reads X-Forwarded-For when trustProxy is on', () => {
    const req = fakeReq({ ip: '127.0.0.1', headers: { 'x-forwarded-for': '5.6.7.8, 10.0.0.1' } });
    assert.equal(new AuthGuard({ password: 'x', secret, trustProxy: false }).clientKey(req), '127.0.0.1');
    assert.equal(new AuthGuard({ password: 'x', secret, trustProxy: true }).clientKey(req), '5.6.7.8');
  });

  it('marks cookies Secure in production or behind an HTTPS proxy', () => {
    const prod = new AuthGuard({ password: 'x', secret, production: true });
    assert.match(prod.login(fakeReq(), 'x').cookie, /Secure/);

    const dev = new AuthGuard({ password: 'x', secret, production: false });
    assert.doesNotMatch(dev.login(fakeReq(), 'x').cookie, /Secure/);

    const proxied = new AuthGuard({ password: 'x', secret, production: false, trustProxy: true });
    assert.match(proxied.login(fakeReq({ headers: { 'x-forwarded-proto': 'https' } }), 'x').cookie, /Secure/);
  });

  it('persists the session secret in dataDir so sessions survive restarts', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-auth-'));
    try {
      const a = new AuthGuard({ password: 'x', dataDir: dir });
      const token = a.createSessionToken();
      const b = new AuthGuard({ password: 'x', dataDir: dir });
      assert.equal(b.verifySessionToken(token), true);
      const stat = await fs.stat(path.join(dir, '.session-secret'));
      assert.ok(stat.size >= 32);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('isCrossSiteRequest', () => {
  const host = 'mail.example.com';
  it('allows reads, same-origin writes, and requests without Origin', () => {
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'GET', headers: { host, origin: 'https://evil.test' } })), false);
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'POST', headers: { host, origin: `https://${host}` } })), false);
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'POST', headers: { host } })), false);
  });

  it('blocks writes from other origins and null origins', () => {
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'POST', headers: { host, origin: 'https://evil.test' } })), true);
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'DELETE', headers: { host, origin: 'null' } })), true);
    assert.equal(isCrossSiteRequest(fakeReq({ method: 'POST', headers: { host, origin: 'not a url' } })), true);
  });
});
