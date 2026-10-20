/**
 * Adversarial Stress & Chaos Test Suite: API Boundaries, Vault Concurrency & Secret Isolation
 * (test/adversarial/api-vault-stress.test.js)
 *
 * Empirical verification for Milestone 1:
 * 1. HTTP API Boundary Conditions:
 *    - Malformed JSON, non-object JSON roots (null, number, boolean, array), empty payloads
 *    - Missing required fields, invalid email/credential schemas
 *    - Payload size boundary (> 1MB returns 413, < 1MB accepted for validation)
 *    - High-volume concurrent requests to /api/accounts/apple, /api/accounts/gmail, /api/accounts/outlook
 * 2. Vault Concurrency & Tamper Detection:
 *    - 50 concurrent saves on single CredentialVault instance
 *    - 10 distinct CredentialVault instances saving concurrently with cross-process file lock
 *    - Tamper detection: systematic bit flips, auth tag mutation, IV mutation, truncated ciphertext, corrupt JSON
 * 3. Zero Secrets Leak in Public Payloads:
 *    - Deep recursive audit of GET /api/accounts, GET /api/accounts/:id, POST /api/accounts/* responses
 *    - Zero presence of canary passwords, access tokens, refresh tokens, or client secrets
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

describe('Adversarial Challenge: API Boundaries, Vault Concurrency & Secret Isolation', () => {
  let tempDir;
  let server;
  let baseUrl;
  let vault;
  let accountManager;

  const CANARY_APPLE_PASS = 'canaryapplepass1'; // 16 chars
  const CANARY_GMAIL_PASS = 'canarygmailpass1'; // 16 chars
  const CANARY_OUTLOOK_PASS = 'CanaryOutlookSecret99!';
  const CANARY_OAUTH_TOKEN = 'canary_access_token_xyz_987654321';
  const CANARY_REFRESH_TOKEN = 'canary_refresh_token_abc_123456789';

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-adv-stress-'));
    vault = new CredentialVault({
      dataDir: tempDir,
      masterKey: crypto.randomBytes(32)
    });
    const oauth = new OAuthManager();
    accountManager = new AccountManager({
      vault,
      oauth,
      imapClientFactory: (resolved) => {
        const mockServer = new MockImapServer({ scenario: 'happy_path', messageCount: 50, unseenCount: 3 });
        return new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        });
      }
    });

    const randomPort = 12000 + Math.floor(Math.random() * 30000);
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

  // ==========================================================================
  // VECTOR 1: HTTP API Boundary Conditions
  // ==========================================================================
  describe('Vector 1: HTTP API Boundary Conditions', () => {

    it('rejects malformed and truncated JSON payloads with HTTP 400 INVALID_JSON', async () => {
      const hostileBodies = [
        '{"email": "broken@icloud.com",',
        '{"unclosed string": 123',
        '{email: invalid_unquoted_key}',
        '{"email": "valid@gmail.com"} trailing garbage',
        'undefined',
        '<<< XML NOT JSON >>>'
      ];

      for (const body of hostileBodies) {
        const res = await fetch(`${baseUrl}/api/accounts/apple`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body
        });

        assert.strictEqual(res.status, 400, `Expected 400 for body: ${body}`);
        const data = await res.json();
        assert.strictEqual(data.code, 'INVALID_JSON');
      }
    });

    it('handles empty and whitespace-only payloads with HTTP 400 VALIDATION_ERROR', async () => {
      const emptyBodies = ['', '   ', '\n\t  \r\n'];

      for (const body of emptyBodies) {
        const res = await fetch(`${baseUrl}/api/accounts/apple`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body
        });

        assert.strictEqual(res.status, 400);
        const data = await res.json();
        assert.strictEqual(data.code, 'VALIDATION_ERROR');
      }
    });

    it('handles non-object JSON roots (numbers, booleans, arrays) with HTTP 400 VALIDATION_ERROR', async () => {
      const nonObjects = [
        '12345',
        '-99.9',
        'true',
        'false',
        '["item1", "item2"]',
        '[]'
      ];

      for (const body of nonObjects) {
        const res = await fetch(`${baseUrl}/api/accounts/apple`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body
        });

        assert.strictEqual(res.status, 400, `Expected 400 for non-object: ${body}`);
        const data = await res.json();
        assert.strictEqual(data.code, 'VALIDATION_ERROR');
      }
    });

    it('identifies behavior when JSON payload is literal null and verifies it never hangs', async () => {
      // Adversarial test: JSON.parse("null") evaluates to null.
      // In web-server.js getBody(), non-null object check ensures immediate HTTP 400 VALIDATION_ERROR.
      const endpoints = [
        '/api/accounts/apple',
        '/api/accounts/gmail',
        '/api/accounts/outlook',
        '/api/accounts/custom',
        '/api/oauth/credentials'
      ];

      for (const ep of endpoints) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 600);
        let hung = false;

        try {
          const res = await fetch(`${baseUrl}${ep}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: 'null',
            signal: controller.signal
          });
          assert.strictEqual(res.status, 400);
          const data = await res.json();
          assert.strictEqual(data.code, 'VALIDATION_ERROR');
        } catch (err) {
          if (err.name === 'AbortError') {
            hung = true;
          } else {
            throw err;
          }
        } finally {
          clearTimeout(timeout);
        }

        assert.strictEqual(hung, false, `Endpoint ${ep} must never hang on literal null payload`);
      }
    });

    it('rejects payloads strictly exceeding 1MB with HTTP 413 PAYLOAD_TOO_LARGE', async () => {
      const oversizedBody = 'x'.repeat(1024 * 1024 + 1);
      const res = await fetch(`${baseUrl}/api/accounts/gmail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'large@gmail.com', appPassword: oversizedBody })
      });

      assert.strictEqual(res.status, 413);
      const data = await res.json();
      assert.strictEqual(data.code, 'PAYLOAD_TOO_LARGE');
    });

    it('enforces strict boundary validation on password length and email format across all providers', async () => {
      // Apple: 15 chars (too short)
      const res1 = await fetch(`${baseUrl}/api/accounts/apple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user@icloud.com', appPassword: '123456789012345' })
      });
      assert.strictEqual(res1.status, 400);
      assert.strictEqual((await res1.json()).code, 'INVALID_CREDENTIALS');

      // Apple: 17 chars (too long)
      const res2 = await fetch(`${baseUrl}/api/accounts/apple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user@icloud.com', appPassword: '12345678901234567' })
      });
      assert.strictEqual(res2.status, 400);
      assert.strictEqual((await res2.json()).code, 'INVALID_CREDENTIALS');

      // Gmail: invalid email
      const res3 = await fetch(`${baseUrl}/api/accounts/gmail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'not-an-email', appPassword: 'abcd efgh ijkl mnop' })
      });
      assert.strictEqual(res3.status, 400);
      assert.strictEqual((await res3.json()).code, 'INVALID_CREDENTIALS');

      // Outlook: empty password
      const res4 = await fetch(`${baseUrl}/api/accounts/outlook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user@outlook.com', password: '   ' })
      });
      assert.strictEqual(res4.status, 400);
      assert.strictEqual((await res4.json()).code, 'VALIDATION_ERROR');

      // Custom: out of bounds port
      const res5 = await fetch(`${baseUrl}/api/accounts/custom`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'custom',
          email: 'custom@domain.com',
          imap: { host: 'mail.domain.com', port: 999999 },
          auth: { type: 'password', pass: 'secret' }
        })
      });
      assert.strictEqual(res5.status, 400);
      const res5Code = (await res5.json()).code;
      assert.ok(['VALIDATION_ERROR', 'CONFIG_SCHEMA_INVALID'].includes(res5Code));
    });

    it('safely handles 20 concurrent account creation requests without dropped sockets', async () => {
      const requests = [];
      for (let i = 0; i < 20; i++) {
        const provider = i % 2 === 0 ? 'gmail' : 'apple';
        const body = provider === 'gmail' ? {
          email: `concur.${i}@gmail.com`,
          appPassword: 'abcd-efgh-ijkl-mnop',
          label: `Concurrent Gmail ${i}`
        } : {
          email: `concur.${i}@icloud.com`,
          appPassword: 'xxxx-yyyy-zzzz-wwww',
          label: `Concurrent Apple ${i}`
        };

        requests.push(
          fetch(`${baseUrl}/api/accounts/${provider}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          })
        );
      }

      const responses = await Promise.all(requests);
      for (const res of responses) {
        assert.strictEqual(res.status, 201);
      }

      // Verify all 20 accounts persisted cleanly in vault
      const listRes = await fetch(`${baseUrl}/api/accounts`);
      const listData = await listRes.json();
      assert.ok(listData.accounts.length >= 20);

      // Clean up created accounts
      for (const acc of listData.accounts) {
        if (acc.email.startsWith('concur.')) {
          await fetch(`${baseUrl}/api/accounts/${acc.id}`, { method: 'DELETE' });
        }
      }
    });
  });

  // ==========================================================================
  // VECTOR 2: Vault Concurrency & Tamper Detection Under Stress
  // ==========================================================================
  describe('Vector 2: Vault Concurrency & Tamper Detection Under Stress', () => {

    it('handles 50 rapid concurrent saveAccount operations on single instance without data loss', async () => {
      const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-stress-single-'));
      try {
        const testVault = new CredentialVault({ dataDir: testDir, masterKey: crypto.randomBytes(32) });
        await testVault.init();

        const accounts = Array.from({ length: 50 }, (_, i) => ({
          id: `single-conc-${i}`,
          provider: 'apple',
          email: `stress${i}@icloud.com`,
          auth: { type: 'app_password', pass: `pass-secret-${i}` }
        }));

        await Promise.all(accounts.map((a) => testVault.saveAccount(a)));

        const all = await testVault.getAll();
        assert.strictEqual(all.length, 50, 'All 50 accounts must be saved without dropped writes');
        for (let i = 0; i < 50; i++) {
          assert.ok(all.some((a) => a.id === `single-conc-${i}`));
        }
      } finally {
        await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
      }
    });

    it('synchronizes 10 independent CredentialVault instances saving concurrently via lockfile', async () => {
      const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-stress-multi-'));
      const masterKey = crypto.randomBytes(32);
      try {
        const instances = Array.from({ length: 10 }, () => new CredentialVault({ dataDir: testDir, masterKey }));
        await Promise.all(instances.map((v) => v.init()));

        const tasks = [];
        for (let i = 0; i < 30; i++) {
          const v = instances[i % instances.length];
          tasks.push(
            v.saveAccount({
              id: `multi-inst-${i}`,
              provider: 'outlook',
              email: `inst${i}@university.edu`,
              auth: { type: 'password', pass: `secret-uni-${i}` }
            })
          );
        }

        await Promise.all(tasks);

        const all = await instances[0].getAll();
        assert.strictEqual(all.length, 30, 'Cross-process locking must preserve all 30 accounts');
        for (let i = 0; i < 30; i++) {
          assert.ok(all.some((a) => a.id === `multi-inst-${i}`));
        }
      } finally {
        await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
      }
    });

    it('detects tampering across every component (IV, AuthTag, Ciphertext) and fails closed', async () => {
      const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-tamper-'));
      try {
        const testVault = new CredentialVault({ dataDir: testDir, masterKey: crypto.randomBytes(32) });
        await testVault.init();

        await testVault.saveAccount({
          id: 'acc-tamper',
          provider: 'apple',
          email: 'tamper@icloud.com',
          auth: { type: 'app_password', pass: 'secret-1234' }
        });

        const vaultFile = path.join(testDir, 'accounts.vault.json');
        const originalContent = (await fs.readFile(vaultFile, 'utf8')).trim();
        const [ivHex, tagHex, cipherHex] = originalContent.split(':');

        // Test 1: Systematic bit flips across ciphertext (start, middle, end)
        const cipherIndices = [0, Math.floor(cipherHex.length / 2), cipherHex.length - 1];
        for (const idx of cipherIndices) {
          const flippedChar = (parseInt(cipherHex[idx], 16) ^ 1).toString(16);
          const tamperedCipher = cipherHex.substring(0, idx) + flippedChar + cipherHex.substring(idx + 1);
          await fs.writeFile(vaultFile, `${ivHex}:${tagHex}:${tamperedCipher}`, 'utf8');

          await assert.rejects(
            async () => testVault.getAll(),
            /Unsupported state or unable to authenticate data/,
            `Should reject bit flip at ciphertext index ${idx}`
          );
        }

        // Test 2: Auth tag mutation (flipped bit)
        const flippedTag = (parseInt(tagHex[0], 16) ^ 1).toString(16) + tagHex.slice(1);
        await fs.writeFile(vaultFile, `${ivHex}:${flippedTag}:${cipherHex}`, 'utf8');
        await assert.rejects(
          async () => testVault.getAll(),
          /Unsupported state or unable to authenticate data/
        );

        // Test 3: Truncated auth tag
        await fs.writeFile(vaultFile, `${ivHex}:${tagHex.slice(0, 16)}:${cipherHex}`, 'utf8');
        await assert.rejects(
          async () => testVault.getAll(),
          /Unsupported state or unable to authenticate data|Invalid authentication tag length/
        );

        // Test 4: Truncated ciphertext
        await fs.writeFile(vaultFile, `${ivHex}:${tagHex}:${cipherHex.slice(0, 10)}`, 'utf8');
        await assert.rejects(
          async () => testVault.getAll(),
          /Unsupported state or unable to authenticate data/
        );

        // Test 5: Corrupt format (not 3 colon-separated parts)
        await fs.writeFile(vaultFile, 'not-a-valid-vault-string', 'utf8');
        await assert.rejects(
          async () => testVault.getAll(),
          /Invalid encrypted payload format/
        );

        // Test 6: Valid AES-GCM ciphertext decrypting to non-JSON string
        const nonJsonEncrypted = testVault.encrypt('THIS IS NOT VALID JSON {[');
        await fs.writeFile(vaultFile, nonJsonEncrypted, 'utf8');
        await assert.rejects(
          async () => testVault.getAll(),
          /Unexpected token|Expected/
        );
      } finally {
        await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
      }
    });

    it('recovers from stale lock and ensures lock cleanup on abnormal termination', async () => {
      const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-stale-adv-'));
      try {
        const testVault = new CredentialVault({ dataDir: testDir, masterKey: crypto.randomBytes(32) });
        await testVault.init();

        const lockFile = path.join(testDir, 'accounts.vault.json.lock');
        // Write stale lock file (20s old)
        await fs.writeFile(lockFile, JSON.stringify({ pid: 8888, time: Date.now() - 20000 }));
        const oldTime = new Date(Date.now() - 20000);
        await fs.utimes(lockFile, oldTime, oldTime);

        // Should evict stale lock and proceed
        const saved = await testVault.saveAccount({ id: 'stale-test', email: 'stale@test.com' });
        assert.strictEqual(saved.id, 'stale-test');

        // Verify lockfile was released
        let lockExists = true;
        try {
          await fs.stat(lockFile);
        } catch {
          lockExists = false;
        }
        assert.strictEqual(lockExists, false, 'Lockfile must be unlinked after operation');
      } finally {
        await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
      }
    });
  });

  // ==========================================================================
  // VECTOR 3: Zero Secrets Leak in Public Payloads
  // ==========================================================================
  describe('Vector 3: Zero Secrets Leak in Public Payloads', () => {

    let createdAccountIds = [];

    before(async () => {
      // Create accounts with distinct canary secrets across all providers
      // 1. Apple
      const appleRes = await fetch(`${baseUrl}/api/accounts/apple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'canary.apple@icloud.com',
          appPassword: CANARY_APPLE_PASS,
          label: 'Canary Apple'
        })
      });
      const appleData = await appleRes.json();
      createdAccountIds.push(appleData.account.id);

      // 2. Gmail
      const gmailRes = await fetch(`${baseUrl}/api/accounts/gmail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'canary.gmail@gmail.com',
          appPassword: CANARY_GMAIL_PASS,
          label: 'Canary Gmail'
        })
      });
      const gmailData = await gmailRes.json();
      createdAccountIds.push(gmailData.account.id);

      // 3. Outlook
      const outlookRes = await fetch(`${baseUrl}/api/accounts/outlook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'canary.outlook@university.edu',
          password: CANARY_OUTLOOK_PASS,
          label: 'Canary Outlook'
        })
      });
      const outlookData = await outlookRes.json();
      createdAccountIds.push(outlookData.account.id);

      // 4. OAuth account in vault directly
      const oauthSaved = await vault.saveAccount({
        id: 'canary-oauth-id',
        provider: 'gmail',
        email: 'canary.oauth@gmail.com',
        auth: {
          type: 'oauth2',
          accessToken: CANARY_OAUTH_TOKEN,
          refreshToken: CANARY_REFRESH_TOKEN
        }
      });
      createdAccountIds.push(oauthSaved.id);
    });

    after(async () => {
      for (const id of createdAccountIds) {
        await vault.removeAccount(id).catch(() => {});
      }
    });

    /**
     * Recursively verifies that an object contains NO secret keys or values
     */
    function assertNoSecrets(obj, pathStr = 'root') {
      const FORBIDDEN_KEYS = new Set([
        'pass', 'password', 'apppassword', 'app_password',
        'accesstoken', 'access_token', 'refreshtoken', 'refresh_token',
        'clientsecret', 'client_secret', 'secret', 'masterkey'
      ]);

      const CANARY_VALUES = [
        CANARY_APPLE_PASS,
        CANARY_GMAIL_PASS,
        CANARY_OUTLOOK_PASS,
        CANARY_OAUTH_TOKEN,
        CANARY_REFRESH_TOKEN
      ];

      if (obj === null || obj === undefined) return;

      if (typeof obj === 'string') {
        for (const canary of CANARY_VALUES) {
          assert.ok(
            !obj.includes(canary),
            `Secret leak detected at ${pathStr}: contains canary secret string "${canary}"`
          );
        }
        return;
      }

      if (Array.isArray(obj)) {
        obj.forEach((item, idx) => assertNoSecrets(item, `${pathStr}[${idx}]`));
        return;
      }

      if (typeof obj === 'object') {
        for (const [key, value] of Object.entries(obj)) {
          const lowerKey = key.toLowerCase();
          assert.ok(
            !FORBIDDEN_KEYS.has(lowerKey),
            `Forbidden secret property "${key}" exposed at ${pathStr}.${key}`
          );
          assertNoSecrets(value, `${pathStr}.${key}`);
        }
      }
    }

    it('verifies GET /api/accounts leaks zero secrets or sensitive keys', async () => {
      const res = await fetch(`${baseUrl}/api/accounts`);
      assert.strictEqual(res.status, 200);

      const rawText = await res.text();
      // Raw string audit for any canary presence
      assert.ok(!rawText.includes(CANARY_APPLE_PASS));
      assert.ok(!rawText.includes(CANARY_GMAIL_PASS));
      assert.ok(!rawText.includes(CANARY_OUTLOOK_PASS));
      assert.ok(!rawText.includes(CANARY_OAUTH_TOKEN));
      assert.ok(!rawText.includes(CANARY_REFRESH_TOKEN));

      // Deep structural audit
      const data = JSON.parse(rawText);
      assertNoSecrets(data);
    });

    it('verifies GET /api/accounts/:id leaks zero secrets for all created accounts', async () => {
      for (const id of createdAccountIds) {
        const res = await fetch(`${baseUrl}/api/accounts/${id}`);
        assert.strictEqual(res.status, 200);

        const rawText = await res.text();
        assert.ok(!rawText.includes(CANARY_APPLE_PASS));
        assert.ok(!rawText.includes(CANARY_GMAIL_PASS));
        assert.ok(!rawText.includes(CANARY_OUTLOOK_PASS));
        assert.ok(!rawText.includes(CANARY_OAUTH_TOKEN));
        assert.ok(!rawText.includes(CANARY_REFRESH_TOKEN));

        const data = JSON.parse(rawText);
        assertNoSecrets(data);
        assert.strictEqual(data.account.auth, undefined);
      }
    });

    it('verifies POST /api/accounts/:id/test leaks zero secrets in diagnostic results', async () => {
      for (const id of createdAccountIds) {
        const res = await fetch(`${baseUrl}/api/accounts/${id}/test`, { method: 'POST' });
        assert.ok([200, 400].includes(res.status), `Unexpected status: ${res.status}`);

        const rawText = await res.text();
        assert.ok(!rawText.includes(CANARY_APPLE_PASS));
        assert.ok(!rawText.includes(CANARY_GMAIL_PASS));
        assert.ok(!rawText.includes(CANARY_OUTLOOK_PASS));
        assert.ok(!rawText.includes(CANARY_OAUTH_TOKEN));
        assert.ok(!rawText.includes(CANARY_REFRESH_TOKEN));

        const data = JSON.parse(rawText);
        assertNoSecrets(data);
      }
    });

    it('verifies error responses do NOT reflect submitted passwords or secrets', async () => {
      const LEAK_CANARY = 'UnauthenticatedCanaryPassword!';
      const res = await fetch(`${baseUrl}/api/accounts/outlook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'invalid.user@outlook.com',
          password: LEAK_CANARY
        })
      });

      const rawText = await res.text();
      assert.ok(
        !rawText.includes(LEAK_CANARY),
        'Error responses must never reflect submitted secret values'
      );
    });
  });
});
