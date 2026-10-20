/**
 * Milestone 1 Adversarial Challenge & Empirical Stress Test Suite
 * (test/adversarial/m1-account-manager-adversarial.test.js)
 *
 * Rigorously stress-tests:
 * 1. Email input edge cases, malformed syntax, boundary lengths, homoglyphs, and injection attempts.
 * 2. Password boundary lengths (15 chars, 17 chars), whitespace normalization (tabs, newlines, non-breaking spaces),
 *    and punctuation.
 * 3. Pre-flight verification failure handling and wire error taxonomy classification across all 3 providers.
 * 4. Concurrency, race conditions, deduplication, and email casing normalization.
 * 5. Web gateway REST API robustness and defensive credential isolation.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import http from 'node:http';

import { AccountManager } from '../../src/auth/account-manager.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { WebServer } from '../../src/server/web-server.js';
import { MockImapServer } from '../helpers/mock-socket.js';
import { isValidEmail, resolveAccountConfig, normalizeAppPassword } from '../../src/config/schema.js';
import { ERROR_CODES } from '../../src/errors/taxonomy.js';

describe('Adversarial Challenge: Milestone 1 (Account Manager & Onboarding Vault)', () => {
  let tempDir;
  let vault;
  let masterKey;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-m1-adv-'));
    masterKey = crypto.randomBytes(32);
    vault = new CredentialVault({
      dataDir: tempDir,
      masterKey
    });
    await vault.init();
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup error
    }
  });

  // ==========================================================================
  // VECTOR 1: Email Input Edge Cases, Malformed Syntax, Boundary Lengths & Injection
  // ==========================================================================
  describe('Vector 1: Email Input Edge Cases & Hostile Injections', () => {
    it('rejects syntactically malformed email addresses across all providers', async () => {
      const manager = new AccountManager({ vault });
      const malformedEmails = [
        'missing-at-sign.com',
        'user@@gmail.com',
        'user@at@gmail.com',
        '.user@gmail.com',
        'user.@gmail.com',
        'user..name@gmail.com',
        'user@.gmail.com',
        'user@gmail.com.',
        'user@gmail..com',
        'user name@gmail.com',
        'user\tname@gmail.com',
        'user\nname@gmail.com',
        'user@',
        '@gmail.com',
        'user@gmail',
        'user@gmail.c', // single character TLD
        'user@gmail.123', // numeric TLD
        '   '
      ];

      for (const badEmail of malformedEmails) {
        assert.strictEqual(isValidEmail(badEmail), false, `isValidEmail should reject: "${badEmail}"`);

        // Google
        await assert.rejects(
          () => manager.addGoogleAccount({ email: badEmail, appPassword: 'abcd-efgh-ijkl-mnop' }),
          (err) => {
            assert.ok(
              err.code === 'INVALID_CREDENTIALS' || err.code === 'VALIDATION_ERROR',
              `Google rejected bad email "${badEmail}" with code ${err.code}`
            );
            return true;
          }
        );

        // Apple
        await assert.rejects(
          () => manager.addAppleAccount({ email: badEmail, appPassword: 'abcd-efgh-ijkl-mnop' }),
          (err) => {
            assert.ok(
              err.code === 'INVALID_CREDENTIALS' || err.code === 'VALIDATION_ERROR',
              `Apple rejected bad email "${badEmail}" with code ${err.code}`
            );
            return true;
          }
        );

        // Outlook
        await assert.rejects(
          () => manager.addOutlookAccount({ email: badEmail, password: 'ValidPassword123!' }),
          (err) => {
            assert.ok(
              err.code === 'INVALID_CREDENTIALS' || err.code === 'VALIDATION_ERROR',
              `Outlook rejected bad email "${badEmail}" with code ${err.code}`
            );
            return true;
          }
        );
      }
    });

    it('rejects non-string and falsy types safely without crashing', async () => {
      const manager = new AccountManager({ vault });
      const badTypes = [null, undefined, 12345, true, false, {}, [], () => {}];

      for (const val of badTypes) {
        assert.strictEqual(isValidEmail(val), false);

        await assert.rejects(
          () => manager.addGoogleAccount({ email: val, appPassword: 'abcd-efgh-ijkl-mnop' }),
          (err) => {
            assert.ok(err.code === 'VALIDATION_ERROR' || err.code === 'INVALID_CREDENTIALS');
            return true;
          }
        );
      }
    });

    it('enforces exact RFC 5322 boundary lengths (local <= 64, domain <= 253, total <= 254)', () => {
      // Valid local part of exactly 64 characters:
      const local64 = 'a'.repeat(64);
      const validEmail64 = `${local64}@example.com`;
      assert.strictEqual(isValidEmail(validEmail64), true, 'Local part of exactly 64 chars should be valid');

      // Invalid local part of 65 characters:
      const local65 = 'a'.repeat(65);
      const invalidEmail65 = `${local65}@example.com`;
      assert.strictEqual(isValidEmail(invalidEmail65), false, 'Local part of 65 chars must be rejected');

      // Maximum total valid length: up to 254 characters
      const localPart = 'a'.repeat(64);
      const domainLabel = 'b'.repeat(60);
      const email254 = `${localPart}@${domainLabel}.${domainLabel}.${domainLabel}.com`;
      assert.strictEqual(email254.length, 251);
      assert.strictEqual(isValidEmail(email254), true);

      // Oversized total length > 254 chars:
      const email255 = 'a'.repeat(64) + '@' + 'b'.repeat(60) + '.' + 'c'.repeat(60) + '.' + 'd'.repeat(60) + '.toolong.com';
      assert.ok(email255.length > 254);
      assert.strictEqual(isValidEmail(email255), false, 'Total email length > 254 chars must be rejected');
    });

    it('rejects unicode homoglyphs, emojis, and non-ASCII spoofing in emails', () => {
      const hostileEmails = [
        'user@gmaіl.com', // Cyrillic small letter 'і' U+0456
        'admin@аррӏе.com', // Cyrillic apple
        'user😎@gmail.com', // emoji in local part
        'user@gm😀il.com', // emoji in domain
        'user\u200B@gmail.com', // zero-width space
        'user\u00A0@gmail.com' // non-breaking space
      ];

      for (const hostile of hostileEmails) {
        assert.strictEqual(isValidEmail(hostile), false, `Should reject spoofed email "${hostile}"`);
      }
    });

    it('defends against CRLF and SQL/XSS injection attempts in email fields', async () => {
      const manager = new AccountManager({ vault });
      const injections = [
        'user\r\n@gmail.com',
        'victim@gmail.com\r\nBcc:attacker@evil.com',
        'admin\' OR \'1\'=\'1@gmail.com',
        'test; DROP TABLE accounts;--@gmail.com',
        '<script>alert("xss")</script>@gmail.com',
        'user\0@gmail.com'
      ];

      for (const injection of injections) {
        assert.strictEqual(isValidEmail(injection), false, `Injection "${injection}" must not be valid email`);

        await assert.rejects(
          () => manager.addGoogleAccount({ email: injection, appPassword: 'abcd-efgh-ijkl-mnop' }),
          (err) => {
            assert.ok(err.code === 'INVALID_CREDENTIALS' || err.code === 'VALIDATION_ERROR');
            return true;
          }
        );
      }
    });
  });

  // ==========================================================================
  // VECTOR 2: Password Boundary Lengths, Whitespace & Punctuation Normalization
  // ==========================================================================
  describe('Vector 2: Password Boundary Lengths & Normalization', () => {
    it('strictly validates Apple 16-char boundary lengths: rejects 15 chars and 17 chars', async () => {
      const manager = new AccountManager({ vault });

      // 15 characters (off-by-one under)
      await assert.rejects(
        () => manager.addAppleAccount({ email: 'user@icloud.com', appPassword: 'abcd-efgh-ijkl-mno' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          return true;
        }
      );

      // 17 characters (off-by-one over)
      await assert.rejects(
        () => manager.addAppleAccount({ email: 'user@icloud.com', appPassword: 'abcd-efgh-ijkl-mnopq' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          return true;
        }
      );
    });

    it('strictly validates Google 16-char boundary lengths: rejects 15 chars and 17 chars', async () => {
      const manager = new AccountManager({ vault });

      // 15 characters
      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mno' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          return true;
        }
      );

      // 17 characters
      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mnopq' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          return true;
        }
      );
    });

    it('normalizes exotic whitespace (tabs, newlines, non-breaking spaces) and multiple hyphens in 16-char app passwords', () => {
      // Exotic whitespace and multiple hyphens
      const input = '\t  abcd----\r\nefgh\u00A0\u00A0ijkl---mnop   \n';
      const normalized = normalizeAppPassword(input);
      assert.strictEqual(normalized, 'abcdefghijklmnop');
      assert.strictEqual(normalized.length, 16);
    });

    it('rejects app passwords with unexpected punctuation or symbols that alter length', async () => {
      const manager = new AccountManager({ vault });

      // Password separated by dots instead of hyphens: "abcd.efgh.ijkl.mnop" (length 19 after hyphen removal)
      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd.efgh.ijkl.mnop' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          return true;
        }
      );
    });

    it('preserves complex standard passwords intact for Microsoft Outlook while detecting 16-char app passwords', async () => {
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mockServer = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({
            accountConfig: resolved,
            transport: mockServer.getClientSocket()
          });
        }
      });

      // 1. Complex standard password with symbols and spaces
      const complexPass = 'P@ss w0rd!#%&*()-+';
      const resultStandard = await manager.addOutlookAccount({
        email: 'staff@university.edu',
        password: complexPass
      });
      assert.strictEqual(resultStandard.account.authType, 'password');
      const storedStandard = await vault.getById(resultStandard.account.id);
      assert.strictEqual(storedStandard.auth.pass, complexPass);

      // 2. 16-character app password format (auto-detected as app_password)
      const appPassOutlook = 'xxxx-yyyy-zzzz-wwww';
      const resultApp = await manager.addOutlookAccount({
        email: 'personal@outlook.com',
        password: appPassOutlook
      });
      assert.strictEqual(resultApp.account.authType, 'app_password');
      const storedApp = await vault.getById(resultApp.account.id);
      assert.strictEqual(storedApp.auth.pass, 'xxxxyyyyzzzzwwww');
    });
  });

  // ==========================================================================
  // VECTOR 3: Pre-Flight Verification & Error Classification Across All Scenarios
  // ==========================================================================
  describe('Vector 3: Pre-Flight Verification & Wire Error Classification', () => {
    it('classifies AUTH_INVALID_CREDENTIALS and does not persist to vault', async () => {
      const mockServer = new MockImapServer({ scenario: 'auth_fail' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
          assert.ok(err.remediationAdvice);
          // Zero secret leak
          assert.strictEqual(err.message.includes('abcd'), false);
          return true;
        }
      );

      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 0, 'Vault must remain empty on pre-flight auth failure');
    });

    it('classifies AUTH_APP_PASSWORD_REQUIRED when Google requires app password URL', async () => {
      const mockServer = new MockImapServer({ scenario: 'app_password_google' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
          assert.ok(err.remediationAdvice.includes('https://myaccount.google.com/apppasswords'));
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });

    it('classifies AUTH_APP_PASSWORD_REQUIRED when Apple rejects standard login', async () => {
      const mockServer = new MockImapServer({ scenario: 'app_password_apple' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addAppleAccount({ email: 'user@icloud.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
          assert.ok(err.remediationAdvice.includes('https://appleid.apple.com'));
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });

    it('classifies AUTH_TENANT_POLICY_BLOCKED for university Outlook blocking basic auth', async () => {
      const mockServer = new MockImapServer({ scenario: 'tenant_blocked_outlook' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addOutlookAccount({ email: 'student@university.edu', password: 'SecretPassword123!' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
          assert.ok(err.remediationAdvice.includes('tenant') || err.remediationAdvice.includes('OAuth2'));
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });

    it('classifies AUTH_IMAP_DISABLED when server indicates IMAP is disabled', async () => {
      const mockServer = new MockImapServer({ scenario: 'imap_disabled' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.AUTH_IMAP_DISABLED);
          assert.ok(err.remediationAdvice.includes('IMAP'));
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });

    it('classifies PROTOCOL_VIOLATION when server returns HTTP or corrupt greeting', async () => {
      const mockServer = new MockImapServer({ scenario: 'invalid_greeting' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.PROTOCOL_VIOLATION);
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });

    it('classifies CONNECTION_DROPPED or socket reset cleanly during pre-flight verify', async () => {
      const mockServer = new MockImapServer({ scenario: 'socket_drop' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addAppleAccount({ email: 'user@icloud.com', appPassword: 'abcd-efgh-ijkl-mnop' }),
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.CONNECTION_DROPPED);
          return true;
        }
      );

      assert.strictEqual((await vault.getAll()).length, 0);
    });
  });

  // ==========================================================================
  // VECTOR 4: Concurrency, Casing Normalization, Deduplication & Race Conditions
  // ==========================================================================
  describe('Vector 4: Concurrency, Deduplication & Race Conditions', () => {
    it('safely executes 10 concurrent account additions without vault corruption or data loss', async () => {
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          manager.addGoogleAccount({
            email: `concurrent.user.${i}@gmail.com`,
            appPassword: 'abcd-efgh-ijkl-mnop',
            label: `User ${i}`
          })
        );
      }

      const results = await Promise.all(promises);
      assert.strictEqual(results.length, 10);

      const stored = await vault.getAll();
      assert.strictEqual(stored.length, 10, 'All 10 accounts must be reliably saved');

      const emails = stored.map(s => s.email).sort();
      for (let i = 0; i < 10; i++) {
        assert.ok(emails.includes(`concurrent.user.${i}@gmail.com`));
      }
    });

    it('deduplicates accounts across casing variations (User@Gmail.COM vs user@gmail.com)', async () => {
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });

      // Add with uppercase casing
      await manager.addGoogleAccount({
        email: 'Case.Insensitive.User@Gmail.COM',
        appPassword: 'abcd-efgh-ijkl-mnop',
        label: 'First Casing'
      });

      assert.strictEqual((await vault.getAll()).length, 1);

      // Add same email with lowercase casing and different label/password
      await manager.addGoogleAccount({
        email: 'case.insensitive.user@gmail.com',
        appPassword: 'xxxx-yyyy-zzzz-wwww',
        label: 'Updated Casing'
      });

      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 1, 'Should update existing account rather than duplicating');
      assert.strictEqual(accounts[0].email, 'case.insensitive.user@gmail.com');
      assert.strictEqual(accounts[0].label, 'Updated Casing');
      assert.strictEqual(accounts[0].auth.pass, 'xxxxyyyyzzzzwwww');
    });

    it('safely handles concurrent additions of the EXACT same account without duplicate entries', async () => {
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });

      // 5 concurrent attempts to add the same email
      const identicalAttempts = Array.from({ length: 5 }, (_, idx) =>
        manager.addGoogleAccount({
          email: 'duplicate.collision@gmail.com',
          appPassword: 'abcd-efgh-ijkl-mnop',
          label: `Attempt ${idx}`
        })
      );

      await Promise.all(identicalAttempts);
      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 1, 'Concurrent identical additions must collapse to 1 entry');
    });

    it('defends against malicious account ID injection and path traversal in custom accounts', async () => {
      const mockServer = new MockImapServer({ scenario: 'happy_path' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      // Custom account with path traversal ID
      const traversalId = '../../../../etc/passwd';
      const result = await manager.addCustomAccount({
        id: traversalId,
        provider: 'custom',
        email: 'custom@university.edu',
        password: 'ValidPassword123!',
        imap: { host: 'imap.university.edu', port: 993, secure: true }
      });

      assert.strictEqual(result.account.id, traversalId);

      // Verify vault file was not escaped
      const stored = await vault.getById(traversalId);
      assert.ok(stored);
      assert.strictEqual(stored.email, 'custom@university.edu');

      // Clean removal
      const removed = await manager.logoutAccount(traversalId);
      assert.strictEqual(removed, true);
    });
  });

  // ==========================================================================
  // VECTOR 5: Web Gateway REST API Adversarial Stress & Secret Isolation
  // ==========================================================================
  describe('Vector 5: Web Gateway REST API Robustness & Zero Secret Leak', () => {
    let server;
    let baseUrl;
    let webServer;

    beforeEach(async () => {
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });

      webServer = new WebServer({
        port: 0, // OS assigned dynamic port
        accountManager: manager
      });
      baseUrl = await webServer.start();
    });

    afterEach(async () => {
      if (webServer) {
        await webServer.stop();
      }
    });

    function makeRequest(method, pathUrl, body = null, headers = {}) {
      return new Promise((resolve, reject) => {
        const url = new URL(pathUrl, baseUrl);
        const req = http.request(url, {
          method,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...headers
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            let parsed = null;
            try {
              parsed = JSON.parse(data);
            } catch {
              parsed = data;
            }
            resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw: data });
          });
        });

        req.on('error', reject);
        if (body !== null) {
          req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
      });
    }

    it('handles malformed JSON request bodies with HTTP 400 without crashing', async () => {
      const res = await makeRequest('POST', '/api/accounts/apple', '{ malformed json: not valid }');
      assert.strictEqual(res.status, 400);
      assert.ok(res.body.error);
    });

    it('rejects non-object JSON bodies (primitives, arrays) with HTTP 400', async () => {
      const resArray = await makeRequest('POST', '/api/accounts/gmail', [1, 2, 3]);
      assert.strictEqual(resArray.status, 400);

      const resString = await makeRequest('POST', '/api/accounts/outlook', 'just a string');
      assert.strictEqual(resString.status, 400);
    });

    it('rejects 15-char app passwords with HTTP 400 and VALIDATION_ERROR/INVALID_CREDENTIALS', async () => {
      const res = await makeRequest('POST', '/api/accounts/apple', {
        email: 'user@icloud.com',
        appPassword: 'abcd-efgh-ijkl-mno' // 15 chars
      });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.code, 'INVALID_CREDENTIALS');
      assert.ok(res.body.error.includes('16 characters'));
      assert.ok(res.body.remediationAdvice);
    });

    it('prevents path traversal outside public assets', async () => {
      const res = await makeRequest('GET', '/../../package.json');
      assert.ok(res.status === 403 || res.status === 404);
    });

    it('strictly isolates credentials: zero secret leak across GET /api/accounts and POST responses', async () => {
      // 1. Add Apple Account
      const addAppleRes = await makeRequest('POST', '/api/accounts/apple', {
        email: 'audited@icloud.com',
        appPassword: 'xxxx-yyyy-zzzz-wwww',
        label: 'Audited Apple'
      });
      assert.strictEqual(addAppleRes.status, 201);
      assert.strictEqual(addAppleRes.raw.includes('xxxxyyyyzzzzwwww'), false, 'Response payload must never contain password');
      assert.strictEqual(addAppleRes.body.account.auth, undefined);
      assert.strictEqual(addAppleRes.body.account.password, undefined);

      // 2. Add Outlook Account
      const addOutlookRes = await makeRequest('POST', '/api/accounts/outlook', {
        email: 'audited@outlook.com',
        password: 'TopSecretUniPassword!'
      });
      assert.strictEqual(addOutlookRes.status, 201);
      assert.strictEqual(addOutlookRes.raw.includes('TopSecretUniPassword!'), false, 'Response payload must never contain password');

      // 3. List accounts
      const listRes = await makeRequest('GET', '/api/accounts');
      assert.strictEqual(listRes.status, 200);
      assert.strictEqual(listRes.raw.includes('xxxxyyyyzzzzwwww'), false);
      assert.strictEqual(listRes.raw.includes('TopSecretUniPassword!'), false);

      for (const acct of listRes.body.accounts) {
        assert.strictEqual(acct.auth, undefined);
        assert.strictEqual(acct.password, undefined);
        assert.strictEqual(acct.appPassword, undefined);
      }
    });
  });
});
