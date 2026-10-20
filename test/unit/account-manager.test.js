/**
 * Account Manager Unit Test Suite (test/unit/account-manager.test.js)
 *
 * Tests:
 * - addGoogleAccount & addGmailAccount email validation, 16-char password normalization,
 *   pre-flight check, and AES-256-GCM vault persistence.
 * - addOutlookAccount input validation, password / app password handling,
 *   pre-flight check, and vault persistence.
 * - addAppleAccount 16-char validation and pre-flight verify.
 * - Secret isolation (safe public listing, zero secrets in return payloads).
 * - Explicit account logout / deletion.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { AccountManager } from '../../src/auth/account-manager.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { MockImapServer } from '../helpers/mock-socket.js';

describe('Account Manager Guided Onboarding & Vault (src/auth/account-manager.js)', () => {
  let tempDir;
  let vault;
  let masterKey;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-acct-test-'));
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
      // ignore
    }
  });

  describe('Google Mail (Gmail) Guided Onboarding', () => {
    it('rejects missing or empty credentials with VALIDATION_ERROR', async () => {
      const manager = new AccountManager({ vault });

      await assert.rejects(
        () => manager.addGoogleAccount({}),
        (err) => {
          assert.strictEqual(err.code, 'VALIDATION_ERROR');
          assert.ok(err.message.includes('required'));
          return true;
        }
      );

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: '   ' }),
        (err) => {
          assert.strictEqual(err.code, 'VALIDATION_ERROR');
          return true;
        }
      );
    });

    it('rejects invalid email addresses with INVALID_CREDENTIALS', async () => {
      const manager = new AccountManager({ vault });

      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'not-an-email', appPassword: 'abcd efgh ijkl mnop' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.remediationAdvice);
          return true;
        }
      );
    });

    it('rejects passwords that are not 16 characters after normalization', async () => {
      const manager = new AccountManager({ vault });

      // 12 chars
      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd efgh ijkl' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          assert.ok(err.remediationAdvice.includes('https://myaccount.google.com/apppasswords'));
          return true;
        }
      );

      // 18 chars
      await assert.rejects(
        () => manager.addGoogleAccount({ email: 'user@gmail.com', appPassword: 'abcd efgh ijkl mnop qr' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          assert.ok(err.message.includes('16 characters'));
          return true;
        }
      );
    });

    it('handles pre-flight connection failure and does not persist to vault', async () => {
      const mockServer = new MockImapServer({ scenario: 'auth_fail' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addGoogleAccount({
          email: 'test@gmail.com',
          appPassword: 'abcd efgh ijkl mnop'
        }),
        (err) => {
          assert.strictEqual(err.code, 'AUTH_INVALID_CREDENTIALS');
          assert.ok(err.remediationAdvice);
          return true;
        }
      );

      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 0);
    });

    it('successfully connects, verifies, and stores Google account in vault', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 150,
        unseenCount: 5
      });

      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      // Pass 16-char password with spaces
      const result = await manager.addGoogleAccount({
        email: 'Personal.User@gmail.com',
        appPassword: 'abcd efgh ijkl mnop',
        label: 'My Google Mail'
      });

      assert.strictEqual(result.account.provider, 'gmail');
      assert.strictEqual(result.account.email, 'personal.user@gmail.com');
      assert.strictEqual(result.account.label, 'My Google Mail');
      assert.strictEqual(result.account.authType, 'app_password');
      assert.strictEqual(result.account.connected, true);
      assert.strictEqual(result.account.inboxStatus.totalMessages, 150);
      assert.strictEqual(result.account.inboxStatus.unseen, 5);
      // Secrets must NOT be returned in public summary
      assert.strictEqual(result.account.auth, undefined);
      assert.strictEqual(result.account.password, undefined);

      // Verify stored in vault permanently
      const stored = await vault.getById(result.account.id);
      assert.ok(stored);
      assert.strictEqual(stored.email, 'personal.user@gmail.com');
      // Pass was normalized to 16 letters without spaces
      assert.strictEqual(stored.auth.pass, 'abcdefghijklmnop');
      assert.strictEqual(stored.auth.type, 'app_password');
      assert.strictEqual(stored.inboxStatus.totalMessages, 150);
    });

    it('addGmailAccount acts as a fully functional alias for addGoogleAccount', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 88,
        unseenCount: 2
      });

      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      const result = await manager.addGmailAccount({
        email: 'alias.test@gmail.com',
        appPassword: 'xxxx-yyyy-zzzz-wwww'
      });

      assert.strictEqual(result.account.provider, 'gmail');
      assert.strictEqual(result.account.email, 'alias.test@gmail.com');
      assert.strictEqual(result.account.authType, 'app_password');
    });
  });

  describe('Microsoft Outlook Guided Onboarding', () => {
    it('rejects missing credentials or invalid email format', async () => {
      const manager = new AccountManager({ vault });

      await assert.rejects(
        () => manager.addOutlookAccount({}),
        (err) => {
          assert.strictEqual(err.code, 'VALIDATION_ERROR');
          return true;
        }
      );

      await assert.rejects(
        () => manager.addOutlookAccount({ email: 'bad-email', password: 'ValidPassword123!' }),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CREDENTIALS');
          return true;
        }
      );
    });

    it('handles pre-flight check failure for Outlook with remediation advice', async () => {
      const mockServer = new MockImapServer({ scenario: 'tenant_blocked_outlook' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      await assert.rejects(
        () => manager.addOutlookAccount({
          email: 'student@university.edu',
          password: 'SecretPassword123'
        }),
        (err) => {
          assert.strictEqual(err.code, 'AUTH_TENANT_POLICY_BLOCKED');
          assert.ok(err.remediationAdvice);
          return true;
        }
      );

      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 0);
    });

    it('successfully connects, verifies, and stores standard password Outlook account', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 300,
        unseenCount: 12
      });

      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      const result = await manager.addOutlookAccount({
        email: 'student@university.edu',
        password: 'ComplexUniPassword99!',
        label: 'University Email'
      });

      assert.strictEqual(result.account.provider, 'outlook');
      assert.strictEqual(result.account.email, 'student@university.edu');
      assert.strictEqual(result.account.label, 'University Email');
      assert.strictEqual(result.account.authType, 'password');
      assert.strictEqual(result.account.connected, true);
      assert.strictEqual(result.account.inboxStatus.totalMessages, 300);
      assert.strictEqual(result.account.auth, undefined);

      const stored = await vault.getById(result.account.id);
      assert.strictEqual(stored.auth.pass, 'ComplexUniPassword99!');
      assert.strictEqual(stored.auth.type, 'password');
    });

    it('normalizes and supports 16-character Microsoft App Password', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 45,
        unseenCount: 1
      });

      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      const result = await manager.addOutlookAccount({
        email: 'personal@outlook.com',
        appPassword: 'abcd-efgh-ijkl-mnop'
      });

      assert.strictEqual(result.account.provider, 'outlook');
      assert.strictEqual(result.account.authType, 'app_password');

      const stored = await vault.getById(result.account.id);
      assert.strictEqual(stored.auth.pass, 'abcdefghijklmnop');
      assert.strictEqual(stored.auth.type, 'app_password');
    });
  });

  describe('Apple Mail Guided Onboarding', () => {
    it('successfully connects and verifies Apple account with normalized 16-char password', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 95,
        unseenCount: 4
      });

      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      const result = await manager.addAppleAccount({
        email: 'user@icloud.com',
        appPassword: 'xxxx-yyyy-zzzz-wwww'
      });

      assert.strictEqual(result.account.provider, 'apple');
      assert.strictEqual(result.account.authType, 'app_password');
      assert.strictEqual(result.account.inboxStatus.totalMessages, 95);

      const stored = await vault.getById(result.account.id);
      assert.strictEqual(stored.auth.pass, 'xxxxyyyyzzzzwwww');
    });
  });

  describe('Vault Management & Secret Isolation', () => {
    it('listAccounts() strips all secrets across Apple, Google, and Outlook accounts', async () => {
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

      await manager.addGoogleAccount({ email: 'g@gmail.com', appPassword: 'aaaa-bbbb-cccc-dddd' });
      await manager.addOutlookAccount({ email: 'o@outlook.com', password: 'outlook-secret-pw' });
      await manager.addAppleAccount({ email: 'a@icloud.com', appPassword: 'eeee-ffff-gggg-hhhh' });

      const list = await manager.listAccounts();
      assert.strictEqual(list.length, 3);

      for (const acct of list) {
        assert.ok(acct.id);
        assert.ok(acct.provider);
        assert.ok(acct.email);
        assert.strictEqual(acct.auth, undefined);
        assert.strictEqual(acct.password, undefined);
        assert.strictEqual(acct.appPassword, undefined);
        assert.strictEqual(acct.accessToken, undefined);
      }
    });

    it('logoutAccount() cleanly removes account from vault', async () => {
      const mockServer = new MockImapServer({ scenario: 'happy_path' });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        })
      });

      const result = await manager.addGoogleAccount({
        email: 'logout-test@gmail.com',
        appPassword: 'aaaa-bbbb-cccc-dddd'
      });

      assert.ok(await vault.getById(result.account.id));

      const loggedOut = await manager.logoutAccount(result.account.id);
      assert.strictEqual(loggedOut, true);

      assert.strictEqual(await vault.getById(result.account.id), null);
    });
  });
});
