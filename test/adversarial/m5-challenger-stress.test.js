/**
 * Milestone 5 Adversarial Stress & Empirical Challenge Suite
 * (test/adversarial/m5-challenger-stress.test.js)
 *
 * EMPIRICAL CHALLENGE TARGETS:
 * 1. Multi-account onboarding burst & race conditions (concurrent 5-account onboarding, deduplication, cross-instance locking).
 * 2. Multi-account concurrent sync (simultaneous triggers, re-entrancy prevention, partial failure isolation).
 * 3. Credential migration & atomic rollbacks under repeated failures (rapid 10x invalid attempts, alternating valid/invalid sequences).
 * 4. Robustness of Tier 4 assertions (Web Push RFC 8291 tamper resistance, triage classification accuracy, search SLA under volume).
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import { AccountManager } from '../../src/auth/account-manager.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { Classifier } from '../../src/triage/classifier.js';
import { NotificationManager } from '../../src/notifications/manager.js';
import { WebPushConduit, decryptWebPushPayload } from '../../src/notifications/web-push.js';
import { NtfyConduit } from '../../src/notifications/ntfy.js';
import { MockDuplexSocket, MockImapServer } from '../helpers/mock-socket.js';

/**
 * Creates an in-memory IMAP mock server configured with custom message sets and latency.
 */
function createCustomSyncMock(options = {}) {
  const {
    messages = [],
    uidValidity = 2026,
    shouldFailLogin = false,
    shouldDropOnFetch = false,
    latencyMs = 0
  } = options;

  function setupDialogue(serverSocket) {
    queueMicrotask(() => {
      if (!serverSocket.destroyed) {
        serverSocket.write('* OK [CAPABILITY IMAP4rev1 IDLE] Mock Sync Server Ready\r\n');
      }
    });

    let buffer = '';
    serverSocket.on('data', async (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\r\n');
      buffer = lines.pop();

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;

        if (latencyMs > 0) {
          await new Promise((r) => setTimeout(r, latencyMs));
        }

        const parts = line.split(' ');
        const tag = parts[0];
        const cmd = (parts[1] || '').toUpperCase();
        const args = parts.slice(2);

        if (cmd === 'CAPABILITY') {
          serverSocket.write('* CAPABILITY IMAP4rev1 IDLE\r\n');
          serverSocket.write(`${tag} OK CAPABILITY completed\r\n`);
          continue;
        }

        if (cmd === 'LOGIN') {
          if (shouldFailLogin) {
            serverSocket.write(`${tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n`);
          } else {
            serverSocket.write(`${tag} OK [CAPABILITY IMAP4rev1] Logged in successfully\r\n`);
          }
          continue;
        }

        if (cmd === 'LIST') {
          serverSocket.write('* LIST (\\HasNoChildren) "/" "INBOX"\r\n');
          serverSocket.write(`${tag} OK LIST completed\r\n`);
          continue;
        }

        if (cmd === 'SELECT' || cmd === 'EXAMINE') {
          serverSocket.write(`* ${messages.length} EXISTS\r\n`);
          serverSocket.write(`* 0 RECENT\r\n`);
          serverSocket.write(`* OK [UIDVALIDITY ${uidValidity}] UIDs valid\r\n`);
          serverSocket.write(`* OK [UIDNEXT 1000] Predicted next UID\r\n`);
          serverSocket.write(`* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n`);
          serverSocket.write(`${tag} OK [READ-WRITE] SELECT completed\r\n`);
          continue;
        }

        if (cmd === 'UID' && (args[0] || '').toUpperCase() === 'SEARCH') {
          const uids = messages.map((m) => m.uid).join(' ');
          serverSocket.write(`* SEARCH ${uids}\r\n`);
          serverSocket.write(`${tag} OK SEARCH completed\r\n`);
          continue;
        }

        if (cmd === 'UID' && (args[0] || '').toUpperCase() === 'FETCH') {
          if (shouldDropOnFetch) {
            serverSocket.destroy(new Error('read ECONNRESET'));
            return;
          }

          let seq = 1;
          for (const m of messages) {
            const flagsStr = (m.flags || []).join(' ');
            const headersText =
              `Date: ${m.date || '2026-10-20T10:00:00Z'}\r\n` +
              `From: ${m.from || 'test@example.com'}\r\n` +
              `Subject: ${m.subject || 'Subject'}\r\n` +
              `Message-ID: <msg${m.uid}@example.com>\r\n\r\n`;
            const bodyText = m.body || 'Body text content';
            const hLen = Buffer.byteLength(headersText, 'utf8');
            const bLen = Buffer.byteLength(bodyText, 'utf8');

            serverSocket.write(
              `* ${seq++} FETCH (UID ${m.uid} FLAGS (${flagsStr}) RFC822.SIZE 1024 BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC BCC SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES LIST-UNSUBSCRIBE PRECEDENCE)] {${hLen}}\r\n${headersText} BODY.PEEK[TEXT]<0.1000> {${bLen}}\r\n${bodyText})\r\n`
            );
          }
          serverSocket.write(`${tag} OK UID FETCH completed\r\n`);
          continue;
        }

        if (cmd === 'LOGOUT') {
          serverSocket.write('* BYE IMAP4rev1 server logging out\r\n');
          serverSocket.write(`${tag} OK LOGOUT completed\r\n`);
          serverSocket.end();
          continue;
        }

        serverSocket.write(`${tag} BAD Command not recognized\r\n`);
      }
    });
  }

  return {
    createClientSocket() {
      const [clientSocket, serverSocket] = MockDuplexSocket.createPair();
      setupDialogue(serverSocket);
      return clientSocket;
    }
  };
}

describe('Milestone 5 Adversarial Challenge & Stress Suite', () => {
  let tempBaseDir;

  before(async () => {
    tempBaseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-m5-stress-'));
  });

  after(async () => {
    if (tempBaseDir && fsSync.existsSync(tempBaseDir)) {
      try {
        await fs.rm(tempBaseDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }
  });

  // ============================================================================
  // FOCUS AREA 1: Multi-Account Onboarding & Sync Under Burst/Race Conditions
  // ============================================================================
  describe('Focus 1: Multi-Account Onboarding & Sync Under Burst/Race Conditions', () => {
    it('1.1 concurrently onboards 5 distinct multi-provider accounts under burst conditions with random jitter', async () => {
      const suiteDir = path.join(tempBaseDir, 'burst-5-onboarding');
      await fs.mkdir(suiteDir, { recursive: true });

      const vault = new CredentialVault({ dataDir: suiteDir });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const jitter = Math.floor(Math.random() * 20);
          const mock = new MockImapServer({ scenario: 'happy_path', messageCount: 10 });
          return new ImapClient({
            accountConfig: resolved,
            transport: mock.getClientSocket()
          });
        }
      });
      await manager.init();

      // Launch 5 simultaneous onboarding requests for 5 distinct accounts across 3 providers
      const accountsToAdd = [
        { type: 'apple', email: 'user1@icloud.com', pass: 'aaaa-1111-bbbb-2222', label: 'Apple 1' },
        { type: 'apple', email: 'user2@me.com', pass: 'cccc-3333-dddd-4444', label: 'Apple 2' },
        { type: 'google', email: 'worker1@gmail.com', pass: 'eeee-5555-ffff-6666', label: 'Gmail 1' },
        { type: 'google', email: 'worker2@gmail.com', pass: 'gggg-7777-hhhh-8888', label: 'Gmail 2' },
        { type: 'outlook', email: 'student@university.edu', pass: 'iiii-9999-jjjj-0000', label: 'Outlook 1' }
      ];

      const results = await Promise.all(
        accountsToAdd.map((acc) => {
          if (acc.type === 'apple') return manager.addAppleAccount({ email: acc.email, appPassword: acc.pass, label: acc.label });
          if (acc.type === 'google') return manager.addGoogleAccount({ email: acc.email, appPassword: acc.pass, label: acc.label });
          return manager.addOutlookAccount({ email: acc.email, appPassword: acc.pass, label: acc.label });
        })
      );

      assert.strictEqual(results.length, 5);
      for (const res of results) {
        assert.strictEqual(res.account.connected, true);
        assert.ok(res.testResult.success);
      }

      // Verify on-disk decrypted vault holds exactly 5 distinct accounts
      const allVaultAccounts = await vault.getAll();
      assert.strictEqual(allVaultAccounts.length, 5, 'Vault must contain exactly 5 accounts');

      const emails = allVaultAccounts.map((a) => a.email.toLowerCase());
      for (const acc of accountsToAdd) {
        assert.ok(emails.includes(acc.email.toLowerCase()), `Email ${acc.email} must exist in vault`);
      }

      // Verify public account list has 5 accounts with NO passwords leaked
      const publicAccounts = await manager.listAccounts();
      assert.strictEqual(publicAccounts.length, 5);
      for (const pub of publicAccounts) {
        assert.strictEqual(pub.password, undefined);
        assert.strictEqual(pub.appPassword, undefined);
        assert.strictEqual(pub.auth, undefined);
      }
    });

    it('1.2 concurrently onboards 5 identical accounts and cleanly deduplicates to 1 vault entry', async () => {
      const suiteDir = path.join(tempBaseDir, 'dedup-burst');
      await fs.mkdir(suiteDir, { recursive: true });

      const vault = new CredentialVault({ dataDir: suiteDir });
      const manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path' });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });
      await manager.init();

      // Dispatch 5 concurrent additions of the exact same email
      const results = await Promise.all([
        manager.addGoogleAccount({ email: 'duplicate@gmail.com', appPassword: 'pass-one1-pass-one1' }),
        manager.addGoogleAccount({ email: 'duplicate@gmail.com', appPassword: 'pass-two2-pass-two2' }),
        manager.addGoogleAccount({ email: 'duplicate@gmail.com', appPassword: 'pass-thr3-pass-thr3' }),
        manager.addGoogleAccount({ email: 'duplicate@gmail.com', appPassword: 'pass-fou4-pass-fou4' }),
        manager.addGoogleAccount({ email: 'duplicate@gmail.com', appPassword: 'pass-fiv5-pass-fiv5' })
      ]);

      assert.strictEqual(results.length, 5);

      const accounts = await vault.getAll();
      assert.strictEqual(accounts.length, 1, 'Must cleanly deduplicate to exactly 1 account');
      assert.strictEqual(accounts[0].email, 'duplicate@gmail.com');
      assert.ok(accounts[0].auth.pass);
    });

    it('1.3 cross-instance concurrency: 5 independent AccountManager instances adding accounts simultaneously to the same directory', async () => {
      const sharedDir = path.join(tempBaseDir, 'cross-instance-vault');
      await fs.mkdir(sharedDir, { recursive: true });

      const instances = Array.from({ length: 5 }, (_, i) => {
        const v = new CredentialVault({ dataDir: sharedDir });
        const m = new AccountManager({
          vault: v,
          imapClientFactory: (resolved) => {
            const mock = new MockImapServer({ scenario: 'happy_path' });
            return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
          }
        });
        return { vault: v, manager: m, email: `inst_user${i}@icloud.com` };
      });

      // Initialize all managers
      await Promise.all(instances.map((inst) => inst.manager.init()));

      // Run concurrent additions across separate instances
      const addPromises = instances.map((inst, i) =>
        inst.manager.addAppleAccount({
          email: inst.email,
          appPassword: `pass-inst-${String(i).padStart(4, '0')}-2026`
        })
      );

      const completed = await Promise.all(addPromises);
      assert.strictEqual(completed.length, 5);

      // Verify shared vault contains all 5 accounts
      const masterVault = new CredentialVault({ dataDir: sharedDir });
      await masterVault.init();
      const stored = await masterVault.getAll();
      assert.strictEqual(stored.length, 5, 'Shared vault must contain all 5 accounts without file corruption');
    });

    it('1.4 concurrently syncs 5 distinct accounts simultaneously without SQLite table lock or collision', async () => {
      const syncDir = path.join(tempBaseDir, 'concurrent-sync-5');
      await fs.mkdir(syncDir, { recursive: true });

      const store = new SqliteStore(path.join(syncDir, 'mailboxer.sqlite'));
      const accounts = [
        { id: 'acc_1', email: 'acc1@gmail.com' },
        { id: 'acc_2', email: 'acc2@icloud.com' },
        { id: 'acc_3', email: 'acc3@outlook.com' },
        { id: 'acc_4', email: 'acc4@gmail.com' },
        { id: 'acc_5', email: 'acc5@icloud.com' }
      ];

      for (const a of accounts) {
        store.upsertAccount({ id: a.id, email: a.email, provider: 'custom' });
      }

      // Each account has 2 unique messages
      const mocks = new Map();
      for (const a of accounts) {
        mocks.set(
          a.id,
          createCustomSyncMock({
            messages: [
              { uid: 1, subject: `Msg 1 for ${a.id}`, from: 'boss@corp.com', body: 'Report' },
              { uid: 2, subject: `Msg 2 for ${a.id}`, from: 'hr@corp.com', body: 'Benefits' }
            ]
          })
        );
      }

      const syncEngine = new SyncEngine({
        store,
        createClient: (cfg) => {
          const m = mocks.get(cfg.id);
          return new ImapClient({ accountConfig: cfg, transport: m.createClientSocket() });
        }
      });

      // Fire all 5 syncAccount concurrently
      const syncResults = await Promise.all(
        accounts.map((a) =>
          syncEngine.syncAccount(a.id, {
            accountConfig: { id: a.id, email: a.email, auth: { user: a.email, pass: 'secret' } }
          })
        )
      );

      assert.strictEqual(syncResults.length, 5);
      for (const sr of syncResults) {
        assert.strictEqual(sr.success, true);
        assert.strictEqual(sr.totalNewMessages, 2);
      }

      // Verify SQLite store contains all 10 messages
      const allMsgs = store.getMessages();
      assert.strictEqual(allMsgs.length, 10, 'All 10 messages across 5 accounts must be stored');

      // Check SQLite WAL integrity
      const pragmaCheck = store.db.prepare('PRAGMA integrity_check').all();
      assert.strictEqual(pragmaCheck[0].integrity_check, 'ok');

      store.close();
    });

    it('1.5 handles 5 simultaneous sync triggers for the SAME account without race conditions', async () => {
      const syncDir = path.join(tempBaseDir, 'reentrant-sync');
      await fs.mkdir(syncDir, { recursive: true });

      const store = new SqliteStore(path.join(syncDir, 'mailboxer.sqlite'));
      const accountId = 'acc_reentrant';
      store.upsertAccount({ id: accountId, email: 'reentrant@test.com', provider: 'custom' });

      const mock = createCustomSyncMock({
        latencyMs: 15, // Introduce artificial latency so triggers overlap
        messages: [{ uid: 1, subject: 'Hello', from: 'sender@test.com' }]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: (cfg) => new ImapClient({ accountConfig: cfg, transport: mock.createClientSocket() })
      });

      const triggers = Array.from({ length: 5 }, () =>
        syncEngine.syncAccount(accountId, {
          accountConfig: { id: accountId, email: 'reentrant@test.com', auth: { user: 'u', pass: 'p' } }
        })
      );

      const outcomes = await Promise.all(triggers);
      assert.strictEqual(outcomes.length, 5);

      const activeCompleted = outcomes.filter((o) => o.success === true && !o.skipped);
      const skipped = outcomes.filter((o) => o.skipped === true);

      assert.strictEqual(activeCompleted.length, 1, 'Only 1 active sync should execute');
      assert.strictEqual(skipped.length, 4, '4 concurrent triggers must be skipped safely');

      // Local store has exactly 1 message, no duplicates
      const stored = store.getMessages({ accountId });
      assert.strictEqual(stored.length, 1);

      store.close();
    });

    it('1.6 isolates partial failure: 1 failing account does not abort or corrupt 4 healthy concurrent account syncs', async () => {
      const syncDir = path.join(tempBaseDir, 'partial-fail-sync');
      await fs.mkdir(syncDir, { recursive: true });

      const store = new SqliteStore(path.join(syncDir, 'mailboxer.sqlite'));
      const accounts = [
        { id: 'acc_ok1', fail: false },
        { id: 'acc_fail', fail: true }, // will fail mid-fetch
        { id: 'acc_ok2', fail: false },
        { id: 'acc_ok3', fail: false },
        { id: 'acc_ok4', fail: false }
      ];

      for (const a of accounts) {
        store.upsertAccount({ id: a.id, email: `${a.id}@test.com`, provider: 'custom' });
      }

      const syncEngine = new SyncEngine({
        store,
        createClient: (cfg) => {
          const isFailing = cfg.id === 'acc_fail';
          const mock = createCustomSyncMock({
            shouldDropOnFetch: isFailing,
            messages: [{ uid: 1, subject: `Msg for ${cfg.id}` }]
          });
          return new ImapClient({ accountConfig: cfg, transport: mock.createClientSocket() });
        }
      });

      syncEngine.on('syncError', () => {}); // absorb event

      const syncPromises = accounts.map((a) =>
        syncEngine.syncAccount(a.id, {
          throwOnError: false,
          accountConfig: { id: a.id, email: `${a.id}@test.com`, auth: { user: 'u', pass: 'p' } }
        })
      );

      const results = await Promise.all(syncPromises);

      const failedResult = results.find((r) => r.accountId === 'acc_fail');
      const okResults = results.filter((r) => r.accountId !== 'acc_fail');

      assert.strictEqual(failedResult.success, false);
      assert.strictEqual(okResults.length, 4);
      for (const ok of okResults) {
        assert.strictEqual(ok.success, true);
        assert.strictEqual(ok.totalNewMessages, 1);
      }

      // Check SQLite state
      const healthyMsgs = store.getMessages();
      assert.strictEqual(healthyMsgs.length, 4, 'Exactly 4 healthy messages must be stored');

      store.close();
    });
  });

  // ============================================================================
  // FOCUS AREA 2: Credential Migration & Atomic Rollbacks Under Repeated Failures
  // ============================================================================
  describe('Focus 2: Credential Migration & Atomic Rollbacks Under Repeated Failures', () => {
    let migrDir;
    let vault;
    let manager;
    let store;
    const INITIAL_PASS = 'orig-pass-word-2026'; // 16 chars: origpassword2026

    beforeEach(async () => {
      migrDir = await fs.mkdtemp(path.join(tempBaseDir, 'migr-stress-'));
      vault = new CredentialVault({ dataDir: migrDir });
      store = new SqliteStore(path.join(migrDir, 'mailboxer.sqlite'));

      manager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const pass = resolved.auth?.pass || resolved.password || '';
          const shouldFail = pass.includes('fail') || pass.includes('bad') || pass.includes('revo');
          const mock = new MockImapServer({
            scenario: shouldFail ? 'auth_fail' : 'happy_path',
            messageCount: 5
          });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });

      await manager.init();

      // Seed valid account
      await manager.addAppleAccount({
        email: 'migr_user@icloud.com',
        appPassword: INITIAL_PASS,
        label: 'Original Account'
      });

      // Seed historical message
      const accounts = await manager.listAccounts();
      store.upsertAccount({ id: accounts[0].id, email: accounts[0].email, provider: 'apple' });
      store.upsertFolder({ id: 'fld_hist', account_id: accounts[0].id, name: 'INBOX', path: 'INBOX' });
      store.upsertMessages([
        {
          id: 'hist_msg_1',
          account_id: accounts[0].id,
          folder_id: 'fld_hist',
          uid: 55,
          subject: 'Critical Historical Message',
          is_seen: 1
        }
      ]);
    });

    afterEach(() => {
      if (store) store.close();
    });

    it('2.1 withstands 10 rapid consecutive invalid migration attempts without vault or SQLite corruption', async () => {
      const accounts = await manager.listAccounts();
      const targetId = accounts[0].id;
      const originalRecord = await vault.getById(targetId);
      const originalPass = originalRecord.auth.pass;
      const originalVerifiedAt = originalRecord.lastVerifiedAt;

      // 10 consecutive bad attempts with invalid / revoked app passwords
      const badPasswords = Array.from({ length: 10 }, (_, i) => `fail-badp-assw-${String(i).padStart(4, '0')}`);

      for (const badPass of badPasswords) {
        await assert.rejects(
          async () => {
            await manager.addAppleAccount({
              email: 'migr_user@icloud.com',
              appPassword: badPass
            });
          },
          (err) => {
            assert.ok(err.code === 'AUTH_FAILED' || err.code === 'AUTH_APP_PASSWORD_REQUIRED');
            return true;
          }
        );

        // Verify vault immediately after each failure
        const currentRecord = await vault.getById(targetId);
        assert.strictEqual(currentRecord.auth.pass, originalPass, 'Vault password must NOT change after failed attempt');
        assert.strictEqual(currentRecord.lastVerifiedAt, originalVerifiedAt, 'Timestamp must remain unchanged');
      }

      // Check final state
      const finalRecord = await vault.getById(targetId);
      assert.strictEqual(finalRecord.auth.pass, originalPass);

      // Verify SQLite historical data remains 100% intact
      const hist = store.getMessages({ accountId: targetId });
      assert.strictEqual(hist.length, 1);
      assert.strictEqual(hist[0].id, 'hist_msg_1');
    });

    it('2.2 handles rapid alternating sequence of 10 valid and invalid migration attempts', async () => {
      const accounts = await manager.listAccounts();
      const targetId = accounts[0].id;

      let expectedPass = 'origpassword2026';

      for (let cycle = 1; cycle <= 5; cycle++) {
        // Step A: Invalid attempt (must fail, preserve expectedPass)
        const badPass = `fail-revo-pass-${String(cycle).padStart(4, '0')}`;
        await assert.rejects(
          () => manager.addAppleAccount({ email: 'migr_user@icloud.com', appPassword: badPass }),
          (err) => err.code === 'AUTH_FAILED' || err.code === 'AUTH_APP_PASSWORD_REQUIRED'
        );

        let cur = await vault.getById(targetId);
        assert.strictEqual(cur.auth.pass, expectedPass);

        // Step B: Valid attempt (must succeed, update expectedPass)
        const validPass = `good-pass-work-${String(cycle).padStart(4, '0')}`;
        const normalized = validPass.replace(/-/g, '');
        expectedPass = normalized;

        const updateRes = await manager.addAppleAccount({
          email: 'migr_user@icloud.com',
          appPassword: validPass
        });
        assert.strictEqual(updateRes.account.connected, true);

        cur = await vault.getById(targetId);
        assert.strictEqual(cur.auth.pass, expectedPass);
      }

      // Final check
      const finalRec = await vault.getById(targetId);
      assert.strictEqual(finalRec.auth.pass, 'goodpasswork0005');

      // SQLite historical data check
      const hist = store.getMessages({ accountId: targetId });
      assert.strictEqual(hist.length, 1);
    });

    it('2.3 handles concurrent conflicting migrations: simultaneous valid and invalid requests for the same account', async () => {
      const accounts = await manager.listAccounts();
      const targetId = accounts[0].id;

      const validPass = 'conc-good-pass-9999';
      const invalidPass = 'conc-fail-pass-1111';

      const results = await Promise.allSettled([
        manager.addAppleAccount({ email: 'migr_user@icloud.com', appPassword: validPass }),
        manager.addAppleAccount({ email: 'migr_user@icloud.com', appPassword: invalidPass })
      ]);

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');

      assert.strictEqual(fulfilled.length, 1, 'Valid attempt must succeed');
      assert.strictEqual(rejected.length, 1, 'Invalid attempt must fail');

      // Vault must contain valid pass, never invalid
      const current = await vault.getById(targetId);
      assert.strictEqual(current.auth.pass, 'concgoodpass9999');
    });
  });

  // ============================================================================
  // FOCUS AREA 3: Verification of Tier 4 Assertions & Mock Shortcut Resistance
  // ============================================================================
  describe('Focus 3: Robustness of Tier 4 Assertions & Mock Shortcut Resistance', () => {
    it('3.1 verifies Web Push RFC 8291 aes128gcm payload rejects tampering and prevents mock shortcuts', async () => {
      const pushDir = path.join(tempBaseDir, 'webpush-tamper');
      await fs.mkdir(pushDir, { recursive: true });

      const store = new SqliteStore(path.join(pushDir, 'mailboxer.sqlite'));

      // Generate client keys
      const clientEcdh = crypto.createECDH('prime256v1');
      clientEcdh.generateKeys();
      const clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
      const clientAuthSecret = crypto.randomBytes(16).toString('base64url');

      store.upsertPushSubscription({
        endpoint: 'https://push.example.com/send/1',
        keys: { p256dh: clientPublicKey, auth: clientAuthSecret }
      });

      const conduit = new WebPushConduit({
        store,
        vapidPath: path.join(pushDir, 'vapid.json'),
        contactEmail: 'mailto:admin@mailboxer.internal'
      });

      let capturedBody = null;
      const mockFetch = async (url, init) => {
        capturedBody = init.body;
        return { status: 201, ok: true, text: async () => 'Created' };
      };

      await conduit.sendToAll(
        { title: 'VIP Alert', body: 'Prof. Vance meeting at 3pm', category: 'VIP' },
        { fetch: mockFetch }
      );

      assert.ok(capturedBody instanceof Buffer, 'Captured payload must be encrypted binary Buffer');

      // 1. Legitimate decryption succeeds
      const decrypted = decryptWebPushPayload(
        capturedBody,
        clientEcdh,
        Buffer.from(clientAuthSecret, 'base64url')
      );
      const json = JSON.parse(decrypted.toString('utf8'));
      assert.strictEqual(json.title, 'VIP Alert');

      // 2. Adversarial tampering: flip a single byte in ciphertext
      const tamperedBody = Buffer.from(capturedBody);
      tamperedBody[tamperedBody.length - 1] ^= 0x01; // flip bit

      assert.throws(
        () => {
          decryptWebPushPayload(tamperedBody, clientEcdh, Buffer.from(clientAuthSecret, 'base64url'));
        },
        (err) => {
          // GCM authentication tag mismatch
          return err.message.includes('Unsupported state') || err.message.includes('auth') || err.name === 'Error';
        },
        'Decryption of tampered ciphertext must throw GCM authentication failure'
      );

      // 3. Adversarial tampering: wrong auth secret
      const wrongAuth = crypto.randomBytes(16);
      assert.throws(
        () => {
          decryptWebPushPayload(capturedBody, clientEcdh, wrongAuth);
        },
        () => true,
        'Decryption with wrong client auth secret must fail'
      );

      store.close();
    });

    it('3.2 verifies triage classifier cannot be fooled by spoofed headers or fake sender prefixes', () => {
      const classifier = new Classifier();

      // Case A: Promo message claiming to be from "professor" in subject but having List-Unsubscribe
      const spoofedPromo = {
        sender: 'Deals <promo@shopping.com>',
        subject: 'Message from Professor: 50% discount on textbooks',
        list_unsubscribe: '<mailto:unsub@shopping.com>',
        precedence: 'bulk'
      };
      const promoResult = classifier.classify(spoofedPromo);
      assert.strictEqual(promoResult.category, 'NOISE', 'List-Unsubscribe and bulk precedence must override keyword in subject');
      assert.strictEqual(promoResult.shouldNotify, false);

      // Case B: Genuine university professor email with no unsubscribe headers
      const genuineVip = {
        sender: 'Prof. Marcus Vance <m.vance@stanford.edu>',
        subject: 'Research Grant Review Today',
        body_snippet: 'Please bring your experimental findings.'
      };
      const vipResult = classifier.classify(genuineVip);
      assert.strictEqual(vipResult.category, 'VIP');
      assert.strictEqual(vipResult.shouldNotify, true);

      // Case C: Automated course update (Canvas / Blackboard)
      const coursework = {
        sender: 'Canvas LMS <notifications@instructure.com>',
        subject: 'Assignment Graded: CS244',
        precedence: 'bulk'
      };
      const courseResult = classifier.classify(coursework);
      assert.strictEqual(courseResult.category, 'UPDATE');
      assert.strictEqual(courseResult.shouldNotify, false);
    });

    it('3.3 verifies SQLite full-text search index enforces sub-20ms SLA under heavy message load (500 items)', () => {
      const ftsDir = path.join(tempBaseDir, 'fts-scale');
      fsSync.mkdirSync(ftsDir, { recursive: true });
      const store = new SqliteStore(path.join(ftsDir, 'mailboxer.sqlite'));

      store.upsertAccount({ id: 'acc_fts', email: 'fts@test.com', provider: 'custom' });
      store.upsertFolder({ id: 'fld_fts', account_id: 'acc_fts', name: 'INBOX', path: 'INBOX' });

      // Generate 500 realistic messages
      const msgs = Array.from({ length: 500 }, (_, i) => ({
        id: `msg_bulk_${i}`,
        account_id: 'acc_fts',
        folder_id: 'fld_fts',
        uid: i + 1,
        sender: `colleague_${i % 20}@company.com`,
        subject: i === 250 ? 'Confidential Project Apollo Architecture Review' : `Routine status update report #${i}`,
        body_snippet: i === 250 ? 'The target server deployment in Packard Room 302 is scheduled.' : `General notes and updates regarding ticket number ${i}.`,
        date: new Date(Date.now() - i * 60000).toISOString(),
        is_seen: 0
      }));

      store.upsertMessages(msgs);

      // Benchmark single-word query
      const start1 = performance.now();
      const res1 = store.search('Apollo');
      const time1 = performance.now() - start1;

      assert.strictEqual(res1.length, 1);
      assert.ok(res1[0].subject.includes('Apollo'));
      assert.ok(time1 < 20.0, `Search for "Apollo" took ${time1.toFixed(2)}ms (must be < 20ms)`);

      // Benchmark body snippet query
      const start2 = performance.now();
      const res2 = store.search('Packard');
      const time2 = performance.now() - start2;

      assert.strictEqual(res2.length, 1);
      assert.ok(res2[0].body_snippet.includes('Packard Room 302'));
      assert.ok(time2 < 20.0, `Search for "Packard" took ${time2.toFixed(2)}ms (must be < 20ms)`);

      store.close();
    });
  });
});
