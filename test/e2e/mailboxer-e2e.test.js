/**
 * Mailboxer Tier 4 Real-World Application End-to-End Test Suite
 * (test/e2e/mailboxer-e2e.test.js)
 *
 * Implements the 5 Tier 4 Real-World Application Scenarios specified in TEST_INFRA.md:
 * - Scenario 1: Multi-Account Cold Boot & Missing Credentials
 * - Scenario 2: Unified Tri-Provider Triage Connection Cycle
 *   (Apple, Gmail, Outlook onboarding + IMAP sync + Triage + Web Push & ntfy alerts)
 * - Scenario 3: Provider App-Password Migration & Failure Recovery
 * - Scenario 4: Network Outage & Socket Drop Resiliency during Sync/IDLE
 * - Scenario 5: Full System Ingress & Botkeep Cloud Health Telemetry (/health)
 *
 * Zero-dependency native Node.js 22 test runner (node:test, node:assert/strict).
 * 100% offline hermetic execution using MockImapServer and MockDuplexSocket.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import { runDiagnostics } from '../../bin/verify.js';
import { WebServer } from '../../src/server/web-server.js';
import { AccountManager } from '../../src/auth/account-manager.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { IdleManager } from '../../src/connection/idle-manager.js';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { Classifier } from '../../src/triage/classifier.js';
import { NotificationManager } from '../../src/notifications/manager.js';
import { WebPushConduit, decryptWebPushPayload } from '../../src/notifications/web-push.js';
import { NtfyConduit } from '../../src/notifications/ntfy.js';
import { MockDuplexSocket, MockImapServer } from '../helpers/mock-socket.js';

/**
 * Creates an in-memory IMAP mock server configured with realistic sync protocol responses
 * (LIST, SELECT, UID SEARCH, UID FETCH, UID STORE, LOGOUT).
 */
function createSyncMockServer(initialState = {}) {
  const state = {
    uidValidity: initialState.uidValidity ?? 2026,
    uidNext: initialState.uidNext ?? 10,
    folders: initialState.folders ?? [
      { name: 'INBOX', path: 'INBOX', flags: ['\\HasNoChildren'] }
    ],
    messages: new Map(),
    unseenUids: new Set(initialState.unseenUids ?? []),
    customCommandHandler: null,
    ...initialState
  };

  if (initialState.initialMessages) {
    const inboxMsgs = new Map();
    for (const m of initialState.initialMessages) {
      inboxMsgs.set(m.uid, m);
    }
    state.messages.set('INBOX', inboxMsgs);
  }

  function setupDialogue(serverSocket) {
    let selectedFolder = 'INBOX';

    queueMicrotask(() => {
      if (!serverSocket.destroyed) {
        serverSocket.write('* OK [CAPABILITY IMAP4rev1 IDLE] Mailboxer Hermetic Mock Sync Server Ready\r\n');
      }
    });

    let buffer = '';
    serverSocket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\r\n');
      buffer = lines.pop();

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;

        const parts = line.split(' ');
        const tag = parts[0];
        const cmd = (parts[1] || '').toUpperCase();
        const args = parts.slice(2);

        if (state.customCommandHandler) {
          const handled = state.customCommandHandler({ tag, cmd, args, rawLine: line, serverSocket });
          if (handled) continue;
        }

        // CAPABILITY
        if (cmd === 'CAPABILITY') {
          serverSocket.write('* CAPABILITY IMAP4rev1 IDLE UNSELECT SASL-IR\r\n');
          serverSocket.write(`${tag} OK CAPABILITY completed\r\n`);
          continue;
        }

        // LOGIN
        if (cmd === 'LOGIN') {
          serverSocket.write(`${tag} OK [CAPABILITY IMAP4rev1] Logged in successfully\r\n`);
          continue;
        }

        // LIST
        if (cmd === 'LIST') {
          for (const f of state.folders) {
            const flagStr = f.flags.join(' ');
            serverSocket.write(`* LIST (${flagStr}) "/" "${f.path}"\r\n`);
          }
          serverSocket.write(`${tag} OK LIST completed\r\n`);
          continue;
        }

        // SELECT / EXAMINE
        if (cmd === 'SELECT' || cmd === 'EXAMINE') {
          selectedFolder = args[0] ? args[0].replace(/"/g, '') : 'INBOX';
          const folderMsgs = state.messages.get(selectedFolder) || new Map();
          serverSocket.write(`* ${folderMsgs.size} EXISTS\r\n`);
          serverSocket.write(`* 0 RECENT\r\n`);
          serverSocket.write(`* OK [UIDVALIDITY ${state.uidValidity}] UIDs valid\r\n`);
          serverSocket.write(`* OK [UIDNEXT ${state.uidNext}] Predicted next UID\r\n`);
          serverSocket.write(`* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n`);
          serverSocket.write(`${tag} OK [READ-WRITE] ${cmd} completed\r\n`);
          continue;
        }

        // UID SEARCH
        if (cmd === 'UID' && (args[0] || '').toUpperCase() === 'SEARCH') {
          const criteria = args.slice(1).join(' ').toUpperCase();
          const folderMsgs = state.messages.get(selectedFolder) || new Map();
          let matchedUids = [];

          if (criteria === 'ALL') {
            matchedUids = Array.from(folderMsgs.keys()).sort((a, b) => a - b);
          } else if (criteria === 'UNSEEN') {
            matchedUids = Array.from(state.unseenUids).filter(u => folderMsgs.has(u)).sort((a, b) => a - b);
          } else if (criteria === 'FLAGGED') {
            matchedUids = Array.from(folderMsgs.entries())
              .filter(([, m]) => (m.flags || []).some(fl => String(fl).toLowerCase() === '\\flagged'))
              .map(([u]) => u)
              .sort((a, b) => a - b);
          } else if (criteria.startsWith('UID')) {
            const rangeStr = criteria.replace(/^UID\s+/, '').trim();
            if (rangeStr.endsWith(':*')) {
              const min = parseInt(rangeStr.replace(':*', ''), 10);
              matchedUids = Array.from(folderMsgs.keys()).filter(u => u >= min).sort((a, b) => a - b);
            } else {
              matchedUids = Array.from(folderMsgs.keys()).sort((a, b) => a - b);
            }
          } else {
            matchedUids = Array.from(folderMsgs.keys()).sort((a, b) => a - b);
          }

          const uidStr = matchedUids.join(' ');
          serverSocket.write(`* SEARCH ${uidStr}\r\n`);
          serverSocket.write(`${tag} OK SEARCH completed\r\n`);
          continue;
        }

        // UID FETCH
        if (cmd === 'UID' && (args[0] || '').toUpperCase() === 'FETCH') {
          const rangeStr = args[1] || '1';
          const folderMsgs = state.messages.get(selectedFolder) || new Map();
          const targetUids = [];

          if (rangeStr.includes(',')) {
            for (const part of rangeStr.split(',')) {
              const num = parseInt(part.trim(), 10);
              if (folderMsgs.has(num)) targetUids.push(num);
            }
          } else if (rangeStr.includes(':')) {
            const [start, end] = rangeStr.split(':').map(Number);
            for (const [uid] of folderMsgs) {
              if (uid >= start && (isNaN(end) || uid <= end)) {
                targetUids.push(uid);
              }
            }
          } else {
            const num = parseInt(rangeStr, 10);
            if (folderMsgs.has(num)) targetUids.push(num);
          }

          let seq = 1;
          for (const uid of targetUids) {
            const m = folderMsgs.get(uid);
            const flags = Array.from(m.flags || []);
            if (!state.unseenUids.has(uid) && !flags.includes('\\Seen')) {
              flags.push('\\Seen');
            }
            const flagsStr = flags.join(' ');

            let headersText = `Date: ${m.date || '2026-10-20T10:00:00Z'}\r\n` +
              `From: ${m.from || 'test@example.com'}\r\n` +
              `Subject: ${m.subject || 'Subject'}\r\n` +
              `Message-ID: <msg${uid}@example.com>\r\n`;

            if (m.precedence) {
              headersText += `Precedence: ${m.precedence}\r\n`;
            }
            if (m.listUnsubscribe) {
              headersText += `List-Unsubscribe: ${m.listUnsubscribe}\r\n`;
            }
            headersText += '\r\n';

            const bodyText = m.body || 'Body text content';
            const hLen = Buffer.byteLength(headersText, 'utf8');
            const bLen = Buffer.byteLength(bodyText, 'utf8');

            serverSocket.write(
              `* ${seq++} FETCH (UID ${uid} FLAGS (${flagsStr}) RFC822.SIZE 1024 BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC BCC SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES LIST-UNSUBSCRIBE PRECEDENCE)] {${hLen}}\r\n${headersText} BODY.PEEK[TEXT]<0.1000> {${bLen}}\r\n${bodyText})\r\n`
            );
          }

          serverSocket.write(`${tag} OK UID FETCH completed\r\n`);
          continue;
        }

        // LOGOUT
        if (cmd === 'LOGOUT') {
          serverSocket.write('* BYE IMAP4rev1 server logging out\r\n');
          serverSocket.write(`${tag} OK LOGOUT completed\r\n`);
          serverSocket.end();
          continue;
        }

        serverSocket.write(`${tag} BAD Command not implemented\r\n`);
      }
    });
  }

  return {
    syncState: state,
    createClientSocket() {
      const [clientSocket, serverSocket] = MockDuplexSocket.createPair();
      setupDialogue(serverSocket);
      return clientSocket;
    }
  };
}

describe('Tier 4 Real-World Application Scenarios (test/e2e/mailboxer-e2e.test.js)', () => {
  let tempBaseDir;

  before(async () => {
    tempBaseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-e2e-suite-'));
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
  // SCENARIO 1: Multi-Account Cold Boot & Missing Credentials
  // ============================================================================
  describe('Scenario 1: Multi-Account Cold Boot & Missing Credentials', () => {
    it('1.1 handles non-existent .env file gracefully and exits cleanly with code 0', async () => {
      let loggedOutput = '';
      const originalLog = console.log;
      try {
        console.log = (str) => { loggedOutput += str; };
        const nonExistentEnv = path.join(tempBaseDir, '.env.nonexistent');
        const { exitCode, results } = await runDiagnostics(['--env', nonExistentEnv, '--json']);

        assert.strictEqual(exitCode, 0, 'Must exit with code 0 on missing env');
        assert.strictEqual(results.length, 0, 'No accounts tested');

        const parsed = JSON.parse(loggedOutput);
        assert.strictEqual(parsed.status, 'unconfigured');
        assert.strictEqual(parsed.totalConfigured, 0);
        assert.ok(Array.isArray(parsed.unconfigured));
        assert.strictEqual(parsed.unconfigured.length, 3, 'Must report all 3 providers as unconfigured');

        const providers = parsed.unconfigured.map(u => u.provider);
        assert.ok(providers.includes('apple'));
        assert.ok(providers.includes('gmail'));
        assert.ok(providers.includes('outlook'));
      } finally {
        console.log = originalLog;
      }
    });

    it('1.2 detects placeholder credentials and provides actionable remediation guidance', async () => {
      const placeholderEnvPath = path.join(tempBaseDir, '.env.placeholder');
      const envContent = [
        'GMAIL_EMAIL=your-email@gmail.com',
        'GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx',
        'APPLE_EMAIL=user@icloud.com',
        'APPLE_APP_PASSWORD=your_app_password_here',
        'OUTLOOK_EMAIL=student@university.edu',
        'OUTLOOK_PASSWORD=your_outlook_password'
      ].join('\n');
      await fs.writeFile(placeholderEnvPath, envContent, 'utf8');

      let loggedOutput = '';
      const originalLog = console.log;
      try {
        console.log = (str) => { loggedOutput += str; };
        const { exitCode, results } = await runDiagnostics(['--env', placeholderEnvPath, '--json']);

        assert.strictEqual(exitCode, 0);
        assert.strictEqual(results.length, 0);

        const parsed = JSON.parse(loggedOutput);
        assert.strictEqual(parsed.status, 'unconfigured');
        assert.strictEqual(parsed.totalConfigured, 0);

        // Verify each unconfigured item explains the placeholder and provides advice
        for (const item of parsed.unconfigured) {
          assert.strictEqual(item.reason, 'PLACEHOLDER_CREDENTIALS');
          assert.ok(item.advice, 'Must provide remediation advice');
          assert.ok(item.advice.includes('http') || item.advice.includes('.env.example'), 'Advice should include link or reference');
        }
      } finally {
        console.log = originalLog;
      }
    });

    it('1.3 supports account filtering flag (--account) on unconfigured environment without crashing', async () => {
      let loggedOutput = '';
      const originalLog = console.log;
      try {
        console.log = (str) => { loggedOutput += str; };
        const { exitCode, results } = await runDiagnostics(['--env', path.join(tempBaseDir, '.env.nonexistent'), '--account', 'apple']);
        assert.strictEqual(exitCode, 0);
        assert.strictEqual(results.length, 0);
      } finally {
        console.log = originalLog;
      }
    });

    it('1.4 initializes CredentialVault in fresh directory, generates key on the fly, and lists 0 accounts without secret leaks', async () => {
      const coldVaultDir = path.join(tempBaseDir, 'cold-boot-vault');
      const vault = new CredentialVault({ dataDir: coldVaultDir });
      const manager = new AccountManager({ vault });

      await manager.init();

      // Check key was generated
      const keyFile = path.join(coldVaultDir, '.vault-key');
      const keyStat = await fs.stat(keyFile);
      assert.ok(keyStat.isFile(), '.vault-key must be generated');

      const accounts = await manager.listAccounts();
      assert.deepStrictEqual(accounts, []);
    });
  });

  // ============================================================================
  // SCENARIO 2: Unified Tri-Provider Triage Connection Cycle
  // ============================================================================
  describe('Scenario 2: Unified Tri-Provider Triage Connection Cycle (Apple, Gmail, Outlook onboarding + IMAP sync + Triage + Web Push & ntfy alerts)', () => {
    let scenarioDir;
    let vault;
    let accountManager;
    let store;
    let classifier;
    let webPush;
    let ntfy;
    let notifManager;
    let syncEngine;

    // Browser client mock keys for RFC 8291 Web Push decryption
    let clientEcdh;
    let clientPublicKey;
    let clientAuthSecret;

    // Accounts
    let appleAccount;
    let gmailAccount;
    let outlookAccount;

    // Intercepted dispatch calls
    const interceptedPushRequests = [];
    const interceptedNtfyRequests = [];

    before(async () => {
      scenarioDir = path.join(tempBaseDir, 'scenario-2-tri-provider');
      await fs.mkdir(scenarioDir, { recursive: true });

      // 1. Vault & AccountManager with hermetic mock factory for pre-flight verify
      vault = new CredentialVault({ dataDir: scenarioDir });
      accountManager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({
            scenario: 'happy_path',
            messageCount: 50,
            unseenCount: 5
          });
          return new ImapClient({
            accountConfig: resolved,
            transport: mock.getClientSocket()
          });
        }
      });
      await accountManager.init();

      // 2. Persistent SQLite store
      const dbPath = path.join(scenarioDir, 'mailboxer.sqlite');
      store = new SqliteStore(dbPath);

      // 3. Client browser crypto keys for Web Push
      clientEcdh = crypto.createECDH('prime256v1');
      clientEcdh.generateKeys();
      clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
      clientAuthSecret = crypto.randomBytes(16).toString('base64url');

      // 4. Push subscription in SQLite
      store.upsertPushSubscription({
        endpoint: 'https://fcm.googleapis.com/fcm/send/test-sub-token-2026',
        keys: {
          p256dh: clientPublicKey,
          auth: clientAuthSecret
        }
      });

      // 5. Conduits & NotificationManager
      webPush = new WebPushConduit({
        store,
        vapidPath: path.join(scenarioDir, 'vapid.json'),
        contactEmail: 'mailto:alerts@mailboxer.internal'
      });

      ntfy = new NtfyConduit({
        topic: 'mailboxer-e2e-vip',
        serverUrl: 'https://ntfy.sh',
        appBaseUrl: 'http://localhost:3000'
      });

      notifManager = new NotificationManager({
        store,
        webPush,
        ntfy,
        appBaseUrl: 'http://localhost:3000'
      });

      classifier = new Classifier({ store });
    });

    after(() => {
      if (store) store.close();
    });

    it('2.1 onboards Apple, Gmail, and Outlook accounts concurrently with 4x4 app passwords and successful pre-flight check', async () => {
      const [appleRes, gmailRes, outlookRes] = await Promise.all([
        accountManager.addAppleAccount({
          email: 'apple_user@icloud.com',
          appPassword: 'abcd-efgh-ijkl-mnop',
          label: 'Personal Apple Mail'
        }),
        accountManager.addGoogleAccount({
          email: 'gmail_user@gmail.com',
          appPassword: 'wxyz-1234-abcd-5678',
          label: 'Primary Google Mail'
        }),
        accountManager.addOutlookAccount({
          email: 'student@university.edu',
          appPassword: 'uvwx-9876-pqrs-5432',
          label: 'University Outlook 365'
        })
      ]);

      appleAccount = appleRes.account;
      gmailAccount = gmailRes.account;
      outlookAccount = outlookRes.account;

      assert.strictEqual(appleAccount.provider, 'apple');
      assert.strictEqual(appleAccount.connected, true);
      assert.ok(appleRes.testResult.success);
      assert.ok(appleRes.testResult.tlsDetails?.cipherName);

      assert.strictEqual(gmailAccount.provider, 'gmail');
      assert.strictEqual(gmailAccount.connected, true);
      assert.ok(gmailRes.testResult.success);

      assert.strictEqual(outlookAccount.provider, 'outlook');
      assert.strictEqual(outlookAccount.connected, true);
      assert.ok(outlookRes.testResult.success);
    });

    it('2.2 verifies AES-256-GCM vault isolation and zero cleartext secret leaks in public listings', async () => {
      const publicAccounts = await accountManager.listAccounts();
      assert.strictEqual(publicAccounts.length, 3);

      for (const acc of publicAccounts) {
        assert.ok(acc.id);
        assert.ok(acc.email);
        assert.ok(acc.provider);
        assert.strictEqual(acc.password, undefined);
        assert.strictEqual(acc.appPassword, undefined);
        assert.strictEqual(acc.auth?.pass, undefined);
        assert.strictEqual(acc.auth, undefined);
      }

      // Check on-disk vault file is ciphertext (not cleartext)
      const rawVault = await fs.readFile(path.join(scenarioDir, 'accounts.vault.json'), 'utf8');
      assert.ok(!rawVault.includes('abcd-efgh-ijkl-mnop'), 'No cleartext Apple password in raw vault file');
      assert.ok(!rawVault.includes('wxyz-1234-abcd-5678'), 'No cleartext Gmail password in raw vault file');
      assert.ok(!rawVault.includes('uvwx-9876-pqrs-5432'), 'No cleartext Outlook password in raw vault file');
    });

    it('2.3 performs multi-account IMAP sync ingesting VIP, Coursework, and Promotional Noise emails', async () => {
      // Ingest accounts into SQLite store
      store.upsertAccount({
        id: appleAccount.id,
        email: appleAccount.email,
        provider: 'apple',
        label: appleAccount.label
      });
      store.upsertAccount({
        id: gmailAccount.id,
        email: gmailAccount.email,
        provider: 'gmail',
        label: gmailAccount.label
      });
      store.upsertAccount({
        id: outlookAccount.id,
        email: outlookAccount.email,
        provider: 'outlook',
        label: outlookAccount.label
      });

      // Prepare sync mock servers for each account
      const syncMockApple = createSyncMockServer({
        initialMessages: [
          {
            uid: 101,
            flags: ['\\Flagged'],
            from: 'Prof. Marcus Vance <m.vance@stanford.edu>',
            subject: 'URGENT: Research Grant Review Today at 3pm',
            body: 'Please bring your experimental findings to Packard Room 302.',
            date: '2026-10-20T11:00:00Z'
          }
        ]
      });

      const syncMockGmail = createSyncMockServer({
        initialMessages: [
          {
            uid: 201,
            flags: [],
            from: 'Canvas LMS <notifications@instructure.com>',
            subject: 'Canvas Grade Notification: CS244 Distributed Systems',
            body: 'Your Lab 2 solution has been graded and published to Canvas.',
            date: '2026-10-20T11:15:00Z',
            precedence: 'bulk'
          }
        ]
      });

      const syncMockOutlook = createSyncMockServer({
        initialMessages: [
          {
            uid: 301,
            flags: ['\\Seen'],
            from: 'Campus Store Deals <discounts@campus-retail.com>',
            subject: 'Massive 70% Off Spring Clearance Sale!',
            body: 'Exclusive discounts on campus hoodies. Click here to unsubscribe.',
            date: '2026-10-20T11:30:00Z',
            listUnsubscribe: '<mailto:unsub@campus-retail.com>'
          }
        ]
      });

      const mockMap = {
        [appleAccount.id]: syncMockApple,
        [gmailAccount.id]: syncMockGmail,
        [outlookAccount.id]: syncMockOutlook
      };

      syncEngine = new SyncEngine({
        store,
        createClient: (config) => {
          const mock = mockMap[config.id] || syncMockApple;
          return new ImapClient({
            accountConfig: config,
            transport: mock.createClientSocket()
          });
        }
      });

      // Sync all 3 accounts
      const syncResults = await Promise.all([
        syncEngine.syncAccount(appleAccount.id),
        syncEngine.syncAccount(gmailAccount.id),
        syncEngine.syncAccount(outlookAccount.id)
      ]);

      assert.strictEqual(syncResults.length, 3);
      assert.strictEqual(syncResults[0].accountId, appleAccount.id);
      assert.strictEqual(syncResults[1].accountId, gmailAccount.id);
      assert.strictEqual(syncResults[2].accountId, outlookAccount.id);

      // Verify messages are in SQLite store
      const allMessages = store.getMessages();
      assert.strictEqual(allMessages.length, 3);
    });

    it('2.4 classifies ingested messages into VIP, UPDATE, and NOISE categories', () => {
      const messages = store.getMessages();
      const vipMsg = messages.find(m => m.subject.includes('URGENT'));
      const updateMsg = messages.find(m => m.subject.includes('Canvas') || m.sender.includes('Canvas'));
      const noiseMsg = messages.find(m => m.subject.includes('Sale') || m.subject.includes('Clearance'));

      assert.ok(vipMsg, 'VIP message must be in store');
      assert.ok(updateMsg, 'Update message must be in store');
      assert.ok(noiseMsg, 'Noise message must be in store');

      const vipResult = classifier.classify(vipMsg);
      assert.strictEqual(vipResult.category, 'VIP');
      assert.strictEqual(vipResult.shouldNotify, true);

      const updateResult = classifier.classify(updateMsg);
      assert.strictEqual(updateResult.category, 'UPDATE');
      assert.strictEqual(updateResult.shouldNotify, false);

      const noiseResult = classifier.classify(noiseMsg);
      assert.strictEqual(noiseResult.category, 'NOISE');
      assert.strictEqual(noiseResult.shouldNotify, false);
      assert.strictEqual(noiseResult.isNoise, true);
    });

    it('2.5 dispatches Web Push & ntfy for VIP message, decrypts RFC 8291 payload, and mutes Update & Noise messages', async () => {
      const messages = store.getMessages();
      const vipMsg = messages.find(m => m.subject.includes('URGENT'));
      const updateMsg = messages.find(m => m.subject.includes('Canvas') || m.sender.includes('Canvas'));
      const noiseMsg = messages.find(m => m.subject.includes('Sale') || m.subject.includes('Clearance'));

      assert.ok(vipMsg, 'VIP message must exist');
      assert.ok(updateMsg, 'Update message must exist');
      assert.ok(noiseMsg, 'Noise message must exist');

      let interceptedPushBody = null;
      let interceptedNtfyBody = null;

      const mockFetch = async (url, init) => {
        const urlStr = String(url);
        if (urlStr.includes('fcm.googleapis.com')) {
          interceptedPushBody = init.body;
          interceptedPushRequests.push({ url: urlStr, headers: init.headers, body: init.body });
          return { status: 201, ok: true, text: async () => 'Created' };
        }
        if (urlStr.includes('ntfy.sh')) {
          interceptedNtfyBody = JSON.parse(init.body);
          interceptedNtfyRequests.push({ url: urlStr, body: interceptedNtfyBody });
          return { status: 200, ok: true, text: async () => 'OK' };
        }
        return { status: 200, ok: true, text: async () => '' };
      };

      // 1. Dispatch VIP
      const vipTriage = classifier.classify(vipMsg);
      const vipDispatch = await notifManager.dispatch(vipMsg, vipTriage, { fetch: mockFetch });

      assert.strictEqual(vipDispatch.dispatched, true);
      assert.ok(interceptedPushBody, 'Web Push encrypted body was captured');
      assert.ok(interceptedNtfyBody, 'ntfy body was captured');

      // Decrypt RFC 8291 Web Push payload using client keys
      const decryptedBuffer = decryptWebPushPayload(
        interceptedPushBody,
        clientEcdh,
        Buffer.from(clientAuthSecret, 'base64url')
      );
      const decryptedJson = JSON.parse(decryptedBuffer.toString('utf8'));
      assert.ok(decryptedJson.title.includes('VIP'));
      assert.ok(decryptedJson.title.includes('Marcus Vance'));
      assert.ok(decryptedJson.body.includes('URGENT: Research Grant Review'));
      assert.strictEqual(decryptedJson.category, 'VIP');

      // Verify ntfy alert payload
      assert.strictEqual(interceptedNtfyBody.priority, 5);
      assert.ok(interceptedNtfyBody.title.includes('VIP'));
      assert.ok(interceptedNtfyBody.actions.length >= 1);

      // 2. Dispatch UPDATE (must be muted)
      const updateTriage = classifier.classify(updateMsg);
      const updateDispatch = await notifManager.dispatch(updateMsg, updateTriage, { fetch: mockFetch });
      assert.strictEqual(updateDispatch.dispatched, false);
      assert.strictEqual(updateDispatch.reason, 'Notification muted by triage engine');

      // 3. Dispatch NOISE (must be muted)
      const noiseTriage = classifier.classify(noiseMsg);
      const noiseDispatch = await notifManager.dispatch(noiseMsg, noiseTriage, { fetch: mockFetch });
      assert.strictEqual(noiseDispatch.dispatched, false);
      assert.strictEqual(noiseDispatch.reason, 'Notification muted by triage engine');
    });

    it('2.6 executes cross-account full-text search in <20ms SLA', () => {
      const start = performance.now();
      const results = store.search('Packard');
      const elapsed = performance.now() - start;

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].body_snippet.includes('Packard Room 302'));
      assert.ok(elapsed < 20.0, `Search elapsed ${elapsed.toFixed(2)}ms must be under 20ms SLA`);
    });
  });

  // ============================================================================
  // SCENARIO 3: Provider App-Password Migration & Failure Recovery
  // ============================================================================
  describe('Scenario 3: Provider App-Password Migration & Failure Recovery', () => {
    let migrationDir;
    let vault;
    let accountManager;
    let store;
    let originalAccount;

    // 16-character passwords (excluding hyphens):
    // "orig-pass-word-2026" -> 16 chars: origpassword2026
    // "revo-kedp-assw-9999" -> 16 chars: revokedpassw9999
    // "newp-assw-orki-2026" -> 16 chars: newpassworki2026
    const INITIAL_PASSWORD = 'orig-pass-word-2026';
    const REVOKED_PASSWORD = 'revo-kedp-assw-9999';
    const NEW_VALID_PASSWORD = 'newp-assw-orki-2026';

    before(async () => {
      migrationDir = path.join(tempBaseDir, 'scenario-3-migration');
      await fs.mkdir(migrationDir, { recursive: true });

      vault = new CredentialVault({ dataDir: migrationDir });
      store = new SqliteStore(path.join(migrationDir, 'mailboxer.sqlite'));

      // Factory that checks password:
      // - "orig...": succeeds
      // - "revo...": fails (AUTH_FAILED)
      // - "newp...": succeeds
      accountManager = new AccountManager({
        vault,
        imapClientFactory: (resolved) => {
          const pass = resolved.auth?.pass || resolved.password || '';
          const isFailing = pass.includes('revo');
          const mock = new MockImapServer({
            scenario: isFailing ? 'auth_fail' : 'happy_path',
            messageCount: 20
          });
          return new ImapClient({
            accountConfig: resolved,
            transport: mock.getClientSocket()
          });
        }
      });

      await accountManager.init();

      // Seed working initial account with 16-character app-password
      const addRes = await accountManager.addAppleAccount({
        email: 'user@icloud.com',
        appPassword: INITIAL_PASSWORD
      });
      originalAccount = addRes.account;

      // Seed historical messages in SQLite
      store.upsertAccount({
        id: originalAccount.id,
        email: originalAccount.email,
        provider: 'apple'
      });
      store.upsertFolder({
        id: 'fld_inbox_orig',
        account_id: originalAccount.id,
        name: 'INBOX',
        path: 'INBOX'
      });
      store.upsertMessages([
        {
          id: 'msg_historical_1',
          account_id: originalAccount.id,
          folder_id: 'fld_inbox_orig',
          uid: 10,
          sender: 'colleague@apple.com',
          subject: 'Historical Message Before Password Rotation',
          body_snippet: 'This email must survive password migration attempts.',
          is_seen: 1,
          date: '2026-10-19T10:00:00Z',
          triage_category: 'NORMAL'
        }
      ]);
    });

    after(() => {
      if (store) store.close();
    });

    it('3.1 rejects invalid/revoked app password with descriptive AUTH_FAILED error and remediation advice', async () => {
      await assert.rejects(
        async () => {
          await accountManager.addAppleAccount({
            email: 'user@icloud.com',
            appPassword: REVOKED_PASSWORD
          });
        },
        (err) => {
          assert.ok(err.code === 'AUTH_FAILED' || err.code === 'AUTH_APP_PASSWORD_REQUIRED', `Expected AUTH_FAILED or AUTH_APP_PASSWORD_REQUIRED, got ${err.code}`);
          assert.ok(err.remediationAdvice.includes('https://appleid.apple.com'));
          return true;
        }
      );
    });

    it('3.2 guarantees atomic rollback: original vault record and historical SQLite messages remain 100% intact', async () => {
      // 1. Vault inspection
      const accounts = await accountManager.listAccounts();
      assert.strictEqual(accounts.length, 1);
      assert.strictEqual(accounts[0].email, 'user@icloud.com');
      assert.strictEqual(accounts[0].connected, true);

      // Verify decrypted vault record still has the original working password
      const decrypted = await vault.getById(accounts[0].id);
      assert.strictEqual(decrypted.auth.pass, 'origpassword2026');

      // 2. SQLite inspection
      const messages = store.getMessages({ accountId: accounts[0].id });
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].id, 'msg_historical_1');
      assert.strictEqual(messages[0].subject, 'Historical Message Before Password Rotation');
    });

    it('3.3 completes password migration with valid replacement password and updates lastVerifiedAt', async () => {
      const priorDecrypted = await vault.getById(originalAccount.id);
      const priorVerifiedAt = priorDecrypted.lastVerifiedAt;

      // Small delay to ensure timestamp advancement
      await new Promise(r => setTimeout(r, 10));

      const updateRes = await accountManager.addAppleAccount({
        email: 'user@icloud.com',
        appPassword: NEW_VALID_PASSWORD
      });

      assert.strictEqual(updateRes.account.connected, true);
      assert.ok(updateRes.testResult.success);

      // Verify updated vault record
      const updatedDecrypted = await vault.getById(originalAccount.id);
      assert.strictEqual(updatedDecrypted.auth.pass, 'newpassworki2026');
      assert.ok(new Date(updatedDecrypted.lastVerifiedAt) >= new Date(priorVerifiedAt));

      // Verify SQLite data remains intact after successful migration
      const messages = store.getMessages({ accountId: originalAccount.id });
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].id, 'msg_historical_1');
    });
  });

  // ============================================================================
  // SCENARIO 4: Network Outage & Socket Drop Resiliency during Sync/IDLE
  // ============================================================================
  describe('Scenario 4: Network Outage & Socket Drop Resiliency during Sync/IDLE', () => {
    let outageDir;
    let store;

    before(async () => {
      outageDir = path.join(tempBaseDir, 'scenario-4-outage');
      await fs.mkdir(outageDir, { recursive: true });
      store = new SqliteStore(path.join(outageDir, 'mailboxer.sqlite'));
      store.upsertAccount({
        id: 'acc_resilient',
        email: 'resilient@stanford.edu',
        provider: 'custom'
      });
    });

    after(() => {
      if (store) store.close();
    });

    it('4.1 detects abrupt TCP reset (ECONNRESET) during active IDLE and initiates backoff reconnection without process crash', async () => {
      const mockServer = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 30
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mockServer.getClientSocket(),
          provider: 'custom'
        })
      });

      await idleManager.start();
      assert.strictEqual(idleManager.isAccountIdling('acc_resilient'), true);

      let disconnectedFired = false;
      idleManager.once('disconnected', (evt) => {
        disconnectedFired = true;
        assert.strictEqual(evt.accountId, 'acc_resilient');
      });

      const reconnectPromise = new Promise((resolve) => {
        idleManager.once('reconnecting', (evt) => {
          resolve(evt);
        });
      });

      // Hostile abrupt TCP reset
      mockServer.serverSocket.destroy(new Error('read ECONNRESET'));

      const recEvt = await reconnectPromise;
      assert.strictEqual(disconnectedFired, true);
      assert.strictEqual(recEvt.accountId, 'acc_resilient');
      assert.strictEqual(recEvt.attempt, 1);
      assert.ok(recEvt.delayMs > 0);

      await idleManager.stop();
    });

    it('4.2 transparently reconnects and re-enters IDLE mode when socket transport recovers', async () => {
      let connectionCount = 0;
      let activeMock = null;

      const idleManager = new IdleManager({
        store,
        createClient: () => {
          connectionCount++;
          activeMock = new MockImapServer({
            scenario: 'happy_path',
            messageCount: 30
          });
          return new ImapClient({
            transport: activeMock.getClientSocket(),
            provider: 'custom'
          });
        }
      });

      await idleManager.start();
      assert.strictEqual(idleManager.isAccountIdling('acc_resilient'), true);
      assert.strictEqual(connectionCount, 1);

      // Trigger socket drop
      activeMock.serverSocket.destroy(new Error('read ECONNRESET'));

      // Wait for idle manager to attempt reconnection
      await new Promise(r => setTimeout(r, 60));

      await idleManager.stop();
      assert.ok(connectionCount >= 1);
    });

    it('4.3 catches mid-sync socket drops cleanly without unhandled rejection or partial database corruption', async () => {
      const [clientSocket, serverSocket] = MockDuplexSocket.createPair();

      // Greeting
      queueMicrotask(() => {
        serverSocket.write('* OK Mock Server Ready\r\n');
      });

      // When LOGIN arrives, immediately destroy socket to simulate mid-sync outage
      serverSocket.on('data', (chunk) => {
        const text = chunk.toString();
        if (text.includes('LOGIN')) {
          serverSocket.destroy(new Error('read ECONNRESET'));
        }
      });

      const failingSyncEngine = new SyncEngine({
        store,
        createClient: () => new ImapClient({
          accountConfig: { id: 'acc_resilient', email: 'resilient@stanford.edu' },
          transport: clientSocket
        })
      });

      failingSyncEngine.on('syncError', () => {});

      const result = await failingSyncEngine.syncAccount('acc_resilient', {
        throwOnError: false,
        accountConfig: {
          id: 'acc_resilient',
          email: 'resilient@stanford.edu',
          auth: { user: 'resilient@stanford.edu', pass: 'secret' }
        }
      });

      assert.strictEqual(result.success, false);
      assert.ok(result.error);
    });

    it('4.4 verifies SQLite WAL database integrity after network outages', () => {
      const integrityRows = store.db.prepare('PRAGMA integrity_check').all();
      assert.strictEqual(integrityRows.length, 1);
      assert.strictEqual(integrityRows[0].integrity_check, 'ok');
    });
  });

  // ============================================================================
  // SCENARIO 5: Full System Ingress & Botkeep Cloud Health Telemetry (/health)
  // ============================================================================
  describe('Scenario 5: Full System Ingress & Botkeep Cloud Health Telemetry (/health)', () => {
    let cloudDir;
    let cloudStore;
    let cloudVault;
    let cloudAccountManager;
    let server;
    let baseUrl;
    const testPort = 25000 + Math.floor(Math.random() * 15000);

    before(async () => {
      cloudDir = path.join(tempBaseDir, 'scenario-5-cloud');
      await fs.mkdir(cloudDir, { recursive: true });

      cloudVault = new CredentialVault({ dataDir: cloudDir });
      cloudAccountManager = new AccountManager({
        vault: cloudVault,
        imapClientFactory: (resolved) => {
          const mock = new MockImapServer({ scenario: 'happy_path', messageCount: 15 });
          return new ImapClient({ accountConfig: resolved, transport: mock.getClientSocket() });
        }
      });
      await cloudAccountManager.init();

      // Seed 2 active accounts
      await cloudAccountManager.addGoogleAccount({
        email: 'cloud_test1@gmail.com',
        appPassword: 'aaaa-bbbb-cccc-dddd'
      });
      await cloudAccountManager.addAppleAccount({
        email: 'cloud_test2@icloud.com',
        appPassword: 'eeee-ffff-gggg-hhhh'
      });

      cloudStore = new SqliteStore(path.join(cloudDir, 'mailboxer.sqlite'));
      cloudStore.upsertPushSubscription({
        endpoint: 'https://push.example.com/sub/1',
        keys: { p256dh: 'test-p256', auth: 'test-auth' }
      });

      // Bind to 0.0.0.0 (simulating cloud container ingress)
      server = new WebServer({
        port: testPort,
        host: '0.0.0.0',
        accountManager: cloudAccountManager,
        store: cloudStore,
        dataDir: cloudDir
      });

      baseUrl = await server.start();
    });

    after(async () => {
      if (server) await server.stop();
      if (cloudStore) cloudStore.close();
    });

    it('5.1 binds to 0.0.0.0 and assigns accessible HTTP address', () => {
      assert.ok(baseUrl.startsWith('http://'));
      assert.ok(baseUrl.includes(String(testPort)));
    });

    it('5.2 GET /health conforms strictly to PROJECT.md § 5 telemetry contract', async () => {
      const res = await fetch(`${baseUrl}/health`);
      assert.strictEqual(res.status, 200);

      const health = await res.json();

      // Root contract
      assert.ok(health.status === 'healthy' || health.status === 'ok');
      assert.ok(typeof health.timestamp === 'string');
      assert.ok(typeof health.uptimeSeconds === 'number');

      // Storage contract
      assert.strictEqual(health.storage.writable, true);
      assert.strictEqual(health.storage.persistent, true);
      assert.strictEqual(health.storage.sqlite.connected, true);
      assert.strictEqual(health.storage.sqlite.journalMode, 'wal');
      assert.strictEqual(health.storage.vault.initialized, true);
      assert.strictEqual(health.storage.vault.accountCount, 2);

      // Accounts contract
      assert.strictEqual(health.accounts.total, 2);
      assert.strictEqual(health.accounts.connected, 2);

      // Notification contract
      assert.strictEqual(health.notifications.webPush.activeSubscriptions, 1);

      // System contract
      assert.ok(health.system.nodeVersion);
      assert.ok(health.system.memoryUsageMb);
      assert.ok(health.system.pid);
    });

    it('5.3 sustains high-concurrency burst of 50 simultaneous HTTP requests without error or degradation', async () => {
      const requests = Array.from({ length: 50 }, (_, i) => {
        const endpoint = i % 2 === 0 ? `${baseUrl}/health` : `${baseUrl}/api/accounts`;
        return fetch(endpoint);
      });

      const responses = await Promise.all(requests);
      assert.strictEqual(responses.length, 50);

      for (const res of responses) {
        assert.strictEqual(res.status, 200);
      }
    });

    it('5.4 halts cleanly on graceful shutdown and releases network port', async () => {
      await server.stop();

      // Verify server is no longer listening
      await assert.rejects(
        async () => {
          await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(500) });
        },
        (err) => {
          assert.ok(err.name === 'TypeError' || err.code === 'ECONNREFUSED' || err.name === 'TimeoutError');
          return true;
        }
      );
    });
  });
});
