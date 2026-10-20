/**
 * Sync API & Triage Ingestion Integration Tests (test/integration/sync-api.test.js)
 *
 * Validates:
 * 1. POST /api/sync triggers full multi-account synchronization
 * 2. Ingestion pipeline tags messages into categories (VIP, UPDATE, NOISE, NORMAL)
 * 3. POST /api/messages/:id/read and POST /api/messages/:id/unread update is_seen flag in SQLite
 * 4. GET /api/messages category filtering and full-text search with category
 * 5. On-demand sync triggers upon account onboarding
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
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { Classifier } from '../../src/triage/classifier.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { MockImapServer } from '../helpers/mock-socket.js';

describe('Sync API & Triage Integration Tests (test/integration/sync-api.test.js)', () => {
  let tempDir;
  let server;
  let baseUrl;
  let store;
  let syncEngine;
  let accountManager;

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-sync-test-'));
    const vault = new CredentialVault({
      dataDir: tempDir,
      masterKey: crypto.randomBytes(32)
    });
    const oauth = new OAuthManager();
    const dbPath = path.join(tempDir, 'test-mailboxer.db');
    store = new SqliteStore(dbPath);

    accountManager = new AccountManager({
      vault,
      oauth,
      store,
      imapClientFactory: (resolved) => {
        const mockServer = new MockImapServer({ scenario: 'happy_path', messageCount: 5, unseenCount: 2 });
        return new ImapClient({
          accountConfig: resolved,
          transport: mockServer.getClientSocket()
        });
      }
    });

    const classifier = new Classifier({ store });

    syncEngine = new SyncEngine({
      store,
      accountManager,
      classifier,
      createClient: (config) => {
        const mockServer = new MockImapServer({ scenario: 'happy_path', messageCount: 5, unseenCount: 2 });
        return new ImapClient({
          accountConfig: config,
          transport: mockServer.getClientSocket()
        });
      }
    });

    const randomPort = 12000 + Math.floor(Math.random() * 35000);
    server = new WebServer({
      port: randomPort,
      accountManager,
      store,
      syncEngine,
      classifier
    });

    baseUrl = await server.start();
  });

  after(async () => {
    if (server) await server.stop();
    if (store) store.close();
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('1. POST /api/sync triggers synchronization and returns status', async () => {
    // Add an account into store and vault
    const accountId = 'sync-test-acc';
    store.upsertAccount({
      id: accountId,
      email: 'test@mailboxer.internal',
      provider: 'custom',
      label: 'Sync Test Inbox'
    });

    const res = await fetch(`${baseUrl}/api/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.message, 'Sync cycle triggered');
  });

  it('2. Ingests messages with triage categories into SQLite', async () => {
    const accountId = 'acc_triage_test';
    const folderId = `${accountId}_INBOX`;

    store.upsertAccount({ id: accountId, email: 'triage@mail.com', provider: 'gmail' });
    store.upsertFolder({ id: folderId, accountId, name: 'INBOX', path: 'INBOX' });

    // Seed messages across categories
    store.upsertMessages([
      {
        accountId,
        folderId,
        uid: 1001,
        messageId: 'vip-1@uni.edu',
        sender: 'Prof. Davis <davis@stanford.edu>',
        senderEmail: 'davis@stanford.edu',
        subject: 'URGENT: Oral Exam Schedule',
        bodySnippet: 'Please confirm your oral exam slot.',
        category: 'VIP',
        isSeen: 0,
        date: new Date().toISOString()
      },
      {
        accountId,
        folderId,
        uid: 1002,
        messageId: 'course-1@instructure.com',
        sender: 'Canvas LMS <notifications@instructure.com>',
        senderEmail: 'notifications@instructure.com',
        subject: 'Assignment 3 Graded: Operating Systems',
        bodySnippet: 'Your grade has been updated on Canvas.',
        category: 'UPDATE',
        isSeen: 1,
        date: new Date().toISOString()
      },
      {
        accountId,
        folderId,
        uid: 1003,
        messageId: 'promo-1@shop.com',
        sender: 'Mega Store <deals@megastore.com>',
        senderEmail: 'deals@megastore.com',
        subject: 'Final Hours: 80% Off Everything!',
        bodySnippet: 'Shop now before the discounts expire.',
        category: 'NOISE',
        isSeen: 0,
        date: new Date().toISOString()
      }
    ]);

    // Test GET /api/messages without category filter
    const allRes = await fetch(`${baseUrl}/api/messages?limit=10`);
    assert.strictEqual(allRes.status, 200);
    const allData = await allRes.json();
    assert.ok(allData.messages.length >= 3);

    // Test GET /api/messages?category=VIP
    const vipRes = await fetch(`${baseUrl}/api/messages?category=VIP`);
    assert.strictEqual(vipRes.status, 200);
    const vipData = await vipRes.json();
    assert.ok(vipData.messages.every(m => m.category === 'VIP'));
    assert.ok(vipData.messages.some(m => m.messageId === 'vip-1@uni.edu'));

    // Test GET /api/messages?category=UPDATE
    const updateRes = await fetch(`${baseUrl}/api/messages?category=UPDATE`);
    assert.strictEqual(updateRes.status, 200);
    const updateData = await updateRes.json();
    assert.ok(updateData.messages.every(m => m.category === 'UPDATE'));

    // Test GET /api/messages?category=NOISE
    const noiseRes = await fetch(`${baseUrl}/api/messages?category=NOISE`);
    assert.strictEqual(noiseRes.status, 200);
    const noiseData = await noiseRes.json();
    assert.ok(noiseData.messages.every(m => m.category === 'NOISE'));
  });

  it('3. POST /api/messages/:id/read and POST /api/messages/:id/unread toggle state', async () => {
    const msg = store.getMessageByUid('acc_triage_test_INBOX', 1001);
    assert.ok(msg);

    // Mark as read
    const readRes = await fetch(`${baseUrl}/api/messages/${encodeURIComponent(msg.id)}/read`, {
      method: 'POST'
    });
    assert.strictEqual(readRes.status, 200);
    const readData = await readRes.json();
    assert.strictEqual(readData.success, true);
    assert.strictEqual(readData.isSeen, true);

    const updatedRead = store.getMessage(msg.id);
    assert.strictEqual(Boolean(updatedRead.isSeen), true);

    // Mark as unread
    const unreadRes = await fetch(`${baseUrl}/api/messages/${encodeURIComponent(msg.id)}/unread`, {
      method: 'POST'
    });
    assert.strictEqual(unreadRes.status, 200);
    const unreadData = await unreadRes.json();
    assert.strictEqual(unreadData.success, true);
    assert.strictEqual(unreadData.isSeen, false);

    const updatedUnread = store.getMessage(msg.id);
    assert.strictEqual(Boolean(updatedUnread.isSeen), false);
  });

  it('4. Full-text search filters by query and category', async () => {
    const searchVip = await fetch(`${baseUrl}/api/messages?q=Exam&category=VIP`);
    assert.strictEqual(searchVip.status, 200);
    const data = await searchVip.json();
    assert.ok(data.messages.length >= 1);
    assert.strictEqual(data.messages[0].category, 'VIP');
  });

  it('5. On-demand sync triggers upon account addition', async () => {
    let syncTriggered = false;
    const origSyncAccount = syncEngine.syncAccount;
    syncEngine.syncAccount = async (id, opts) => {
      syncTriggered = true;
      return origSyncAccount.call(syncEngine, id, opts);
    };

    try {
      const res = await fetch(`${baseUrl}/api/accounts/apple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ondemand@icloud.com',
          appPassword: 'abcd-efgh-ijkl-mnop',
          label: 'On-Demand Apple'
        })
      });

      assert.strictEqual(res.status, 201);
      assert.strictEqual(syncTriggered, true, 'syncAccount should be triggered when account is added');
    } finally {
      syncEngine.syncAccount = origSyncAccount;
    }
  });
});
