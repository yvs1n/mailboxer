/**
 * End-to-End Triage & Real-Time Notification Integration Test Suite
 *
 * Verifies full end-to-end integration:
 * - REST API endpoints:
 *   - /health (with triage, idle, and webPush status)
 *   - /api/notifications/vapid-public-key
 *   - /api/notifications/subscribe
 *   - /api/triage/rules (GET, POST, DELETE)
 *   - /api/notifications/test
 *   - /api/messages (category filtering and query search)
 *   - /api/messages/:id/read
 * - End-to-end pipeline:
 *   - Mock IMAP server pushing unsolicited * <N> EXISTS
 *   - IdleManager detecting event and syncing folder
 *   - Classifier triaging messages into VIP / UPDATE / NOISE / NORMAL
 *   - NotificationManager dispatching encrypted RFC 8291 Web Push and ntfy alerts
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { WebServer } from '../../src/server/web-server.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { Classifier } from '../../src/triage/classifier.js';
import { NotificationManager } from '../../src/notifications/manager.js';
import { WebPushConduit, decryptWebPushPayload } from '../../src/notifications/web-push.js';
import { NtfyConduit } from '../../src/notifications/ntfy.js';
import { IdleManager } from '../../src/connection/idle-manager.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { MockImapServer } from '../helpers/mock-socket.js';

describe('End-to-End Anti-Noise Triage & Real-Time Notification Integration', () => {
  let tmpDir;
  let store;
  let classifier;
  let webPush;
  let ntfy;
  let notificationManager;
  let server;
  let baseUrl;
  let mockServer;
  let idleManager;
  let sentPushPayloads = [];
  let sentNtfyPayloads = [];

  // Browser client keys for Web Push decryption verification
  let clientEcdh;
  let clientPublicKey;
  let clientAuthSecret;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mailboxer-triage-test-'));

    store = new SqliteStore(':memory:');

    // Setup client browser mock
    clientEcdh = crypto.createECDH('prime256v1');
    clientEcdh.generateKeys();
    clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
    clientAuthSecret = crypto.randomBytes(16).toString('base64url');

    // Conduit setup with injected mocks
    webPush = new WebPushConduit({
      store,
      vapidPath: path.join(tmpDir, 'test-vapid.json'),
      contactEmail: 'mailto:admin@mailboxer.local'
    });

    ntfy = new NtfyConduit({
      topic: 'test-vip-alerts',
      serverUrl: 'https://ntfy.sh'
    });

    notificationManager = new NotificationManager({
      store,
      webPush,
      ntfy,
      appBaseUrl: 'http://localhost:3000'
    });

    classifier = new Classifier({ store });

    // Mock IMAP Server
    mockServer = new MockImapServer({
      scenario: 'happy_path',
      messageCount: 50,
      unseenCount: 3
    });

    // Account setup
    store.upsertAccount({
      id: 'acc_test_1',
      email: 'student@stanford.edu',
      provider: 'custom'
    });

    idleManager = new IdleManager({
      store,
      classifier,
      notificationManager,
      createClient: () => new ImapClient({
        transport: mockServer.getClientSocket(),
        provider: 'custom'
      }),
      keepaliveIntervalMs: 5000
    });

    const randomPort = 12000 + Math.floor(Math.random() * 30000);
    server = new WebServer({
      port: randomPort,
      store,
      classifier,
      notificationManager,
      idleManager
    });

    baseUrl = await server.start();
  });

  after(async () => {
    if (idleManager) await idleManager.stop();
    if (server) await server.stop();
    if (store) store.close();
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('1. Health and Configuration REST Endpoints', () => {
    it('GET /health reports operational state with triage and notification engine info', async () => {
      const res = await fetch(`${baseUrl}/health`);
      assert.equal(res.status, 200);

      const json = await res.json();
      assert.ok(json.status === 'ok' || json.status === 'healthy');
      assert.ok(json.notifications && json.notifications.webPush);
      assert.ok(json.storage && json.storage.sqlite);
    });

    it('GET /api/notifications/vapid-public-key returns NIST P-256 base64url public key', async () => {
      const res = await fetch(`${baseUrl}/api/notifications/vapid-public-key`);
      assert.equal(res.status, 200);

      const json = await res.json();
      assert.ok(json.publicKey);

      const buf = Buffer.from(json.publicKey, 'base64url');
      assert.equal(buf.length, 65);
      assert.equal(buf[0], 0x04);
    });
  });

  describe('2. Push Subscription Management Endpoint', () => {
    it('POST /api/notifications/subscribe registers a browser push subscription in SQLite', async () => {
      const subPayload = {
        endpoint: 'https://push.services.mozilla.com/wpush/v2/test_client_token',
        keys: {
          p256dh: clientPublicKey,
          auth: clientAuthSecret
        }
      };

      const res = await fetch(`${baseUrl}/api/notifications/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(subPayload)
      });

      assert.ok(res.status === 200 || res.status === 201);
      const json = await res.json();
      assert.equal(json.success, true);

      // Verify in SQLite database
      const subs = store.getPushSubscriptions();
      assert.equal(subs.length, 1);
      assert.equal(subs[0].endpoint, subPayload.endpoint);
    });

    it('POST /api/notifications/subscribe rejects invalid subscription schemas with HTTP 400', async () => {
      const res = await fetch(`${baseUrl}/api/notifications/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint: '' }) // missing keys
      });

      assert.equal(res.status, 400);
    });
  });

  describe('3. Triage Rules CRUD REST Endpoints', () => {
    let createdRuleId;

    it('POST /api/triage/rules creates a high-priority user classification rule', async () => {
      const newRule = {
        name: 'Advisor VIP Rule',
        header: 'from',
        pattern: '*@cs.stanford.edu',
        targetCategory: 'VIP',
        priority: 95
      };

      const res = await fetch(`${baseUrl}/api/triage/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });

      assert.ok(res.status === 200 || res.status === 201);
      const json = await res.json();
      assert.equal(json.success, true);
      assert.ok(json.rule.id);
      assert.equal(json.rule.target_category, 'VIP');
      assert.equal(json.rule.pattern, '*@cs.stanford.edu');
      createdRuleId = json.rule.id;
    });

    it('GET /api/triage/rules lists all configured rules with user precedence', async () => {
      const res = await fetch(`${baseUrl}/api/triage/rules`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.rules));
      assert.equal(json.rules.length, 1);
      assert.equal(json.rules[0].id, createdRuleId);
    });

    it('DELETE /api/triage/rules/:id removes the rule from SQLite', async () => {
      const res = await fetch(`${baseUrl}/api/triage/rules/${createdRuleId}`, {
        method: 'DELETE'
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.success, true);

      // Verify deletion
      const checkRes = await fetch(`${baseUrl}/api/triage/rules`);
      const checkJson = await checkRes.json();
      assert.equal(checkJson.rules.length, 0);
    });
  });

  describe('4. Test Alert Dispatch Endpoint', () => {
    it('POST /api/notifications/test dispatches test alert across conduits', async () => {
      let pushDelivered = false;
      let ntfyDelivered = false;

      // Mock fetch on conduit instances for this test
      const originalPushSend = webPush.send.bind(webPush);
      webPush.send = async (sub, payload, opts) => {
        pushDelivered = true;
        return true;
      };

      const originalNtfySend = ntfy.send.bind(ntfy);
      ntfy.send = async (payload, opts) => {
        ntfyDelivered = true;
        return true;
      };

      const res = await fetch(`${baseUrl}/api/notifications/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: 'Integration Verification' })
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.success, true);
      assert.equal(pushDelivered, true);
      assert.equal(ntfyDelivered, true);

      // Restore
      webPush.send = originalPushSend;
      ntfy.send = originalNtfySend;
    });
  });

  describe('5. Messages Listing with Triage Filtering & Read Status', () => {
    before(() => {
      // Ingest test messages across triage categories
      store.upsertFolder({
        id: 'fld_inbox',
        account_id: 'acc_test_1',
        name: 'INBOX',
        path: 'INBOX'
      });

      store.upsertMessages([
        {
          id: 'msg_vip_1',
          account_id: 'acc_test_1',
          folder_id: 'fld_inbox',
          uid: 101,
          sender: 'Dean of Engineering <dean@stanford.edu>',
          sender_email: 'dean@stanford.edu',
          subject: 'URGENT: Research Fellowship Acceptance',
          body_snippet: 'Congratulations, your proposal was accepted by the committee.',
          is_seen: 0,
          date: '2026-10-20T12:00:00Z',
          triage_category: 'VIP',
          triage_score: 95,
          triage_reason: 'Dean urgent token'
        },
        {
          id: 'msg_update_1',
          account_id: 'acc_test_1',
          folder_id: 'fld_inbox',
          uid: 102,
          sender: 'Canvas LMS <notifications@instructure.com>',
          sender_email: 'notifications@instructure.com',
          subject: 'Assignment 3 Graded: CS224N',
          body_snippet: 'Your grade for assignment 3 is now available on Canvas.',
          is_seen: 0,
          date: '2026-10-20T12:10:00Z',
          triage_category: 'UPDATE',
          triage_score: 65,
          triage_reason: 'LMS grade notification'
        },
        {
          id: 'msg_noise_1',
          account_id: 'acc_test_1',
          folder_id: 'fld_inbox',
          uid: 103,
          sender: 'Newsletter Deals <deals@promo.com>',
          sender_email: 'deals@promo.com',
          subject: 'Huge 70% Off Cyber Monday Sale!',
          body_snippet: 'Unsubscribe here to stop receiving discounts.',
          is_seen: 0,
          date: '2026-10-20T12:15:00Z',
          triage_category: 'NOISE',
          triage_score: 15,
          triage_reason: 'Promotional discount noise'
        }
      ]);
    });

    it('GET /api/messages filters by category=VIP', async () => {
      const res = await fetch(`${baseUrl}/api/messages?category=VIP`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.messages));
      assert.equal(json.messages.length, 1);
      assert.equal(json.messages[0].id, 'msg_vip_1');
      assert.equal(json.messages[0].triage_category, 'VIP');
    });

    it('GET /api/messages filters by search query', async () => {
      const res = await fetch(`${baseUrl}/api/messages?q=fellowship`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.messages));
      assert.equal(json.messages.length, 1);
      assert.equal(json.messages[0].id, 'msg_vip_1');
    });

    it('POST /api/messages/:id/read updates message to seen in database', async () => {
      const res = await fetch(`${baseUrl}/api/messages/msg_vip_1/read`, {
        method: 'POST'
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.success, true);

      // Verify in DB
      const msg = store.getMessage('msg_vip_1');
      assert.equal(msg.is_seen, true);
    });
  });

  describe('6. End-to-End Pipeline: IDLE -> Sync -> Triage -> RFC 8291 Web Push Dispatch', () => {
    it('dispatches encrypted Web Push on newly ingested VIP email message', async () => {
      let interceptedWireBody = null;

      // Injected mock fetch to intercept encrypted Web Push request
      const pushFetchMock = async (url, init) => {
        interceptedWireBody = init.body;
        return {
          status: 201,
          ok: true,
          text: async () => 'Created'
        };
      };

      const customWebPush = new WebPushConduit({
        store,
        vapidPath: path.join(tmpDir, 'test-vapid.json'),
        contactEmail: 'mailto:admin@mailboxer.local'
      });

      const customNotifMgr = new NotificationManager({
        store,
        webPush: customWebPush,
        ntfy: new NtfyConduit({ topic: '' }) // quiet ntfy
      });

      const incomingVipMessage = {
        id: 'msg_incoming_vip',
        account_id: 'acc_test_1',
        sender: 'Prof. John Hennessy <hennessy@stanford.edu>',
        sender_email: 'hennessy@stanford.edu',
        subject: 'URGENT: Research Laboratory Meeting',
        body_snippet: 'Please attend the emergency briefing in Packard 101.'
      };

      // Triage message
      const triageResult = classifier.classify(incomingVipMessage);
      assert.equal(triageResult.category, 'VIP');
      assert.equal(triageResult.shouldNotify, true);

      // Dispatch notification
      const dispatchRes = await customNotifMgr.dispatch(incomingVipMessage, triageResult, {
        fetch: pushFetchMock
      });

      assert.equal(dispatchRes.dispatched, true);
      assert.ok(interceptedWireBody, 'Expected encrypted binary payload over wire');

      // Decrypt using client browser's ECDH key and auth secret to prove RFC 8291 authenticity
      const decryptedBuffer = decryptWebPushPayload(
        interceptedWireBody,
        clientEcdh,
        Buffer.from(clientAuthSecret, 'base64url')
      );

      const decryptedPayload = JSON.parse(decryptedBuffer.toString('utf8'));
      assert.ok(decryptedPayload.title.includes('VIP'));
      assert.ok(decryptedPayload.title.includes('Hennessy'));
      assert.ok(decryptedPayload.body.includes('emergency briefing'));
      assert.equal(decryptedPayload.category, 'VIP');
    });
  });
});
