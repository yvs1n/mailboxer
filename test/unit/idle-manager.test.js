/**
 * IMAP IDLE State Machine & IdleManager Unit Test Suite
 *
 * Verifies RFC 2177 IDLE protocol lifecycle, continuation line handshake,
 * unsolicited untagged event streaming (* <N> EXISTS), DONE termination,
 * 25-minute keepalive renewal, socket drop recovery with exponential backoff,
 * and adaptive polling fallback.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';
import { IdleManager } from '../../src/connection/idle-manager.js';
import { MockImapServer } from '../helpers/mock-socket.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

describe('Real-Time IMAP IDLE & IdleManager (src/connection/idle-manager.js)', () => {
  let store;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
  });

  afterEach(() => {
    store?.close();
  });

  function createTestPair(options = {}) {
    const mock = new MockImapServer({
      scenario: 'happy_path',
      messageCount: options.messageCount || 40,
      unseenCount: options.unseenCount || 2,
      ...options
    });
    const client = new ImapClient({
      transport: mock.getClientSocket(),
      provider: 'custom'
    });
    return { mock, client };
  }

  describe('1. RFC 2177 IDLE Protocol Lifecycle on ImapClient', () => {
    it('sends tagged IDLE command, receives continuation line + idling, and enters IDLE state', async () => {
      const { client } = createTestPair();
      await client.connect();
      await client.login('user@test.com', 'secret');
      await client.selectMailbox('INBOX');

      assert.equal(client.state, IMAP_STATES.QUERYING);

      let idleEmitted = false;
      client.once('idle', (data) => {
        idleEmitted = true;
        assert.ok(data.tag, 'Expected IDLE tag');
        assert.match(data.line, /\+\s*idling/i);
      });

      const res = await client.idle();

      assert.equal(client.state, IMAP_STATES.IDLE);
      assert.equal(idleEmitted, true);
      assert.ok(res.tag);

      await client.logout();
    });

    it('receives unsolicited * <N> EXISTS push notification while idling', async () => {
      const { mock, client } = createTestPair();
      await client.connect();
      await client.login('user@test.com', 'secret');
      await client.selectMailbox('INBOX');
      await client.idle();

      let existsCount = 0;
      const existsPromise = new Promise((resolve) => {
        client.once('exists', (count) => {
          existsCount = count;
          resolve(count);
        });
      });

      // Server pushes new email notification
      mock.pushExists(41);

      const receivedCount = await existsPromise;
      assert.equal(receivedCount, 41);
      assert.equal(existsCount, 41);

      await client.logout();
    });

    it('exits IDLE state cleanly via DONE\\r\\n and returns to AUTHENTICATED state', async () => {
      const { client } = createTestPair();
      await client.connect();
      await client.login('user@test.com', 'secret');
      await client.selectMailbox('INBOX');
      await client.idle();

      assert.equal(client.state, IMAP_STATES.IDLE);

      let idleDoneEmitted = false;
      client.once('idleDone', () => {
        idleDoneEmitted = true;
      });

      const doneRes = await client.done();
      assert.equal(doneRes.status, 'OK');
      assert.equal(client.state, IMAP_STATES.AUTHENTICATED);
      assert.equal(idleDoneEmitted, true);

      // Verify that standard commands can now be sent on the socket
      const statusRes = await client.getStatus('INBOX');
      assert.equal(statusRes.totalMessages, 40);

      await client.logout();
    });
  });

  describe('2. IdleManager Lifecycle & Keepalive Cycling', () => {
    it('starts monitoring an account with IDLE capability', async () => {
      const { mock } = createTestPair();
      store.upsertAccount({
        id: 'acc_idle',
        email: 'user@test.com',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        }),
        keepaliveIntervalMs: 50
      });

      let idleStarted = false;
      idleManager.once('idle', (evt) => {
        idleStarted = true;
        assert.equal(evt.accountId, 'acc_idle');
      });

      await idleManager.start();

      assert.equal(idleStarted, true);
      assert.equal(idleManager.isAccountIdling('acc_idle'), true);

      await idleManager.stop();
      assert.equal(idleManager.isAccountIdling('acc_idle'), false);
    });

    it('cycles keepalive renewal (DONE then re-IDLE) when keepalive interval fires', async () => {
      const { mock } = createTestPair();
      store.upsertAccount({
        id: 'acc_keepalive',
        email: 'user@test.com',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        }),
        keepaliveIntervalMs: 25 // 25ms rapid keepalive
      });

      const keepalivePromise = new Promise((resolve) => {
        idleManager.once('keepalive', (evt) => {
          resolve(evt);
        });
      });

      await idleManager.start();
      const evt = await keepalivePromise;

      assert.equal(evt.accountId, 'acc_keepalive');
      assert.ok(evt.timestamp);
      assert.equal(idleManager.isAccountIdling('acc_keepalive'), true);

      await idleManager.stop();
    });
  });

  describe('3. Adaptive Polling Fallback', () => {
    it('falls back to adaptive polling when server capability lacks IDLE', async () => {
      const nonIdleServer = new MockImapServer({
        scenario: 'happy_path',
        greeting: '* OK [CAPABILITY IMAP4rev1 UNSELECT NAMESPACE] Mailboxer Mock Server Ready\r\n',
        messageCount: 25
      });

      store.upsertAccount({
        id: 'acc_polling',
        email: 'student@uni.edu',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: nonIdleServer.getClientSocket(),
          provider: 'custom'
        }),
        pollIntervalMs: 20
      });

      let pollingFallbackEmitted = false;
      idleManager.once('pollingFallback', (evt) => {
        pollingFallbackEmitted = true;
        assert.equal(evt.accountId, 'acc_polling');
      });

      await idleManager.start();

      assert.equal(pollingFallbackEmitted, true);
      assert.equal(idleManager.isAccountPolling('acc_polling'), true);
      assert.equal(idleManager.isAccountIdling('acc_polling'), false);

      const status = idleManager.getStatus();
      assert.equal(status.pollingAccounts, 1);
      assert.equal(status.idleAccounts, 0);

      await idleManager.stop();
    });
  });

  describe('4. Socket Drop Recovery with Backoff', () => {
    it('detects abrupt socket disconnection and schedules exponential backoff reconnection', async () => {
      const { mock } = createTestPair();
      store.upsertAccount({
        id: 'acc_reconnect',
        email: 'user@test.com',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        })
      });

      await idleManager.start();
      assert.equal(idleManager.isAccountIdling('acc_reconnect'), true);

      const reconnectPromise = new Promise((resolve) => {
        idleManager.once('reconnecting', (evt) => {
          resolve(evt);
        });
      });

      // Simulate abrupt network drop
      mock.serverSocket.destroy(new Error('read ECONNRESET'));

      const reconnectEvt = await reconnectPromise;
      assert.equal(reconnectEvt.accountId, 'acc_reconnect');
      assert.equal(reconnectEvt.attempt, 1);
      assert.ok(reconnectEvt.delayMs > 0, 'Expected positive backoff delay with jitter');

      await idleManager.stop();
    });
  });
});
