/**
 * Adversarial Stress & Chaos Test Suite: Milestone 3 IDLE & Notification Conduits
 *
 * Rigorously stress-tests:
 * 1. IDLE chaos: abrupt connection abort (ECONNRESET, socket.end), unsolicited EXISTS spam,
 *    server BAD/NO responses to IDLE & DONE, keepalive timeout renewal and clock drift resilience.
 * 2. Adaptive polling fallback: server lacking IDLE capability, diurnal active/night shift,
 *    server failures during status polling.
 * 3. Web Push & ntfy chaos: expired push subscription (HTTP 410 Gone / 404 Not Found) auto-cleanup
 *    from SQLite, network failures (ECONNREFUSED, timeouts, 503), concurrent multi-alert flooding.
 * 4. Process crash defense: verifies notification dispatch errors never crash the sync engine,
 *    idle manager, or server.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';
import { IdleManager, IDLE_CONSTANTS } from '../../src/connection/idle-manager.js';
import { MockDuplexSocket, MockImapServer } from '../helpers/mock-socket.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { WebPushConduit, generateVapidKeys } from '../../src/notifications/web-push.js';
import { NtfyConduit } from '../../src/notifications/ntfy.js';
import { NotificationManager } from '../../src/notifications/manager.js';
import { ERROR_CODES } from '../../src/errors/taxonomy.js';

describe('Milestone 3 Adversarial Chaos: IDLE & Notification Conduits', () => {
  let store;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
  });

  afterEach(() => {
    store?.close();
  });

  function createMockPair(options = {}) {
    const mock = new MockImapServer({
      scenario: 'happy_path',
      messageCount: options.messageCount || 30,
      unseenCount: options.unseenCount || 2,
      ...options
    });
    const client = new ImapClient({
      transport: mock.getClientSocket(),
      provider: 'custom',
      commandTimeoutMs: options.commandTimeoutMs || 5000
    });
    return { mock, client };
  }

  // ==========================================================================
  // VECTOR 1: IDLE Chaos & Hostile Wire Conditions
  // ==========================================================================
  describe('Vector 1: IDLE Chaos & Hostile Wire Conditions', () => {

    it('handles abrupt TCP connection abort (ECONNRESET) while in IDLE state without unhandled rejection', async () => {
      const { mock } = createMockPair();
      store.upsertAccount({
        id: 'acc_abort',
        email: 'victim@test.local',
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
      assert.equal(idleManager.isAccountIdling('acc_abort'), true);

      let disconnectedFired = false;
      idleManager.once('disconnected', (evt) => {
        disconnectedFired = true;
        assert.equal(evt.accountId, 'acc_abort');
        assert.equal(evt.mode, 'IDLE');
      });

      const reconnectPromise = new Promise((resolve) => {
        idleManager.once('reconnecting', (evt) => {
          resolve(evt);
        });
      });

      // Hostile abrupt TCP abort
      mock.serverSocket.destroy(new Error('read ECONNRESET'));

      const recEvt = await reconnectPromise;
      assert.equal(disconnectedFired, true);
      assert.equal(recEvt.accountId, 'acc_abort');
      assert.equal(recEvt.attempt, 1);
      assert.ok(recEvt.delayMs > 0);

      await idleManager.stop();
      assert.equal(idleManager.isAccountIdling('acc_abort'), false);
    });

    it('handles abrupt connection termination (destroy without error) while in IDLE state', async () => {
      const { mock } = createMockPair();
      store.upsertAccount({
        id: 'acc_fin',
        email: 'fin@test.local',
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
      assert.equal(idleManager.isAccountIdling('acc_fin'), true);

      const reconnectPromise = new Promise((resolve) => {
        idleManager.once('reconnecting', (evt) => {
          resolve(evt);
        });
      });

      // Remote server terminates socket abruptly without error argument
      mock.serverSocket.destroy();

      const recEvt = await reconnectPromise;
      assert.equal(recEvt.accountId, 'acc_fin');

      await idleManager.stop();
    });

    it('survives unsolicited * <N> EXISTS spam burst (50 rapid untagged events + EXPUNGE + FETCH)', async () => {
      const { mock, client } = createMockPair({ messageCount: 10 });
      await client.connect();
      await client.login('spam@test.local', 'secret');
      await client.selectMailbox('INBOX');
      await client.idle();

      assert.equal(client.state, IMAP_STATES.IDLE);

      const receivedExists = [];
      const receivedExpunge = [];
      const receivedFetch = [];

      client.on('exists', (count) => receivedExists.push(count));
      client.on('expunge', (seq) => receivedExpunge.push(seq));
      client.on('fetch', (seq) => receivedFetch.push(seq));

      // Blast 50 rapid EXISTS and mixed untagged lines in a single write buffer
      let burstPayload = '';
      for (let i = 11; i <= 60; i++) {
        burstPayload += `* ${i} EXISTS\r\n`;
        if (i % 10 === 0) {
          burstPayload += `* ${i - 1} EXPUNGE\r\n`;
          burstPayload += `* ${i} FETCH (FLAGS (\\Seen))\r\n`;
        }
      }

      mock.serverSocket.write(burstPayload);

      // Wait a microtask loop for line drain
      await new Promise(r => setTimeout(r, 60));

      assert.equal(receivedExists.length, 50, 'Expected 50 EXISTS events processed');
      assert.equal(receivedExists[receivedExists.length - 1], 60, 'Final count must be 60');
      assert.equal(receivedExpunge.length, 5, 'Expected 5 EXPUNGE events');
      assert.equal(receivedFetch.length, 5, 'Expected 5 FETCH events');
      assert.equal(client.state, IMAP_STATES.IDLE, 'Must remain safely in IDLE');

      // Verify clean DONE exit after spam
      const doneRes = await client.done();
      assert.equal(doneRes.status, 'OK');
      assert.equal(client.state, IMAP_STATES.AUTHENTICATED);

      await client.logout();
    });

    it('rejects cleanly and transitions state when server sends BAD in response to IDLE', async () => {
      const { mock, client } = createMockPair();
      await client.connect();
      await client.login('bad@test.local', 'secret');
      await client.selectMailbox('INBOX');

      // Intercept IDLE command with hostile BAD response
      mock.onCommand(({ cmd, tag, server }) => {
        if (cmd === 'IDLE') {
          server.serverSocket.write(`${tag} BAD [CLIENTBUG] IDLE is not permitted on this folder\r\n`);
          return true;
        }
        return false;
      });

      await assert.rejects(
        async () => {
          await client.idle();
        },
        (err) => {
          assert.equal(err.code, ERROR_CODES.PROTOCOL_VIOLATION);
          assert.match(err.message, /IDLE is not permitted/i);
          return true;
        }
      );

      // Client must stay in QUERYING state (mailbox selected) and not hang
      assert.equal(client.state, IMAP_STATES.QUERYING);
      assert.equal(client.isAuthenticated, true);

      await client.logout();
    });

    it('rejects cleanly and returns to AUTHENTICATED when server sends NO in response to DONE', async () => {
      const { mock, client } = createMockPair();
      await client.connect();
      await client.login('done_no@test.local', 'secret');
      await client.selectMailbox('INBOX');
      await client.idle();

      assert.equal(client.state, IMAP_STATES.IDLE);

      // Intercept DONE with NO response
      mock.onCommand(({ rawLine, server }) => {
        if (rawLine.trim().toUpperCase() === 'DONE') {
          server.serverSocket.write(`${client._idleTag} NO [CANNOT] Mailbox synchronization lock failed\r\n`);
          return true;
        }
        return false;
      });

      await assert.rejects(
        async () => {
          await client.done();
        },
        (err) => {
          assert.match(err.message, /Mailbox synchronization lock failed/i);
          return true;
        }
      );

      // Must have reset _idleTag and returned to AUTHENTICATED
      assert.equal(client.state, IMAP_STATES.AUTHENTICATED);
      assert.equal(client._idleTag, null);

      await client.logout();
    });

    it('handles keepalive timeout renewal and recovers from silent server freeze on DONE', async () => {
      const { mock, client } = createMockPair();
      await client.connect();
      await client.login('freeze@test.local', 'secret');
      await client.selectMailbox('INBOX');
      await client.idle();

      // Intercept DONE and drop it completely to simulate remote network freeze
      mock.onCommand(({ rawLine }) => {
        if (rawLine.trim().toUpperCase() === 'DONE') {
          // Intentionally do not reply
          return true;
        }
        return false;
      });

      // Done with aggressive 30ms timeout
      await assert.rejects(
        async () => {
          await client.done({ timeoutMs: 30 });
        },
        (err) => {
          assert.equal(err.code, ERROR_CODES.CONNECTION_TIMEOUT);
          return true;
        }
      );

      // Must reset internal command state and return to AUTHENTICATED
      assert.equal(client.state, IMAP_STATES.AUTHENTICATED);
      assert.equal(client._currentCommand, null);
      assert.equal(client._idleTag, null);

      await client.logout();
    });

    it('rapidly cycles keepalive 5 times in succession without resource exhaustion or drift', async () => {
      const { mock } = createMockPair();
      store.upsertAccount({
        id: 'acc_rapid_keepalive',
        email: 'rapid@test.local',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        }),
        keepaliveIntervalMs: 15 // 15ms rapid cycling
      });

      let keepaliveCount = 0;
      idleManager.on('keepalive', () => {
        keepaliveCount++;
      });

      await idleManager.start();

      // Wait for at least 4 keepalive renewals
      await new Promise((resolve) => {
        const interval = setInterval(() => {
          if (keepaliveCount >= 4) {
            clearInterval(interval);
            resolve();
          }
        }, 10);
      });

      assert.ok(keepaliveCount >= 4, `Expected at least 4 keepalives, got ${keepaliveCount}`);
      assert.equal(idleManager.isAccountIdling('acc_rapid_keepalive'), true);

      const status = idleManager.getStatus();
      assert.equal(status.idleAccounts, 1);
      assert.ok(status.sessions.acc_rapid_keepalive.lastKeepaliveAt);

      await idleManager.stop();
      assert.equal(idleManager.isAccountIdling('acc_rapid_keepalive'), false);
    });
  });

  // ==========================================================================
  // VECTOR 2: Adaptive Polling Fallback Chaos
  // ==========================================================================
  describe('Vector 2: Adaptive Polling Fallback Chaos', () => {

    it('falls back to adaptive polling when server omits IDLE capability and detects count shifts', async () => {
      const nonIdleServer = new MockImapServer({
        scenario: 'happy_path',
        greeting: '* OK [CAPABILITY IMAP4rev1 UNSELECT NAMESPACE] Server Without IDLE Ready\r\n',
        messageCount: 15
      });

      store.upsertAccount({
        id: 'acc_noidle',
        email: 'polling@uni.edu',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: nonIdleServer.getClientSocket(),
          provider: 'custom'
        }),
        pollIntervalMs: 25
      });

      let fallbackEmitted = false;
      idleManager.once('pollingFallback', (evt) => {
        fallbackEmitted = true;
        assert.equal(evt.accountId, 'acc_noidle');
      });

      await idleManager.start();

      assert.equal(fallbackEmitted, true);
      assert.equal(idleManager.isAccountPolling('acc_noidle'), true);
      assert.equal(idleManager.isAccountIdling('acc_noidle'), false);

      // Verify status metrics
      const status = idleManager.getStatus();
      assert.equal(status.pollingAccounts, 1);
      assert.equal(status.idleAccounts, 0);

      // In polling mode, simulate message arrival
      nonIdleServer.messageCount = 18;

      let existsCountRecorded = null;
      idleManager.once('triage', (evt) => {
        existsCountRecorded = evt;
      });

      // Wait for poll interval to detect change
      await new Promise(r => setTimeout(r, 60));

      const updatedStatus = idleManager.getStatus();
      assert.equal(updatedStatus.sessions.acc_noidle.lastKnownExists, 18);

      await idleManager.stop();
      assert.equal(idleManager.isAccountPolling('acc_noidle'), false);
    });

    it('calculates correct diurnal intervals: active 60s vs night 300s', () => {
      const idleManager = new IdleManager({
        pollIntervalMs: 60000,
        nightPollIntervalMs: 300000
      });

      const interval = idleManager._getAdaptivePollInterval();
      const currentHour = new Date().getHours();

      if (currentHour >= 8 && currentHour < 22) {
        assert.equal(interval, 60000, 'Daytime must use active 60s interval');
      } else {
        assert.equal(interval, 300000, 'Nighttime must use quiet 300s interval');
      }
    });

    it('handles server status error during polling cycle and schedules reconnect backoff', async () => {
      const mock = new MockImapServer({
        greeting: '* OK [CAPABILITY IMAP4rev1] Server Ready\r\n',
        messageCount: 5
      });

      store.upsertAccount({
        id: 'acc_poll_fail',
        email: 'fail@test.local',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        }),
        pollIntervalMs: 20
      });

      await idleManager.start();
      assert.equal(idleManager.isAccountPolling('acc_poll_fail'), true);

      // Force STATUS command to fail with NO
      mock.onCommand(({ cmd, tag, server }) => {
        if (cmd === 'STATUS') {
          server.serverSocket.write(`${tag} NO [TEMPFAIL] Status unavailable\r\n`);
          return true;
        }
        return false;
      });

      const pollErrorPromise = new Promise((resolve) => {
        idleManager.once('pollError', (evt) => {
          resolve(evt);
        });
      });

      const errEvt = await pollErrorPromise;
      assert.equal(errEvt.accountId, 'acc_poll_fail');
      assert.ok(errEvt.error);

      await idleManager.stop();
    });
  });

  // ==========================================================================
  // VECTOR 3: Web Push & ntfy Chaos
  // ==========================================================================
  describe('Vector 3: Web Push & ntfy Chaos', () => {

    it('automatically purges expired subscriptions on HTTP 410 Gone and 404 Not Found from SQLite', async () => {
      // Create test keys for WebPush
      const testKeys = generateVapidKeys();

      // Register 3 push subscriptions in SQLite
      store.upsertPushSubscription({
        id: 'sub_expired_410',
        endpoint: 'https://push.services.mozilla.com/v1/sub_410',
        p256dh: testKeys.publicKey,
        auth: 'dGVzdGF1dGg='
      });
      store.upsertPushSubscription({
        id: 'sub_not_found_404',
        endpoint: 'https://fcm.googleapis.com/fcm/send/sub_404',
        p256dh: testKeys.publicKey,
        auth: 'dGVzdGF1dGg='
      });
      store.upsertPushSubscription({
        id: 'sub_active_201',
        endpoint: 'https://fcm.googleapis.com/fcm/send/sub_201',
        p256dh: testKeys.publicKey,
        auth: 'dGVzdGF1dGg='
      });

      assert.equal(store.getPushSubscriptions().length, 3);

      const conduit = new WebPushConduit({
        store,
        contactEmail: 'mailto:admin@test.local'
      });

      // Mock fetch simulating 410, 404, and 201
      const mockFetch = async (url) => {
        if (url.includes('sub_410')) {
          return { status: 410, ok: false, text: async () => 'Gone' };
        }
        if (url.includes('sub_404')) {
          return { status: 404, ok: false, text: async () => 'Not Found' };
        }
        if (url.includes('sub_201')) {
          return { status: 201, ok: true, text: async () => 'Created' };
        }
        return { status: 500, ok: false, text: async () => 'Error' };
      };

      const result = await conduit.sendToAll({ title: 'Chaos Test', body: 'Testing 410/404 purge' }, {
        fetch: mockFetch
      });

      assert.equal(result.sent, 1, 'Exactly 1 active subscription should succeed');
      assert.equal(result.failed, 2, '2 expired subscriptions should report failed');

      // Verify SQLite state: sub_410 and sub_404 must be purged!
      const remaining = store.getPushSubscriptions();
      assert.equal(remaining.length, 1, 'Only the active subscription must remain in SQLite');
      assert.equal(remaining[0].id, 'sub_active_201');
    });

    it('handles network failure (ECONNREFUSED) during ntfy dispatch without crashing caller', async () => {
      const ntfy = new NtfyConduit({
        topic: 'vip-alerts',
        serverUrl: 'https://offline-mock.local'
      });

      const manager = new NotificationManager({
        ntfy,
        webPush: null
      });

      // Mock network connection failure
      const failingFetch = async () => {
        const err = new TypeError('fetch failed');
        err.cause = { code: 'ECONNREFUSED', message: 'connect ECONNREFUSED 127.0.0.1:9999' };
        throw err;
      };

      const vipMsg = {
        id: 'msg_ntfy_chaos',
        sender: 'Dean Academic <dean@university.edu>',
        subject: 'URGENT: Committee Meeting',
        bodySnippet: 'Please review the attached dossier immediately.'
      };

      const result = await manager.dispatch(vipMsg, {
        category: 'VIP',
        shouldNotify: true
      }, {
        fetch: failingFetch
      });

      // Must return graceful error object without throwing
      assert.equal(result.dispatched, true);
      assert.ok(result.ntfyResult);
      assert.match(result.ntfyResult.error, /fetch failed/i);
    });

    it('handles HTTP 503 Service Unavailable and HTTP 429 Too Many Requests from ntfy server', async () => {
      const ntfy = new NtfyConduit({ topic: 'conduit-stress' });

      // Mock 503 response
      const server503Fetch = async () => ({
        ok: false,
        status: 503,
        text: async () => 'Service Temporarily Unavailable'
      });

      await assert.rejects(
        async () => {
          await ntfy.send({ title: 'Test', body: 'Msg' }, { fetch: server503Fetch });
        },
        /HTTP 503/
      );

      // Mock 429 response
      const server429Fetch = async () => ({
        ok: false,
        status: 429,
        text: async () => 'Rate Limit Exceeded'
      });

      await assert.rejects(
        async () => {
          await ntfy.send({ title: 'Test', body: 'Msg' }, { fetch: server429Fetch });
        },
        /HTTP 429/
      );
    });

    it('handles 50 concurrent alert dispatches without database lock contention or state corruption', async () => {
      const testKeys = generateVapidKeys();

      // Register 5 subscriptions
      for (let i = 1; i <= 5; i++) {
        store.upsertPushSubscription({
          id: `sub_conc_${i}`,
          endpoint: `https://fcm.googleapis.com/fcm/send/conc_${i}`,
          p256dh: testKeys.publicKey,
          auth: 'dGVzdGF1dGg='
        });
      }

      const webPush = new WebPushConduit({ store });
      const ntfy = new NtfyConduit({ topic: 'conc-test' });
      const manager = new NotificationManager({ store, webPush, ntfy });

      let mockFetchCount = 0;
      const mockFetch = async () => {
        mockFetchCount++;
        // Simulate realistic network delay 2-10ms
        await new Promise(r => setTimeout(r, 2 + Math.floor(Math.random() * 8)));
        return { status: 201, ok: true, text: async () => 'OK' };
      };

      // Fire 50 concurrent dispatches simultaneously
      const dispatchPromises = [];
      for (let i = 1; i <= 50; i++) {
        const msg = {
          id: `msg_flood_${i}`,
          sender: `Professor_${i} <prof${i}@uni.edu>`,
          subject: `Urgent Notice #${i}`,
          bodySnippet: `Content for urgent notice ${i}`
        };
        dispatchPromises.push(
          manager.dispatch(msg, { category: 'VIP', shouldNotify: true }, { fetch: mockFetch })
        );
      }

      const results = await Promise.allSettled(dispatchPromises);

      // Verify all 50 completed successfully
      assert.equal(results.length, 50);
      for (const res of results) {
        assert.equal(res.status, 'fulfilled');
        assert.equal(res.value.dispatched, true);
        assert.equal(res.value.webPushResult.sent, 5);
        assert.equal(res.value.webPushResult.failed, 0);
        assert.equal(res.value.ntfyResult, true);
      }

      // 50 dispatches * (5 webpush + 1 ntfy) = 300 network fetches
      assert.equal(mockFetchCount, 300);

      // Ensure SQLite subscriptions are intact
      assert.equal(store.getPushSubscriptions().length, 5);
    });
  });

  // ==========================================================================
  // VECTOR 4: Process Crash Defense & Non-Crashing Error Handling
  // ==========================================================================
  describe('Vector 4: Process Crash Defense & Isolation', () => {

    it('ensures notification dispatcher failure NEVER crashes IdleManager or sync loop', async () => {
      const { mock } = createMockPair({ messageCount: 5 });
      store.upsertAccount({
        id: 'acc_bulletproof',
        email: 'bulletproof@test.local',
        provider: 'custom'
      });
      const folderId = 'acc_bulletproof:INBOX';
      store.upsertFolder({
        id: folderId,
        accountId: 'acc_bulletproof',
        name: 'INBOX',
        path: 'INBOX'
      });
      store.upsertMessages([{
        id: 'msg_bulletproof_1',
        accountId: 'acc_bulletproof',
        folderId,
        uid: 6,
        sender: 'Prof. Danger <danger@uni.edu>',
        subject: 'URGENT: Explosive notification',
        bodySnippet: 'Testing non-crashing behavior',
        date: new Date().toISOString()
      }]);

      // Exploding NotificationManager mock
      const explodingNotificationManager = {
        dispatch: async () => {
          throw new Error('CATASTROPHIC_NOTIFICATION_SUBSYSTEM_CRASH');
        }
      };

      const idleManager = new IdleManager({
        store,
        notificationManager: explodingNotificationManager,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        })
      });

      await idleManager.start();
      assert.equal(idleManager.isAccountIdling('acc_bulletproof'), true);

      let triageFired = false;
      idleManager.once('triage', (evt) => {
        triageFired = true;
        assert.equal(evt.accountId, 'acc_bulletproof');
      });

      // Push unsolicited new message
      mock.pushExists(6);

      // Wait for event loop to process exists, triage, and notification dispatch attempt
      await new Promise(r => setTimeout(r, 60));

      assert.equal(triageFired, true);
      // IdleManager must still be running and connected!
      assert.equal(idleManager.isRunning, true);
      assert.equal(idleManager.isAccountIdling('acc_bulletproof'), true);

      await idleManager.stop();
    });

    it('cleans up all sessions, timers, and active sockets on stop() during active IDLE', async () => {
      const { mock } = createMockPair();
      store.upsertAccount({
        id: 'acc_teardown',
        email: 'teardown@test.local',
        provider: 'custom'
      });

      const idleManager = new IdleManager({
        store,
        createClient: () => new ImapClient({
          transport: mock.getClientSocket(),
          provider: 'custom'
        }),
        keepaliveIntervalMs: 500
      });

      await idleManager.start();
      assert.equal(idleManager.isAccountIdling('acc_teardown'), true);

      let stoppedEmitted = false;
      idleManager.once('stopped', (evt) => {
        stoppedEmitted = true;
        assert.equal(evt.accountId, 'acc_teardown');
      });

      await idleManager.stop();

      assert.equal(stoppedEmitted, true);
      assert.equal(idleManager.isRunning, false);
      assert.equal(idleManager.isAccountIdling('acc_teardown'), false);
      assert.equal(idleManager.getStatus().totalMonitored, 0);
    });
  });
});
