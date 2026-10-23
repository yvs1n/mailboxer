/**
 * Adversarial Stress & Protocol Fault Injection Test Suite for Milestone 2 IMAP & Sync Engine
 * (test/adversarial/sync-stress.test.js)
 *
 * Empirical Challenge Verification:
 * 1. Fault injection: sudden socket disconnects during UID FETCH literal streaming,
 *    corrupted untagged responses, truncated literal byte counts ({500}\r\n followed by socket drop).
 * 2. UIDVALIDITY mismatch handling and local state recovery (complete cache flush, zero duplicates).
 * 3. Empty mailboxes, wide gaps in UIDs (e.g. UIDs 1, 50, 1000), remote deletion pruning.
 * 4. Remote flag preservation: strict RFC 3501 compliance verifying background sync never marks
 *    remote messages seen (BODY.PEEK wire enforcement, zero STORE commands, server flag immutability).
 *
 * 100% offline using in-memory DatabaseSync and MockDuplexSocket dialogue harness.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';
import { MockDuplexSocket } from '../helpers/mock-socket.js';
import { ERROR_CODES } from '../../src/errors/taxonomy.js';

/**
 * Creates an adversarial mock IMAP server with wire command recording,
 * remote flag tracking, and custom fault injection triggers.
 */
function createAdversarialServer(initialConfig = {}) {
  const recordedCommands = [];
  const initialMessages = initialConfig.messages;
  const configCopy = { ...initialConfig };
  delete configCopy.messages;

  const state = {
    uidValidity: configCopy.uidValidity ?? 5001,
    uidNext: configCopy.uidNext ?? 10,
    folders: configCopy.folders ?? [
      { name: 'INBOX', path: 'INBOX', flags: ['\\HasNoChildren'] }
    ],
    // Map of folderName -> Map of uid -> message object
    messages: new Map(),
    unseenUids: new Set(configCopy.unseenUids ?? []),
    customHandler: null,
    onFetchHook: null,
    onSelectHook: null,
    recordedCommands,
    ...configCopy
  };

  // Populate folder messages
  const defaultMsgs = initialMessages !== undefined ? initialMessages : [
    {
      uid: 1,
      flags: [],
      subject: 'Urgent: Project Review Needed',
      from: 'Advisor <advisor@university.edu>',
      date: '2026-10-20T08:00:00Z',
      body: 'Please review the architecture diagram.'
    },
    {
      uid: 50,
      flags: ['\\Flagged'],
      subject: 'Lab Assignment Instructions',
      from: 'Teaching Assistant <ta@university.edu>',
      date: '2026-10-20T09:00:00Z',
      body: 'The lab environment is ready for testing.'
    },
    {
      uid: 1000,
      flags: ['\\Seen'],
      subject: 'Weekly Digest #42',
      from: 'Newsletter <news@weekly.internal>',
      date: '2026-10-20T10:00:00Z',
      body: 'Here are the top stories of the week.'
    }
  ];

  const inboxMap = new Map();
  for (const m of defaultMsgs) {
    inboxMap.set(m.uid, { ...m, flags: [...(m.flags || [])] });
    if (!m.flags?.includes('\\Seen')) {
      state.unseenUids.add(m.uid);
    }
  }
  state.messages.set('INBOX', inboxMap);

  function attachSocketDialogue(serverSocket) {
    let selectedFolder = 'INBOX';

    queueMicrotask(() => {
      if (!serverSocket.destroyed) {
        serverSocket.write('* OK [CAPABILITY IMAP4rev1 IDLE] Adversarial IMAP Test Server Ready\r\n');
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

        recordedCommands.push(line);

        const parts = line.split(' ');
        const tag = parts[0];
        const cmd = (parts[1] || '').toUpperCase();
        const args = parts.slice(2);

        // Custom interceptor hook
        if (state.customHandler) {
          const handled = state.customHandler({ tag, cmd, args, rawLine: line, serverSocket, state });
          if (handled) continue;
        }

        // CAPABILITY
        if (cmd === 'CAPABILITY') {
          serverSocket.write('* CAPABILITY IMAP4rev1 IDLE UNSELECT\r\n');
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
          if (state.onSelectHook) {
            state.onSelectHook({ folder: selectedFolder, tag, serverSocket });
          }
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

          if (state.onFetchHook) {
            const intercepted = state.onFetchHook({ tag, rangeStr, serverSocket, state });
            if (intercepted) continue;
          }

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
            const flagsStr = flags.join(' ');

            const headersText = `Date: ${m.date || '2026-10-20T10:00:00Z'}\r\nFrom: ${m.from || 'test@example.com'}\r\nSubject: ${m.subject || 'Subject'}\r\nMessage-ID: <msg${uid}@example.com>\r\n\r\n`;
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

        // UID STORE
        if (cmd === 'UID' && (args[0] || '').toUpperCase() === 'STORE') {
          const uid = parseInt(args[1], 10);
          const action = (args[2] || '').toUpperCase();
          const flagMatch = line.match(/\(([^)]*)\)/);
          const changedFlags = flagMatch ? flagMatch[1].trim().split(/\s+/).filter(Boolean) : [];

          const folderMsgs = state.messages.get(selectedFolder);
          if (folderMsgs && folderMsgs.has(uid)) {
            const m = folderMsgs.get(uid);
            const flagSet = new Set(m.flags || []);
            if (action.includes('+')) {
              for (const f of changedFlags) flagSet.add(f);
            } else if (action.includes('-')) {
              for (const f of changedFlags) flagSet.delete(f);
            } else {
              flagSet.clear();
              for (const f of changedFlags) flagSet.add(f);
            }
            m.flags = Array.from(flagSet);
            if (flagSet.has('\\Seen')) {
              state.unseenUids.delete(uid);
            } else {
              state.unseenUids.add(uid);
            }
          }

          serverSocket.write(`* 1 FETCH (UID ${uid} FLAGS (${changedFlags.join(' ')}))\r\n`);
          serverSocket.write(`${tag} OK STORE completed\r\n`);
          continue;
        }

        // LOGOUT
        if (cmd === 'LOGOUT') {
          serverSocket.write('* BYE IMAP4rev1 Server logging out\r\n');
          serverSocket.write(`${tag} OK LOGOUT completed\r\n`);
          serverSocket.end();
          continue;
        }

        // NOOP
        if (cmd === 'NOOP') {
          serverSocket.write(`${tag} OK NOOP completed\r\n`);
          continue;
        }

        // Fallback OK
        serverSocket.write(`${tag} OK Unknown command executed\r\n`);
      }
    });
  }

  return {
    state,
    recordedCommands,
    createClientWithTransport(options = {}) {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      attachSocketDialogue(serverSock);
      return new ImapClient({ transport: clientSock, ...options });
    }
  };
}

describe('Adversarial Verification: Milestone 2 Sync Engine & IMAP Protocol', () => {

  // ==========================================================================
  // CHALLENGE 1: Fault Injection (Socket Disconnects, Truncation, Corrupted Wire)
  // ==========================================================================
  describe('Challenge 1: Fault Injection during UID FETCH & Literal Processing', () => {

    it('rejects in-flight UID FETCH with CONNECTION_DROPPED when socket drops mid-literal streaming', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      // Hook fetch to disconnect halfway through writing literal
      server.state.onFetchHook = ({ serverSocket }) => {
        // Send partial response with literal header
        serverSocket.write('* 1 FETCH (UID 1 RFC822.SIZE 500 BODY.PEEK[HEADER.FIELDS (SUBJECT)] {100}\r\nSubject: Incomplete');
        // Simulate sudden network termination mid-stream
        queueMicrotask(() => {
          serverSocket.destroy(new Error('read ECONNRESET'));
        });
        return true;
      };

      await client.connect();
      await client.login('test@mailboxer.internal', 'pass');
      await client.selectMailbox('INBOX');

      await assert.rejects(
        async () => {
          await client.fetchMessages('1');
        },
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.CONNECTION_DROPPED);
          return true;
        }
      );

      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });

    it('SyncEngine.syncFolder catches mid-fetch socket drop, updates folder to ERROR, and leaves database consistent with 0 corrupt rows', async () => {
      const store = new SqliteStore(':memory:');
      const server = createAdversarialServer();

      // Ensure account exists in store
      store.upsertAccount({ id: 'acc_fault', email: 'fault@mailboxer.internal', provider: 'custom' });

      // Induce drop on UID FETCH
      server.state.onFetchHook = ({ serverSocket }) => {
        serverSocket.write('* 1 FETCH (UID 1 RFC822.SIZE 800 BODY.PEEK[TEXT]<0.1000> {800}\r\nPartial');
        queueMicrotask(() => {
          serverSocket.destroy(new Error('Socket hung up abruptly'));
        });
        return true;
      };

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      await assert.rejects(
        async () => {
          await syncEngine.syncFolder('acc_fault', 'INBOX');
        }
      );

      // Verify folder recorded ERROR state in SQLite
      const folder = store.getFolder('acc_fault', 'INBOX');
      assert.ok(folder !== null);
      assert.strictEqual(folder.syncStatus, 'ERROR');
      assert.ok(folder.syncError.includes('closed prematurely') || folder.syncError.includes('CONNECTION_DROPPED') || folder.syncError.includes('hung up'));

      // Verify zero partial/corrupted messages inserted in SQLite
      const messages = store.getMessages({ folderId: 'acc_fault:INBOX' });
      assert.strictEqual(messages.length, 0);

      // Verify search index is empty
      const searchRes = store.search('Partial', { folderId: 'acc_fault:INBOX' });
      assert.strictEqual(searchRes.length, 0);
    });

    it('handles truncated literal byte count ({500}\\r\\n followed by socket close) without indefinite hanging', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      server.state.onFetchHook = ({ serverSocket }) => {
        // Declares 500 octets, but writes only 20 octets, then terminates abruptly
        serverSocket.write('* 1 FETCH (UID 1 BODY.PEEK[HEADER] {500}\r\n12345678901234567890');
        queueMicrotask(() => {
          serverSocket.destroy(new Error('Truncated stream drop'));
        });
        return true;
      };

      await client.connect();
      await client.login('test@mailboxer.internal', 'pass');
      await client.selectMailbox('INBOX');

      await assert.rejects(
        async () => {
          await client.fetchMessages('1');
        },
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.CONNECTION_DROPPED);
          return true;
        }
      );

      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });

    it('parses gracefully when untagged response contains malformed literal declarations ({NOT_A_NUM} or {-50}) without throwing TypeError', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      server.state.onFetchHook = ({ tag, serverSocket }) => {
        // Malformed literal headers and corrupted syntax
        serverSocket.write('* 1 FETCH (UID 1 RFC822.SIZE 100 BODY.PEEK[HEADER] {NOT_A_NUMBER}\r\n');
        serverSocket.write('Subject: Fallback Subject\r\n\r\n');
        serverSocket.write('* 2 FETCH (UID 2 RFC822.SIZE 100 BODY.PEEK[HEADER] {-50}\r\n');
        serverSocket.write('Subject: Negative Len Subject\r\n\r\n');
        serverSocket.write(`${tag} OK UID FETCH completed\r\n`);
        return true;
      };

      await client.connect();
      await client.login('test@mailboxer.internal', 'pass');
      await client.selectMailbox('INBOX');

      // Must resolve without unhandled crash
      const res = await client.fetchMessages('1,2');
      assert.ok(Array.isArray(res));
      // Fallback extraction populates default fields
      for (const m of res) {
        assert.ok(typeof m.uid === 'number');
        assert.ok(typeof m.subject === 'string');
      }
    });

    it('enforces command timeout when server transmits incomplete literal and remains silent', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      server.state.onFetchHook = ({ serverSocket }) => {
        // Declares 500 bytes, sends 20 bytes, and goes totally silent
        serverSocket.write('* 1 FETCH (UID 1 BODY.PEEK[HEADER] {500}\r\n12345678901234567890');
        // Do not close socket, do not send remaining 480 bytes
        return true;
      };

      await client.connect();
      await client.login('test@mailboxer.internal', 'pass');
      await client.selectMailbox('INBOX');

      const start = Date.now();
      await assert.rejects(
        async () => {
          await client.sendCommand('UID FETCH 1 (BODY.PEEK[HEADER])', { timeoutMs: 60 });
        },
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.CONNECTION_TIMEOUT);
          return true;
        }
      );

      const elapsed = Date.now() - start;
      assert.ok(elapsed >= 55, `Expected timeout after ~60ms, elapsed: ${elapsed}ms`);
      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });
  });

  // ==========================================================================
  // CHALLENGE 2: UIDVALIDITY Mismatch Handling & Local State Recovery
  // ==========================================================================
  describe('Challenge 2: UIDVALIDITY Mismatch Handling & State Recovery', () => {

    it('purges existing cached messages and re-indexes new messages when UIDVALIDITY changes on remote server', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_uidv', email: 'uidv@mailboxer.internal', provider: 'custom' });

      // Step 1: Initial sync with UIDVALIDITY 1001
      const initialServer = createAdversarialServer({
        uidValidity: 1001,
        messages: [
          {
            uid: 1,
            subject: 'Epoch 1 Message A',
            from: 'alpha@old.internal',
            body: 'Old epoch text keyword_dinosaur'
          },
          {
            uid: 2,
            subject: 'Epoch 1 Message B',
            from: 'beta@old.internal',
            body: 'Another old epoch message'
          },
          {
            uid: 3,
            subject: 'Epoch 1 Message C (To be purged)',
            from: 'gamma@old.internal',
            body: 'keyword_pterodactyl unique string'
          }
        ]
      });

      let currentServer = initialServer;
      const syncEngine = new SyncEngine({
        store,
        createClient: () => currentServer.createClientWithTransport()
      });

      const res1 = await syncEngine.syncFolder('acc_uidv', 'INBOX');
      assert.strictEqual(res1.flushed, false);
      assert.strictEqual(res1.newMessagesCount, 3);
      assert.strictEqual(res1.uidValidity, 1001);

      // Verify stored messages and search indexing
      let stored = store.getMessages({ folderId: 'acc_uidv:INBOX' });
      assert.strictEqual(stored.length, 3);
      assert.strictEqual(store.search('keyword_dinosaur', { folderId: 'acc_uidv:INBOX' }).length, 1);
      assert.strictEqual(store.search('keyword_pterodactyl', { folderId: 'acc_uidv:INBOX' }).length, 1);

      // Step 2: Remote server mailbox is rebuilt/restored! UIDVALIDITY changes to 2002.
      // Remote now has totally different messages under UIDs 1 and 2.
      const rebuiltServer = createAdversarialServer({
        uidValidity: 2002,
        messages: [
          {
            uid: 1,
            subject: 'Epoch 2 New Message 1',
            from: 'new1@rebuilt.internal',
            body: 'New epoch body keyword_astronaut'
          },
          {
            uid: 2,
            subject: 'Epoch 2 New Message 2',
            from: 'new2@rebuilt.internal',
            body: 'New epoch body keyword_spaceship'
          }
        ]
      });
      currentServer = rebuiltServer;

      let cacheInvalidatedEvent = null;
      syncEngine.once('cacheInvalidated', (ev) => {
        cacheInvalidatedEvent = ev;
      });

      // Step 3: Run incremental sync
      const res2 = await syncEngine.syncFolder('acc_uidv', 'INBOX');
      assert.strictEqual(res2.flushed, true, 'Expected flushed=true when UIDVALIDITY mismatched');
      assert.strictEqual(res2.uidValidity, 2002);
      assert.strictEqual(res2.newMessagesCount, 2);

      // Verify event was fired
      assert.ok(cacheInvalidatedEvent !== null);
      assert.strictEqual(cacheInvalidatedEvent.oldUidValidity, 1001);
      assert.strictEqual(cacheInvalidatedEvent.newUidValidity, 2002);

      // Verify local database state:
      // Old UID 3 must be completely gone
      stored = store.getMessages({ folderId: 'acc_uidv:INBOX' });
      assert.strictEqual(stored.length, 2);

      const uidsInStore = stored.map(m => m.uid).sort((a, b) => a - b);
      assert.deepStrictEqual(uidsInStore, [1, 2]);

      // Check content is epoch 2, not epoch 1
      const msg1 = store.getMessageByUid('acc_uidv:INBOX', 1);
      assert.strictEqual(msg1.subject, 'Epoch 2 New Message 1');
      assert.strictEqual(msg1.sender, 'new1@rebuilt.internal');

      // Verify search index was purged of old epoch keywords
      assert.strictEqual(store.search('keyword_dinosaur', { folderId: 'acc_uidv:INBOX' }).length, 0);
      assert.strictEqual(store.search('keyword_pterodactyl', { folderId: 'acc_uidv:INBOX' }).length, 0);

      // Verify search index finds new epoch keywords
      assert.strictEqual(store.search('keyword_astronaut', { folderId: 'acc_uidv:INBOX' }).length, 1);
      assert.strictEqual(store.search('keyword_spaceship', { folderId: 'acc_uidv:INBOX' }).length, 1);

      // Verify folder record in SQLite reflects new UIDVALIDITY
      const folderRecord = store.getFolder('acc_uidv', 'INBOX');
      assert.strictEqual(folderRecord.uidvalidity, 2002);
    });

    it('does not flush cache when UIDVALIDITY matches previous sync', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_stable', email: 'stable@mailboxer.internal', provider: 'custom' });

      const server = createAdversarialServer({
        uidValidity: 9999,
        messages: [
          { uid: 1, subject: 'Stable 1', from: 's@test.com', body: 'Stable message' }
        ]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      const res1 = await syncEngine.syncFolder('acc_stable', 'INBOX');
      assert.strictEqual(res1.flushed, false);
      assert.strictEqual(res1.newMessagesCount, 1);

      // Add message 2 on server with same UIDVALIDITY
      server.state.messages.get('INBOX').set(2, {
        uid: 2,
        flags: [],
        subject: 'Stable 2',
        from: 's@test.com',
        body: 'New delta message'
      });

      let invalidatedCalled = false;
      syncEngine.once('cacheInvalidated', () => { invalidatedCalled = true; });

      const res2 = await syncEngine.syncFolder('acc_stable', 'INBOX');
      assert.strictEqual(res2.flushed, false);
      assert.strictEqual(res2.newMessagesCount, 1);
      assert.strictEqual(invalidatedCalled, false);

      const msgs = store.getMessages({ folderId: 'acc_stable:INBOX' });
      assert.strictEqual(msgs.length, 2);
    });
  });

  // ==========================================================================
  // CHALLENGE 3: Empty Mailboxes & Wide UID Gaps
  // ==========================================================================
  describe('Challenge 3: Empty Mailboxes & Gaps in UIDs', () => {

    it('cleanly synchronizes a completely empty mailbox (EXISTS 0, SEARCH returns empty) without errors', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_empty', email: 'empty@mailboxer.internal', provider: 'custom' });

      const server = createAdversarialServer({
        messages: [] // 0 messages
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      const res = await syncEngine.syncFolder('acc_empty', 'INBOX');
      assert.strictEqual(res.totalMessages, 0);
      assert.strictEqual(res.newMessagesCount, 0);
      assert.strictEqual(res.prunedCount, 0);
      assert.strictEqual(res.unseenCount, 0);

      const folder = store.getFolder('acc_empty', 'INBOX');
      assert.ok(folder !== null);
      assert.strictEqual(folder.totalMessages, 0);
      assert.strictEqual(folder.unseenMessages, 0);
      assert.strictEqual(folder.syncStatus, 'IDLE');
      assert.strictEqual(folder.syncError, null);

      const msgs = store.getMessages({ folderId: 'acc_empty:INBOX' });
      assert.deepStrictEqual(msgs, []);

      const searchRes = store.search('anything', { folderId: 'acc_empty:INBOX' });
      assert.deepStrictEqual(searchRes, []);
    });

    it('correctly manages wide non-consecutive UID gaps (UIDs 1, 50, 1000) during initial and delta sync', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_gaps', email: 'gaps@mailboxer.internal', provider: 'custom' });

      const server = createAdversarialServer({
        messages: [
          { uid: 1, subject: 'UID 1 Msg', from: 'a@gap.internal', body: 'First message' },
          { uid: 50, subject: 'UID 50 Msg', from: 'b@gap.internal', body: 'Middle message with huge gap' },
          { uid: 1000, subject: 'UID 1000 Msg', from: 'c@gap.internal', body: 'Top message with gap' }
        ]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      // 1. Initial sync
      const res1 = await syncEngine.syncFolder('acc_gaps', 'INBOX');
      assert.strictEqual(res1.newMessagesCount, 3);

      let stored = store.getMessages({ folderId: 'acc_gaps:INBOX' });
      assert.strictEqual(stored.length, 3);
      assert.strictEqual(store.getMaxUid('acc_gaps:INBOX'), 1000);

      // 2. Add message 5000 remotely (next leap gap)
      server.state.messages.get('INBOX').set(5000, {
        uid: 5000,
        flags: ['\\Seen'],
        subject: 'UID 5000 Leap Msg',
        from: 'd@gap.internal',
        body: 'Leap message after 1000'
      });

      const res2 = await syncEngine.syncFolder('acc_gaps', 'INBOX');
      assert.strictEqual(res2.newMessagesCount, 1);
      assert.strictEqual(store.getMaxUid('acc_gaps:INBOX'), 5000);

      stored = store.getMessages({ folderId: 'acc_gaps:INBOX' });
      assert.strictEqual(stored.length, 4);
      assert.deepStrictEqual(stored.map(m => m.uid).sort((a, b) => a - b), [1, 50, 1000, 5000]);

      // Verify incremental query used UID 1001:*
      const searchCommands = server.recordedCommands.filter(c => c.includes('UID SEARCH UID'));
      assert.ok(searchCommands.length > 0);
      assert.ok(searchCommands.some(c => c.includes('UID 1001:*')));

      // 3. Remote deletion of middle gap UID 50
      server.state.messages.get('INBOX').delete(50);

      const res3 = await syncEngine.syncFolder('acc_gaps', 'INBOX');
      assert.strictEqual(res3.prunedCount, 1);

      stored = store.getMessages({ folderId: 'acc_gaps:INBOX' });
      assert.strictEqual(stored.length, 3);
      assert.deepStrictEqual(stored.map(m => m.uid).sort((a, b) => a - b), [1, 1000, 5000]);

      // Message 50 is unsearchable
      assert.strictEqual(store.search('UID 50 Msg', { folderId: 'acc_gaps:INBOX' }).length, 0);
    });

    it('prunes all local messages when entire remote mailbox is expunged to 0 messages', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_purge_all', email: 'purge@mailboxer.internal', provider: 'custom' });

      const server = createAdversarialServer({
        messages: [
          { uid: 10, subject: 'To be wiped 1', from: 'wipe@test.com', body: 'body 1' },
          { uid: 20, subject: 'To be wiped 2', from: 'wipe@test.com', body: 'body 2' }
        ]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      await syncEngine.syncFolder('acc_purge_all', 'INBOX');
      assert.strictEqual(store.getMessages({ folderId: 'acc_purge_all:INBOX' }).length, 2);

      // Remotely wipe all messages
      server.state.messages.get('INBOX').clear();
      server.state.unseenUids.clear();

      const res = await syncEngine.syncFolder('acc_purge_all', 'INBOX');
      assert.strictEqual(res.prunedCount, 2);
      assert.strictEqual(res.totalMessages, 0);

      const remaining = store.getMessages({ folderId: 'acc_purge_all:INBOX' });
      assert.strictEqual(remaining.length, 0);
      assert.strictEqual(store.getMaxUid('acc_purge_all:INBOX'), null);
    });
  });

  // ==========================================================================
  // CHALLENGE 4: Remote Flag Preservation (RFC 3501 Strict Compliance)
  // ==========================================================================
  describe('Challenge 4: Remote Flag Preservation & RFC 3501 Compliance', () => {

    it('never alters remote \\Seen flags during background sync: enforces BODY.PEEK on wire and zero STORE commands', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_flags', email: 'flags@mailboxer.internal', provider: 'custom' });

      // Unseen message setup
      const server = createAdversarialServer({
        messages: [
          {
            uid: 101,
            flags: [], // Strict unread
            subject: 'Unread Critical Alert',
            from: 'admin@alert.internal',
            body: 'Do not mark this seen on remote server!'
          },
          {
            uid: 102,
            flags: ['\\Flagged'], // Unread and Flagged
            subject: 'Important Flagged Note',
            from: 'boss@corp.internal',
            body: 'Another unread message that must remain unread.'
          },
          {
            uid: 103,
            flags: ['\\Seen'], // Read
            subject: 'Read Newsletter',
            from: 'news@digest.internal',
            body: 'Already seen.'
          }
        ]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      // Execute full sync
      const res = await syncEngine.syncFolder('acc_flags', 'INBOX');
      assert.strictEqual(res.newMessagesCount, 3);
      assert.strictEqual(res.unseenCount, 2);

      // WIRE AUDIT 1: Check that all FETCH commands strictly use BODY.PEEK
      const fetchCommands = server.recordedCommands.filter(c => c.includes('FETCH'));
      assert.ok(fetchCommands.length > 0, 'Expected at least one FETCH command on wire');

      for (const cmd of fetchCommands) {
        assert.ok(
          cmd.includes('BODY.PEEK['),
          `RFC 3501 Violation: Command "${cmd}" fetched body without BODY.PEEK`
        );
        // Verify no bare BODY[] or RFC822 without PEEK
        const hasViolatingBody = /\bBODY\[/i.test(cmd);
        const hasViolatingRfc822 = /\bRFC822(?!\.SIZE)\b/i.test(cmd);
        assert.strictEqual(hasViolatingBody, false, `Forbidden BODY[] fetch detected: ${cmd}`);
        assert.strictEqual(hasViolatingRfc822, false, `Forbidden RFC822 fetch detected: ${cmd}`);
      }

      // WIRE AUDIT 2: Verify zero STORE commands sent during sync
      const storeCommands = server.recordedCommands.filter(c => c.includes('STORE'));
      assert.strictEqual(
        storeCommands.length,
        0,
        `RFC 3501 Violation: Background sync transmitted STORE command(s): ${storeCommands.join(', ')}`
      );

      // REMOTE STATE AUDIT: Verify remote messages flags were NOT mutated
      const remoteInbox = server.state.messages.get('INBOX');
      const remoteMsg101 = remoteInbox.get(101);
      const remoteMsg102 = remoteInbox.get(102);

      assert.deepStrictEqual(remoteMsg101.flags, [], 'Remote UID 101 must remain strictly unread');
      assert.deepStrictEqual(remoteMsg102.flags, ['\\Flagged'], 'Remote UID 102 must preserve flags without \\Seen');
      assert.ok(server.state.unseenUids.has(101), 'Remote state unseenUids must still contain 101');
      assert.ok(server.state.unseenUids.has(102), 'Remote state unseenUids must still contain 102');

      // LOCAL RECONCILIATION AUDIT: Local store correctly captured isSeen flags
      const local101 = store.getMessageByUid('acc_flags:INBOX', 101);
      const local102 = store.getMessageByUid('acc_flags:INBOX', 102);
      const local103 = store.getMessageByUid('acc_flags:INBOX', 103);

      assert.strictEqual(local101.isSeen, false, 'Local UID 101 must be isSeen=false');
      assert.strictEqual(local102.isSeen, false, 'Local UID 102 must be isSeen=false');
      assert.strictEqual(local102.isFlagged, true, 'Local UID 102 must be isFlagged=true');
      assert.strictEqual(local103.isSeen, true, 'Local UID 103 must be isSeen=true');
    });

    it('reconciles remote flag changes (e.g. read on mobile) during subsequent sync without touching untouched messages', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_recon', email: 'recon@mailboxer.internal', provider: 'custom' });

      const server = createAdversarialServer({
        messages: [
          { uid: 1, flags: [], subject: 'Msg 1', from: 'a@a.com', body: 'body 1' },
          { uid: 2, flags: [], subject: 'Msg 2', from: 'b@b.com', body: 'body 2' }
        ]
      });

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      await syncEngine.syncFolder('acc_recon', 'INBOX');
      assert.strictEqual(store.getMessageByUid('acc_recon:INBOX', 1).isSeen, false);
      assert.strictEqual(store.getMessageByUid('acc_recon:INBOX', 2).isSeen, false);

      // User marks message 1 as read remotely on their phone!
      server.state.messages.get('INBOX').get(1).flags = ['\\Seen'];
      server.state.unseenUids.delete(1);

      // Run second sync
      const res = await syncEngine.syncFolder('acc_recon', 'INBOX');
      assert.strictEqual(res.newMessagesCount, 0); // No new messages
      assert.strictEqual(res.unseenCount, 1); // Only message 2 is unseen

      // Local store reconciles: message 1 is now seen, message 2 remains unseen
      assert.strictEqual(store.getMessageByUid('acc_recon:INBOX', 1).isSeen, true);
      assert.strictEqual(store.getMessageByUid('acc_recon:INBOX', 2).isSeen, false);

      // Remote message 2 remains untouched
      assert.deepStrictEqual(server.state.messages.get('INBOX').get(2).flags, []);
    });
  });

  // ==========================================================================
  // CHALLENGE 5: Advanced Protocol Chaos & Boundary Probing
  // ==========================================================================
  describe('Challenge 5: Advanced Protocol Chaos & Boundary Invariants', () => {

    it('recovers from socket drop during chunk 2 of multi-batch fetch and cleanly resumes delta without duplicates', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_chunk', email: 'chunk@mailboxer.internal', provider: 'custom' });

      // Generate 60 messages: batch 1 has 1..30, batch 2 has 31..60
      const messages = [];
      for (let i = 1; i <= 60; i++) {
        messages.push({
          uid: i * 2, // gaps: 2, 4, 6 ... 120
          flags: [],
          subject: `Chunk Msg ${i * 2}`,
          from: `user${i}@chunk.internal`,
          body: `Body ${i * 2}`
        });
      }

      let fetchCallCount = 0;
      let shouldDropOnBatch2 = true;

      const server = createAdversarialServer({ messages });
      server.state.onFetchHook = ({ tag, rangeStr, serverSocket, state }) => {
        fetchCallCount++;
        if (fetchCallCount === 2 && shouldDropOnBatch2) {
          // Drop connection right on batch 2
          queueMicrotask(() => {
            serverSocket.destroy(new Error('Batch 2 dropped abruptly'));
          });
          return true;
        }
        return false; // let normal handler process batch 1
      };

      const syncEngine = new SyncEngine({
        store,
        batchSize: 30, // 2 batches: 30 each
        createClient: () => server.createClientWithTransport()
      });

      // Run 1: Should fail during batch 2
      await assert.rejects(
        async () => {
          await syncEngine.syncFolder('acc_chunk', 'INBOX');
        }
      );

      // Batch 1 (30 messages, UIDs 2..60) was already committed!
      let stored = store.getMessages({ folderId: 'acc_chunk:INBOX', limit: 100 });
      assert.strictEqual(stored.length, 30);
      assert.strictEqual(store.getMaxUid('acc_chunk:INBOX'), 60);

      // Run 2: Disable fault injection and sync again
      shouldDropOnBatch2 = false;
      const res2 = await syncEngine.syncFolder('acc_chunk', 'INBOX');

      // Delta sync queried UID 61:* and fetched remaining 30 messages (UIDs 62..120)
      assert.strictEqual(res2.newMessagesCount, 30);

      stored = store.getMessages({ folderId: 'acc_chunk:INBOX', limit: 100 });
      assert.strictEqual(stored.length, 60);
      assert.strictEqual(store.getMaxUid('acc_chunk:INBOX'), 120);

      // Verify zero duplicate primary keys
      const uids = stored.map(m => m.uid);
      const uniqueUids = new Set(uids);
      assert.strictEqual(uniqueUids.size, 60);
    });

    it('isolates UIDVALIDITY mismatch to affected folder without clearing sibling folders in same account', async () => {
      const store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_multi', email: 'multi@mailboxer.internal', provider: 'custom' });

      // Account with two folders: INBOX and Archive
      const server = createAdversarialServer({
        folders: [
          { name: 'INBOX', path: 'INBOX', flags: [] },
          { name: 'Archive', path: 'Archive', flags: [] }
        ],
        messages: [
          { uid: 1, subject: 'Inbox Message 1', from: 'inbox@test.com', body: 'inbox body' }
        ]
      });

      // Add Archive message
      const archiveMap = new Map();
      archiveMap.set(55, {
        uid: 55,
        flags: ['\\Seen'],
        subject: 'Archive Important Note',
        from: 'arch@test.com',
        body: 'archive body keyword_treasure'
      });
      server.state.messages.set('Archive', archiveMap);

      const syncEngine = new SyncEngine({
        store,
        createClient: () => server.createClientWithTransport()
      });

      // Sync both folders initially
      await syncEngine.syncFolder('acc_multi', 'INBOX');
      await syncEngine.syncFolder('acc_multi', 'Archive');

      assert.strictEqual(store.getMessages({ folderId: 'acc_multi:INBOX' }).length, 1);
      assert.strictEqual(store.getMessages({ folderId: 'acc_multi:Archive' }).length, 1);

      // Now change UIDVALIDITY ONLY on INBOX!
      server.state.onSelectHook = ({ folder, tag, serverSocket }) => {
        if (folder === 'INBOX') {
          server.state.uidValidity = 77777; // New validity for INBOX
        }
      };

      // Sync INBOX again
      const res = await syncEngine.syncFolder('acc_multi', 'INBOX');
      assert.strictEqual(res.flushed, true);

      // Verify Archive folder was NOT touched or purged!
      const archiveMessages = store.getMessages({ folderId: 'acc_multi:Archive' });
      assert.strictEqual(archiveMessages.length, 1);
      assert.strictEqual(archiveMessages[0].uid, 55);
      assert.strictEqual(store.search('keyword_treasure', { folderId: 'acc_multi:Archive' }).length, 1);
    });

    it('handles zero-length literals ({0}\\r\\n\\r\\n) and empty body snippets without corruption', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      server.state.onFetchHook = ({ tag, serverSocket }) => {
        // Zero-length header literal and zero-length body literal
        serverSocket.write(
          `* 1 FETCH (UID 42 FLAGS (\\Flagged) RFC822.SIZE 0 BODY.PEEK[HEADER.FIELDS ()] {0}\r\n\r\n BODY.PEEK[TEXT]<0.1000> {0}\r\n\r\n)\r\n`
        );
        serverSocket.write(`${tag} OK UID FETCH completed\r\n`);
        return true;
      };

      await client.connect();
      await client.login('u', 'p');
      await client.selectMailbox('INBOX');

      const messages = await client.fetchMessages('42');
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].uid, 42);
      assert.strictEqual(messages[0].subject, '(no subject)');
      assert.strictEqual(messages[0].bodySnippet, '');
      assert.strictEqual(messages[0].isFlagged, true);
    });

    it('safely discards interleaved unsolicited untagged lines (* EXPUNGE, * EXISTS) arriving during UID FETCH', async () => {
      const server = createAdversarialServer();
      const client = server.createClientWithTransport();

      server.state.onFetchHook = ({ tag, serverSocket }) => {
        // Interleave unsolicited server events into the fetch dialogue
        serverSocket.write('* 12 EXPUNGE\r\n');
        serverSocket.write('* 500 EXISTS\r\n');
        serverSocket.write(
          `* 1 FETCH (UID 10 FLAGS (\\Seen) RFC822.SIZE 250 BODY.PEEK[HEADER.FIELDS (SUBJECT)] {23}\r\nSubject: Real Subject\r\n)\r\n`
        );
        serverSocket.write('* NO [ALERT] Maintenance warning\r\n');
        serverSocket.write(`${tag} OK UID FETCH completed\r\n`);
        return true;
      };

      await client.connect();
      await client.login('u', 'p');
      await client.selectMailbox('INBOX');

      const messages = await client.fetchMessages('10');
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].uid, 10);
      assert.strictEqual(messages[0].subject, 'Real Subject');
      assert.strictEqual(messages[0].isSeen, true);
    });
  });
});

