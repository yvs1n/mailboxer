/**
 * Unit Tests: Incremental IMAP Sync Engine (test/unit/sync-engine.test.js)
 *
 * Validates the complete RFC 3501 synchronization lifecycle:
 * - In-memory DatabaseSync local caching
 * - Initial mailbox sync and message ingestion
 * - Incremental delta UID fetching (<maxLocalUid + 1>:*)
 * - UIDVALIDITY cache invalidation upon mailbox rebuild
 * - Flag reconciliation (UNSEEN)
 * - Remote deletion pruning (ALL)
 * - Periodic background sync scheduling
 * - Error isolation and state reporting
 *
 * 100% offline using MockDuplexSocket and MockImapServer dialogue simulator.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { ImapClient } from '../../src/connection/imap-client.js';
import { MockDuplexSocket } from '../helpers/mock-socket.js';

/**
 * Creates an in-memory IMAP mock server configured with realistic synchronization responses.
 */
function createSyncMockServer(initialState = {}) {
  const state = {
    uidValidity: initialState.uidValidity ?? 1001,
    uidNext: initialState.uidNext ?? 4,
    folders: initialState.folders ?? [
      { name: 'INBOX', path: 'INBOX', flags: ['\\HasNoChildren'] },
      { name: 'Archive', path: 'Archive', flags: ['\\HasNoChildren'] }
    ],
    // Map of folderName -> Map of uid -> message
    messages: new Map(),
    unseenUids: new Set(initialState.unseenUids ?? [1, 2]),
    customCommandHandler: null,
    ...initialState
  };

  // Populate default messages for INBOX
  const inboxMsgs = new Map();
  const defaultMsgs = initialState.initialMessages ?? [
    {
      uid: 1,
      flags: ['\\Flagged'],
      subject: 'Welcome to Mailboxer',
      from: 'Mailboxer Team <welcome@mailboxer.internal>',
      date: '2026-10-20T08:00:00Z',
      body: 'Welcome to your unified inbox!'
    },
    {
      uid: 2,
      flags: [],
      subject: 'CS101 Assignment 1 Due Tomorrow',
      from: 'Prof. Miller <miller@uni.edu>',
      date: '2026-10-20T09:00:00Z',
      body: 'Please submit Assignment 1 on Canvas by 11:59pm.'
    },
    {
      uid: 3,
      flags: ['\\Seen'],
      subject: 'Security Alert: New Sign-in from Windows',
      from: 'Security <security@google.com>',
      date: '2026-10-20T10:00:00Z',
      body: 'A new login was detected for your account.'
    }
  ];

  for (const m of defaultMsgs) {
    inboxMsgs.set(m.uid, m);
  }
  state.messages.set('INBOX', inboxMsgs);

  function setupDialogue(serverSocket) {
    let selectedFolder = 'INBOX';

    queueMicrotask(() => {
      if (!serverSocket.destroyed) {
        serverSocket.write('* OK [CAPABILITY IMAP4rev1 IDLE] Mailboxer Mock Sync Server Ready\r\n');
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
          const flags = flagMatch ? flagMatch[1].trim().split(/\s+/) : [];

          const folderMsgs = state.messages.get(selectedFolder) || new Map();
          const m = folderMsgs.get(uid);
          if (m) {
            if (action.includes('+FLAGS')) {
              for (const f of flags) if (!m.flags.includes(f)) m.flags.push(f);
            } else if (action.includes('-FLAGS')) {
              m.flags = m.flags.filter(f => !flags.includes(f));
            } else {
              m.flags = [...flags];
            }

            if (m.flags.includes('\\Seen')) {
              state.unseenUids.delete(uid);
            } else {
              state.unseenUids.add(uid);
            }
          }

          serverSocket.write(`* 1 FETCH (FLAGS (${m ? m.flags.join(' ') : ''}))\r\n`);
          serverSocket.write(`${tag} OK UID STORE completed\r\n`);
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

describe('Incremental IMAP Sync Engine (src/sync/sync-engine.js)', () => {
  let store;
  let mockServer;
  let syncEngine;
  const TEST_ACCOUNT_ID = 'acc_sync_test';

  beforeEach(() => {
    store = new SqliteStore(':memory:');
    store.upsertAccount({
      id: TEST_ACCOUNT_ID,
      email: 'test@mailboxer.internal',
      provider: 'gmail',
      name: 'Test Account'
    });

    mockServer = createSyncMockServer();

    // Factory returning fresh client connected to the mock server dialogue
    const createClient = (config) => {
      const clientSocket = mockServer.createClientSocket();
      return new ImapClient({ accountConfig: config, transport: clientSocket });
    };

    syncEngine = new SyncEngine({
      store,
      createClient,
      accountManager: {
        getAccount: async () => ({
          id: TEST_ACCOUNT_ID,
          email: 'test@mailboxer.internal',
          provider: 'gmail',
          auth: { user: 'test@mailboxer.internal', pass: 'secret' }
        })
      }
    });
  });

  afterEach(() => {
    if (syncEngine) {
      syncEngine.stopPeriodicSync();
    }
    if (store) {
      store.close();
    }
  });

  describe('1. Initial Mailbox Sync', () => {
    it('synchronizes all initial messages and populates local store', async () => {
      const events = [];
      syncEngine.on('syncFolderStart', e => events.push(['start', e]));
      syncEngine.on('messageAdded', e => events.push(['added', e.uid]));
      syncEngine.on('folderSynced', e => events.push(['synced', e]));

      const result = await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      assert.strictEqual(result.accountId, TEST_ACCOUNT_ID);
      assert.strictEqual(result.folder, 'INBOX');
      assert.strictEqual(result.newMessagesCount, 3);
      assert.strictEqual(result.prunedCount, 0);
      assert.strictEqual(result.flushed, false);
      assert.strictEqual(result.uidValidity, 1001);

      // Verify records in local SQLite store
      const messages = store.getMessages({ accountId: TEST_ACCOUNT_ID, folderId: `${TEST_ACCOUNT_ID}:INBOX` });
      assert.strictEqual(messages.length, 3);

      const msg1 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 1);
      assert.ok(msg1);
      assert.strictEqual(msg1.subject, 'Welcome to Mailboxer');
      assert.strictEqual(msg1.isFlagged, true);
      assert.strictEqual(msg1.bodySnippet, 'Welcome to your unified inbox!');

      const msg2 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 2);
      assert.ok(msg2);
      assert.strictEqual(msg2.subject, 'CS101 Assignment 1 Due Tomorrow');
      assert.strictEqual(msg2.senderEmail, 'miller@uni.edu');

      // Verify folder record
      const folder = store.getFolder(TEST_ACCOUNT_ID, 'INBOX');
      assert.ok(folder);
      assert.strictEqual(folder.uidvalidity, 1001);
      assert.strictEqual(folder.totalMessages, 3);
      assert.strictEqual(folder.syncStatus, 'IDLE');

      // Verify event order
      assert.strictEqual(events[0][0], 'start');
      assert.strictEqual(events[1][0], 'added');
      assert.strictEqual(events[2][0], 'added');
      assert.strictEqual(events[3][0], 'added');
      assert.strictEqual(events[events.length - 1][0], 'synced');
    });
  });

  describe('2. Incremental Delta Sync', () => {
    it('fetches only newly arrived UIDs and skips previously cached messages', async () => {
      // 1. Initial sync ingests UIDs 1, 2, 3
      const initialRes = await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');
      assert.strictEqual(initialRes.newMessagesCount, 3);
      assert.strictEqual(store.getMaxUid(`${TEST_ACCOUNT_ID}:INBOX`), 3);

      // 2. Server gains new message UID 4
      const inboxMsgs = mockServer.syncState.messages.get('INBOX');
      inboxMsgs.set(4, {
        uid: 4,
        flags: [],
        subject: 'Urgent: Registration Deadline Extended',
        from: 'Registrar <registrar@uni.edu>',
        date: '2026-10-20T11:00:00Z',
        body: 'Registration has been extended through Friday.'
      });
      mockServer.syncState.uidNext = 5;

      // 3. Perform second incremental sync
      const newlyAddedUids = [];
      syncEngine.on('messageAdded', m => newlyAddedUids.push(m.uid));

      const deltaRes = await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      assert.strictEqual(deltaRes.newMessagesCount, 1);
      assert.deepStrictEqual(newlyAddedUids, [4]);

      // Total messages in SQLite should now be 4
      const allMsgs = store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:INBOX` });
      assert.strictEqual(allMsgs.length, 4);

      const msg4 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 4);
      assert.ok(msg4);
      assert.strictEqual(msg4.subject, 'Urgent: Registration Deadline Extended');
    });
  });

  describe('3. UIDVALIDITY Change Cache Invalidation', () => {
    it('purges cached local messages and re-syncs when remote UIDVALIDITY changes', async () => {
      // 1. Initial sync with UIDVALIDITY = 1001
      await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');
      assert.strictEqual(store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:INBOX` }).length, 3);

      // 2. Simulate server rebuild: UIDVALIDITY changes to 2002 with completely fresh messages
      mockServer.syncState.uidValidity = 2002;
      const freshMsgs = new Map();
      freshMsgs.set(100, {
        uid: 100,
        flags: ['\\Seen'],
        subject: 'Post-migration message',
        from: 'Admin <admin@service.com>',
        date: '2026-10-20T12:00:00Z',
        body: 'Mailbox migrated successfully.'
      });
      mockServer.syncState.messages.set('INBOX', freshMsgs);
      mockServer.syncState.unseenUids = new Set();

      let invalidatedEvent = null;
      syncEngine.on('cacheInvalidated', ev => {
        invalidatedEvent = ev;
      });

      // 3. Run sync
      const res = await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      assert.strictEqual(res.flushed, true);
      assert.strictEqual(res.uidValidity, 2002);
      assert.strictEqual(res.newMessagesCount, 1);

      assert.ok(invalidatedEvent);
      assert.strictEqual(invalidatedEvent.oldUidValidity, 1001);
      assert.strictEqual(invalidatedEvent.newUidValidity, 2002);

      // Old messages (1, 2, 3) must be gone, only message 100 exists
      const currentMsgs = store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:INBOX` });
      assert.strictEqual(currentMsgs.length, 1);
      assert.strictEqual(currentMsgs[0].uid, 100);
      assert.strictEqual(store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 1), null);
    });
  });

  describe('4. Flag Reconciliation (UNSEEN)', () => {
    it('reconciles local read/unread flags against remote UNSEEN search', async () => {
      // Initially messages 1 and 2 are unseen, message 3 is seen
      await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      let m1 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 1);
      let m3 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 3);
      assert.strictEqual(m1.isSeen, false);
      assert.strictEqual(m3.isSeen, true);

      // Remote server state changes: user read message 1, but marked message 3 as unread
      mockServer.syncState.unseenUids = new Set([3]);

      await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      m1 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 1);
      m3 = store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 3);

      assert.strictEqual(m1.isSeen, true, 'Message 1 should now be reconciled as seen');
      assert.strictEqual(m3.isSeen, false, 'Message 3 should now be reconciled as unseen');
    });
  });

  describe('5. Remote Deletion Pruning', () => {
    it('prunes local messages when removed from the remote mailbox', async () => {
      // Initial sync with 3 messages
      await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');
      assert.strictEqual(store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:INBOX` }).length, 3);

      // User deletes message UID 2 on remote webmail
      const inbox = mockServer.syncState.messages.get('INBOX');
      inbox.delete(2);

      let prunedEvent = null;
      syncEngine.on('messagesPruned', ev => {
        prunedEvent = ev;
      });

      const res = await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');

      assert.strictEqual(res.prunedCount, 1);
      assert.ok(prunedEvent);
      assert.strictEqual(prunedEvent.count, 1);

      // Verify UID 2 is pruned from SQLite
      assert.strictEqual(store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 2), null);
      assert.ok(store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 1));
      assert.ok(store.getMessageByUid(`${TEST_ACCOUNT_ID}:INBOX`, 3));
    });
  });

  describe('6. syncAccount & Folder Discovery', () => {
    it('discovers and synchronizes multiple folders for an account', async () => {
      // Add a message to Archive folder on server
      const archiveMsgs = new Map();
      archiveMsgs.set(50, {
        uid: 50,
        flags: ['\\Seen'],
        subject: 'Archived Tax Document',
        from: 'IRS <tax@internal.gov>',
        date: '2026-10-01T09:00:00Z',
        body: 'Your 1099 has been generated.'
      });
      mockServer.syncState.messages.set('Archive', archiveMsgs);

      const accountResult = await syncEngine.syncAccount(TEST_ACCOUNT_ID);

      assert.strictEqual(accountResult.accountId, TEST_ACCOUNT_ID);
      assert.strictEqual(accountResult.success, true);
      assert.strictEqual(accountResult.folders.length, 2);
      assert.strictEqual(accountResult.totalNewMessages, 4); // 3 from INBOX + 1 from Archive

      // Verify messages exist across both folders
      const inboxList = store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:INBOX` });
      const archiveList = store.getMessages({ folderId: `${TEST_ACCOUNT_ID}:Archive` });

      assert.strictEqual(inboxList.length, 3);
      assert.strictEqual(archiveList.length, 1);
      assert.strictEqual(archiveList[0].subject, 'Archived Tax Document');
    });

    it('skips concurrent overlapping sync on the same account', async () => {
      syncEngine._isSyncing.set(TEST_ACCOUNT_ID, true);

      const res = await syncEngine.syncAccount(TEST_ACCOUNT_ID, { skipIfActive: true });
      assert.strictEqual(res.skipped, true);

      syncEngine._isSyncing.set(TEST_ACCOUNT_ID, false);
    });
  });

  describe('7. Periodic Background Sync', () => {
    it('starts and stops periodic sync timer cleanly', () => {
      assert.strictEqual(syncEngine.isPeriodicSyncActive, false);

      syncEngine.startPeriodicSync(10000);
      assert.strictEqual(syncEngine.isPeriodicSyncActive, true);

      syncEngine.stopPeriodicSync();
      assert.strictEqual(syncEngine.isPeriodicSyncActive, false);
    });
  });

  describe('8. Error Isolation & Fault Handling', () => {
    it('marks folder sync status as ERROR and emits syncError on failure', async () => {
      // Force mock server to abort command on SELECT
      mockServer.syncState.customCommandHandler = ({ tag, cmd, serverSocket }) => {
        if (cmd === 'SELECT') {
          serverSocket.write(`${tag} NO [SERVERBUG] Mailbox damaged on disk\r\n`);
          return true;
        }
        return false;
      };

      await assert.rejects(async () => {
        await syncEngine.syncFolder(TEST_ACCOUNT_ID, 'INBOX');
      }, /Mailbox damaged on disk/i);

      // Verify folder record recorded error
      const folder = store.getFolder(TEST_ACCOUNT_ID, 'INBOX');
      assert.ok(folder);
      assert.strictEqual(folder.syncStatus, 'ERROR');
      assert.ok(folder.syncError);
    });
  });
});
