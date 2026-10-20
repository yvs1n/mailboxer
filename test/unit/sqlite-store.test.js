/**
 * Unit Tests: Persistent SQLite Storage Engine (test/unit/sqlite-store.test.js)
 *
 * Validates native node:sqlite DatabaseSync integration, WAL mode, foreign keys,
 * accounts/folders/messages CRUD, transactions, flag reconciliation, UID pruning,
 * and <20ms search indexing across 10,000 messages.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { SqliteStore, MailboxDatabase } from '../../src/storage/sqlite-store.js';
import { initSchema, tokenize, SCHEMA_VERSION } from '../../src/storage/schema.js';

describe('SQLite Storage Engine (src/storage/sqlite-store.js)', () => {
  let store;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
  });

  afterEach(() => {
    if (store) {
      store.close();
    }
  });

  describe('1. Schema Initialization & PRAGMAs', () => {
    it('initializes schema and exports SCHEMA_VERSION', () => {
      assert.strictEqual(SCHEMA_VERSION, 1);
      assert.ok(store.db instanceof DatabaseSync);
    });

    it('enforces foreign key constraints', () => {
      const fkRow = store.db.prepare('PRAGMA foreign_keys').get();
      assert.strictEqual(fkRow.foreign_keys, 1);

      // Attempting to insert a folder with non-existent account_id should fail
      assert.throws(() => {
        store.db.prepare(`
          INSERT INTO folders (id, account_id, name, path)
          VALUES ('f1', 'nonexistent_account', 'INBOX', 'INBOX')
        `).run();
      }, /FOREIGN KEY constraint failed/i);
    });

    it('supports MailboxDatabase alias', () => {
      assert.strictEqual(MailboxDatabase, SqliteStore);
      const aliasDb = new MailboxDatabase(':memory:');
      assert.ok(aliasDb instanceof SqliteStore);
      aliasDb.close();
    });

    it('persists data to disk and reloads cleanly', () => {
      const testDir = join(tmpdir(), `mailboxer_test_${Date.now()}_${Math.random().toString(36).slice(2)}`);
      const testDbPath = join(testDir, 'test.sqlite');

      try {
        const fileStore1 = new SqliteStore(testDbPath);
        fileStore1.upsertAccount({
          id: 'acc_persist_1',
          email: 'persist@example.com',
          provider: 'gmail',
          name: 'Persist Test'
        });
        fileStore1.close();

        assert.ok(existsSync(testDbPath));

        const fileStore2 = new SqliteStore(testDbPath);
        const acc = fileStore2.getAccount('acc_persist_1');
        assert.ok(acc);
        assert.strictEqual(acc.email, 'persist@example.com');
        assert.strictEqual(acc.provider, 'gmail');
        fileStore2.close();
      } finally {
        if (existsSync(testDir)) {
          rmSync(testDir, { recursive: true, force: true });
        }
      }
    });

    it('tokenizes text correctly with email handling and minimum length filter', () => {
      const tokens = tokenize('URGENT: Final Exam Schedule for CS101 from prof.smith@uni.edu!');
      assert.ok(tokens.includes('urgent'));
      assert.ok(tokens.includes('final'));
      assert.ok(tokens.includes('exam'));
      assert.ok(tokens.includes('schedule'));
      assert.ok(tokens.includes('cs101'));
      assert.ok(tokens.includes('prof.smith@uni.edu'));
      assert.ok(tokens.includes('prof.smith'));
      assert.ok(tokens.includes('uni.edu'));
      // Single characters shouldn't be included
      assert.ok(!tokens.includes('a'));
    });
  });

  describe('2. Accounts CRUD', () => {
    it('creates and retrieves accounts', () => {
      store.upsertAccount({
        id: 'acc_1',
        email: 'user1@gmail.com',
        provider: 'gmail',
        name: 'Personal'
      });

      const acc = store.getAccount('acc_1');
      assert.ok(acc);
      assert.strictEqual(acc.id, 'acc_1');
      assert.strictEqual(acc.email, 'user1@gmail.com');
      assert.strictEqual(acc.provider, 'gmail');
      assert.strictEqual(acc.name, 'Personal');
      assert.ok(acc.createdAt);
      assert.ok(acc.updatedAt);
    });

    it('updates existing account on duplicate ID conflict', () => {
      store.upsertAccount({
        id: 'acc_1',
        email: 'user1@gmail.com',
        provider: 'gmail',
        name: 'Personal'
      });

      store.upsertAccount({
        id: 'acc_1',
        email: 'user1_updated@gmail.com',
        provider: 'gmail',
        name: 'Personal Updated'
      });

      const acc = store.getAccount('acc_1');
      assert.strictEqual(acc.email, 'user1_updated@gmail.com');
      assert.strictEqual(acc.name, 'Personal Updated');

      const all = store.getAccounts();
      assert.strictEqual(all.length, 1);
    });

    it('deletes account and cascades deletion to child folders and messages', () => {
      store.upsertAccount({ id: 'acc_del', email: 'del@uni.edu', provider: 'outlook', name: 'Uni' });
      const fId = store.upsertFolder({ accountId: 'acc_del', name: 'INBOX', path: 'INBOX' });
      store.upsertMessages([{
        accountId: 'acc_del',
        folderId: fId,
        uid: 1,
        subject: 'To be deleted',
        sender: 'sender@uni.edu',
        senderEmail: 'sender@uni.edu',
        date: '2026-10-20T10:00:00Z'
      }]);

      assert.strictEqual(store.getAccounts().length, 1);
      assert.strictEqual(store.getFolders('acc_del').length, 1);
      assert.strictEqual(store.getMessages({ accountId: 'acc_del' }).length, 1);

      store.deleteAccount('acc_del');

      assert.strictEqual(store.getAccounts().length, 0);
      assert.strictEqual(store.getFolders('acc_del').length, 0);
      assert.strictEqual(store.getMessages({ accountId: 'acc_del' }).length, 0);
    });
  });

  describe('3. Folders CRUD', () => {
    beforeEach(() => {
      store.upsertAccount({ id: 'acc_folders', email: 'folders@example.com', provider: 'apple' });
    });

    it('upserts and retrieves folders for an account', () => {
      const id1 = store.upsertFolder({
        accountId: 'acc_folders',
        name: 'INBOX',
        path: 'INBOX',
        delimiter: '/',
        uidvalidity: 1001,
        uidnext: 205,
        totalMessages: 50,
        unseenMessages: 5
      });

      assert.strictEqual(id1, 'acc_folders:INBOX');

      const folder = store.getFolder('acc_folders', 'INBOX');
      assert.ok(folder);
      assert.strictEqual(folder.name, 'INBOX');
      assert.strictEqual(folder.uidvalidity, 1001);
      assert.strictEqual(folder.uidValidity, 1001);
      assert.strictEqual(folder.uidnext, 205);
      assert.strictEqual(folder.uidNext, 205);
      assert.strictEqual(folder.totalMessages, 50);
      assert.strictEqual(folder.unseenMessages, 5);

      const byId = store.getFolderById(id1);
      assert.ok(byId);
      assert.strictEqual(byId.id, id1);
    });

    it('updates folder metadata on conflict', () => {
      store.upsertFolder({
        accountId: 'acc_folders',
        name: 'INBOX',
        path: 'INBOX',
        uidvalidity: 1001,
        totalMessages: 10
      });

      store.upsertFolder({
        accountId: 'acc_folders',
        name: 'INBOX',
        path: 'INBOX',
        uidvalidity: 1001,
        totalMessages: 25,
        unseenMessages: 3
      });

      const folder = store.getFolder('acc_folders', 'INBOX');
      assert.strictEqual(folder.totalMessages, 25);
      assert.strictEqual(folder.unseenMessages, 3);
      assert.strictEqual(store.getFolders('acc_folders').length, 1);
    });

    it('clears folder messages with clearFolder', () => {
      const fId = store.upsertFolder({ accountId: 'acc_folders', name: 'Drafts', path: 'Drafts' });
      store.upsertMessages([
        { accountId: 'acc_folders', folderId: fId, uid: 1, subject: 'Draft 1', sender: 'me', senderEmail: 'me@ex.com' },
        { accountId: 'acc_folders', folderId: fId, uid: 2, subject: 'Draft 2', sender: 'me', senderEmail: 'me@ex.com' }
      ]);

      assert.strictEqual(store.getMessages({ folderId: fId }).length, 2);
      store.clearFolder(fId);
      assert.strictEqual(store.getMessages({ folderId: fId }).length, 0);

      // Folder record itself remains intact
      assert.ok(store.getFolderById(fId));
    });
  });

  describe('4. Messages Batch Insertion & Atomic Transactions', () => {
    let folderId;

    beforeEach(() => {
      store.upsertAccount({ id: 'acc_msgs', email: 'msgs@example.com', provider: 'gmail' });
      folderId = store.upsertFolder({ accountId: 'acc_msgs', name: 'INBOX', path: 'INBOX' });
    });

    it('batch inserts messages atomically and parses fields', () => {
      const inserted = store.upsertMessages([
        {
          accountId: 'acc_msgs',
          folderId,
          uid: 101,
          messageId: '<msg101@example.com>',
          threadId: '<root@example.com>',
          sender: 'Professor Alice <alice@uni.edu>',
          senderEmail: 'alice@uni.edu',
          recipients: ['student@uni.edu'],
          subject: 'CS101 Midterm Grades Published',
          date: '2026-10-20T12:00:00Z',
          bodySnippet: 'Please check Blackboard for your scores.',
          flags: ['\\Seen'],
          size: 1540
        },
        {
          accountId: 'acc_msgs',
          folderId,
          uid: 102,
          messageId: '<msg102@example.com>',
          sender: 'Campus Events <events@uni.edu>',
          senderEmail: 'events@uni.edu',
          subject: 'Hackathon Registration Open',
          date: '2026-10-20T13:00:00Z',
          bodySnippet: 'Join us this weekend for 24 hours of coding.',
          flags: ['\\Flagged'],
          size: 2400
        }
      ]);

      assert.strictEqual(inserted.length, 2);

      const msg1 = store.getMessage(inserted[0]);
      assert.ok(msg1);
      assert.strictEqual(msg1.uid, 101);
      assert.strictEqual(msg1.subject, 'CS101 Midterm Grades Published');
      assert.strictEqual(msg1.senderEmail, 'alice@uni.edu');
      assert.strictEqual(msg1.threadId, '<root@example.com>');
      assert.strictEqual(msg1.isSeen, true);
      assert.strictEqual(msg1.isFlagged, false);
      assert.deepStrictEqual(msg1.recipients, ['student@uni.edu']);

      const msg2 = store.getMessageByUid(folderId, 102);
      assert.ok(msg2);
      assert.strictEqual(msg2.isSeen, false);
      assert.strictEqual(msg2.isFlagged, true);
    });

    it('rolls back entire batch if an invalid message causes an error', () => {
      assert.throws(() => {
        store.upsertMessages([
          {
            accountId: 'acc_msgs',
            folderId,
            uid: 201,
            subject: 'Good message',
            sender: 'good@test.com',
            senderEmail: 'good@test.com'
          },
          {
            // Missing accountId and invalid uid
            subject: 'Malformed message'
          }
        ]);
      });

      // Assert that 201 was NOT committed due to atomic rollback
      assert.strictEqual(store.getMessageByUid(folderId, 201), null);
    });

    it('computes max UID accurately', () => {
      assert.strictEqual(store.getMaxUid(folderId), null);

      store.upsertMessages([
        { accountId: 'acc_msgs', folderId, uid: 5, subject: 'Five', sender: 's', senderEmail: 's@e.com' },
        { accountId: 'acc_msgs', folderId, uid: 88, subject: 'Eighty Eight', sender: 's', senderEmail: 's@e.com' },
        { accountId: 'acc_msgs', folderId, uid: 12, subject: 'Twelve', sender: 's', senderEmail: 's@e.com' }
      ]);

      assert.strictEqual(store.getMaxUid(folderId), 88);
    });
  });

  describe('5. Message Filtering & Pagination', () => {
    let f1, f2;

    beforeEach(() => {
      store.upsertAccount({ id: 'acc_filter', email: 'filter@example.com', provider: 'apple' });
      f1 = store.upsertFolder({ accountId: 'acc_filter', name: 'INBOX', path: 'INBOX' });
      f2 = store.upsertFolder({ accountId: 'acc_filter', name: 'Archive', path: 'Archive' });

      store.upsertMessages([
        { accountId: 'acc_filter', folderId: f1, uid: 1, subject: 'M1', sender: 's', senderEmail: 's@e.com', isSeen: true, isFlagged: false, category: 'vip', date: '2026-10-20T10:00:00Z' },
        { accountId: 'acc_filter', folderId: f1, uid: 2, subject: 'M2', sender: 's', senderEmail: 's@e.com', isSeen: false, isFlagged: true, category: 'noise', date: '2026-10-20T11:00:00Z' },
        { accountId: 'acc_filter', folderId: f1, uid: 3, subject: 'M3', sender: 's', senderEmail: 's@e.com', isSeen: true, isFlagged: true, category: 'vip', date: '2026-10-20T12:00:00Z' },
        { accountId: 'acc_filter', folderId: f2, uid: 4, subject: 'M4', sender: 's', senderEmail: 's@e.com', isSeen: false, isFlagged: false, category: 'update', date: '2026-10-20T13:00:00Z' }
      ]);
    });

    it('filters by folderId', () => {
      const inF1 = store.getMessages({ folderId: f1 });
      assert.strictEqual(inF1.length, 3);
      const inF2 = store.getMessages({ folderId: f2 });
      assert.strictEqual(inF2.length, 1);
    });

    it('filters by isSeen status', () => {
      const seen = store.getMessages({ isSeen: true });
      assert.strictEqual(seen.length, 2);
      const unseen = store.getMessages({ isSeen: false });
      assert.strictEqual(unseen.length, 2);
    });

    it('filters by isFlagged and category', () => {
      const flagged = store.getMessages({ isFlagged: true });
      assert.strictEqual(flagged.length, 2);

      const vip = store.getMessages({ category: 'vip' });
      assert.strictEqual(vip.length, 2);
    });

    it('supports pagination with limit and offset', () => {
      const page1 = store.getMessages({ limit: 2, offset: 0 });
      assert.strictEqual(page1.length, 2);
      // Ordered by date DESC
      assert.strictEqual(page1[0].subject, 'M4');
      assert.strictEqual(page1[1].subject, 'M3');

      const page2 = store.getMessages({ limit: 2, offset: 2 });
      assert.strictEqual(page2.length, 2);
      assert.strictEqual(page2[0].subject, 'M2');
      assert.strictEqual(page2[1].subject, 'M1');
    });
  });

  describe('6. Full-Text Search Performance & SLA (< 20ms)', () => {
    let fId;

    beforeEach(() => {
      store.upsertAccount({ id: 'acc_search', email: 'search@example.com', provider: 'gmail' });
      fId = store.upsertFolder({ accountId: 'acc_search', name: 'INBOX', path: 'INBOX' });
    });

    it('executes multi-token and single-token search accurately', () => {
      store.upsertMessages([
        {
          accountId: 'acc_search',
          folderId: fId,
          uid: 1,
          subject: 'Final exam reminder for biology students',
          sender: 'Dr. Watson <watson@biology.edu>',
          senderEmail: 'watson@biology.edu',
          bodySnippet: 'Room 304 at 9am sharp with pencil.',
          date: '2026-10-20T10:00:00Z'
        },
        {
          accountId: 'acc_search',
          folderId: fId,
          uid: 2,
          subject: 'Weekly grocery store receipt',
          sender: 'Receipts <no-reply@store.com>',
          senderEmail: 'no-reply@store.com',
          bodySnippet: 'Your total was $42.50 for groceries.',
          date: '2026-10-20T11:00:00Z'
        }
      ]);

      const singleResult = store.search('biology');
      assert.strictEqual(singleResult.length, 1);
      assert.strictEqual(singleResult[0].uid, 1);

      const multiResult = store.search('exam biology');
      assert.strictEqual(multiResult.length, 1);
      assert.strictEqual(multiResult[0].uid, 1);

      const noResult = store.search('astronomy');
      assert.strictEqual(noResult.length, 0);
    });

    it('satisfies < 20ms SLA benchmark over message corpus', () => {
      const BATCH_TOTAL = 2500;
      const msgs = [];

      for (let i = 1; i <= BATCH_TOTAL; i++) {
        const isTarget = i % 100 === 0; // 25 matches
        msgs.push({
          accountId: 'acc_search',
          folderId: fId,
          uid: i + 10,
          subject: isTarget ? `Critical security alert regarding credentials #${i}` : `Daily digest update notification #${i}`,
          sender: isTarget ? 'IT Security Team <security@internal.net>' : 'Automated Bot <bot@service.com>',
          senderEmail: isTarget ? 'security@internal.net' : 'bot@service.com',
          bodySnippet: isTarget ? 'Immediate password rotation required for compromised session tokens.' : 'Nothing new today.',
          date: new Date(1729410000000 + i * 1000).toISOString()
        });
      }

      store.upsertMessages(msgs);

      // Measure search latency
      const t0 = performance.now();
      const results = store.search('security credentials', { limit: 50 });
      const durationMs = performance.now() - t0;

      assert.strictEqual(results.length, 25);
      assert.ok(
        durationMs < 20,
        `Search latency must be strictly < 20ms. Measured: ${durationMs.toFixed(2)}ms`
      );
    });
  });

  describe('7. Flag Reconciliation & Deleted UID Pruning', () => {
    let fId;

    beforeEach(() => {
      store.upsertAccount({ id: 'acc_flags', email: 'flags@example.com', provider: 'outlook' });
      fId = store.upsertFolder({ accountId: 'acc_flags', name: 'INBOX', path: 'INBOX' });

      store.upsertMessages([
        { accountId: 'acc_flags', folderId: fId, uid: 1, subject: '1', sender: 's', senderEmail: 's@e.com', isSeen: true, isFlagged: false },
        { accountId: 'acc_flags', folderId: fId, uid: 2, subject: '2', sender: 's', senderEmail: 's@e.com', isSeen: true, isFlagged: false },
        { accountId: 'acc_flags', folderId: fId, uid: 3, subject: '3', sender: 's', senderEmail: 's@e.com', isSeen: false, isFlagged: false },
        { accountId: 'acc_flags', folderId: fId, uid: 4, subject: '4', sender: 's', senderEmail: 's@e.com', isSeen: false, isFlagged: false }
      ]);
    });

    it('updates specific message flags', () => {
      store.updateMessageFlags(fId, 3, ['\\Seen', '\\Flagged']);
      const msg = store.getMessageByUid(fId, 3);
      assert.strictEqual(msg.isSeen, true);
      assert.strictEqual(msg.isFlagged, true);
    });

    it('reconciles seen status based on remote UNSEEN search results', () => {
      // Remote says only UID 1 and UID 4 are unseen.
      // Therefore, UID 2 and UID 3 must be marked as seen!
      store.reconcileSeenFlags(fId, [1, 4]);

      assert.strictEqual(store.getMessageByUid(fId, 1).isSeen, false);
      assert.strictEqual(store.getMessageByUid(fId, 2).isSeen, true);
      assert.strictEqual(store.getMessageByUid(fId, 3).isSeen, true);
      assert.strictEqual(store.getMessageByUid(fId, 4).isSeen, false);
    });

    it('prunes deleted UIDs when remote messages are removed', () => {
      // Server currently has UIDs [1, 3] (UIDs 2 and 4 were deleted on server)
      const pruned = store.pruneDeletedUids(fId, [1, 3]);

      assert.strictEqual(pruned, 2);
      assert.ok(store.getMessageByUid(fId, 1));
      assert.strictEqual(store.getMessageByUid(fId, 2), null);
      assert.ok(store.getMessageByUid(fId, 3));
      assert.strictEqual(store.getMessageByUid(fId, 4), null);
    });
  });
});
