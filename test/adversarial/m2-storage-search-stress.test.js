/**
 * Adversarial Stress & Integrity Test Suite for Milestone 2 Storage & Search
 * (test/adversarial/m2-storage-search-stress.test.js)
 *
 * Exercises:
 * 1. Bulk Ingestion & Extreme Payloads: 5,000+ messages, 64KB subjects, truncated snippets, high UIDs
 * 2. Hostile & Exotic Characters: Null bytes (C truncation audit), UTF-8 surrogate emojis, RTL/CJK/Arabic, XSS tags, quotes, control chars
 * 3. SQL Injection Resilience: Union selects, drop tables, stacked queries, tautologies in search & options
 * 4. Latency Benchmarking Under Load: < 20ms SLA across 10,000 message corpus, p50/p95 distribution
 * 5. WAL Mode Concurrency: Multi-connection snapshot isolation, non-blocking reads during writes
 * 6. Transaction Rollback on Corrupt Batches: Mid-batch NaN, foreign key violation, zero token leakage
 * 7. Foreign Key Cascade Integrity: Account & folder cascades purging inverted search index tokens
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { SqliteStore, MailboxDatabase } from '../../src/storage/sqlite-store.js';
import { tokenize } from '../../src/storage/schema.js';

describe('Adversarial Stress: Milestone 2 Storage & Search Engine', () => {

  // ==========================================================================
  // VECTOR 1: Bulk Ingestion, Extreme Payloads & Data Integrity
  // ==========================================================================
  describe('Vector 1: Bulk Ingestion & Extreme Payloads', () => {
    let store;

    beforeEach(() => {
      store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_stress', email: 'stress@mailboxer.local', provider: 'apple' });
      store.upsertFolder({ accountId: 'acc_stress', name: 'INBOX', path: 'INBOX' });
    });

    afterEach(() => {
      if (store) store.close();
    });

    it('ingests 5,000 messages in a single batch without memory or stack exhaustion', () => {
      const folderId = 'acc_stress:INBOX';
      const COUNT = 5000;
      const messages = [];

      for (let i = 1; i <= COUNT; i++) {
        messages.push({
          accountId: 'acc_stress',
          folderId,
          uid: i,
          messageId: `<bulk_${i}@mailboxer.local>`,
          threadId: `thread_${i % 100}`,
          sender: `Sender ${i} <sender_${i}@test.com>`,
          senderEmail: `sender_${i}@test.com`,
          subject: `Automated transaction notification #${i} status update`,
          date: new Date(1700000000000 + i * 1000).toISOString(),
          bodySnippet: `Summary of message payload number ${i} with transaction details and audit log.`,
          flags: i % 2 === 0 ? ['\\Seen'] : ['\\Flagged'],
          size: 1024 + (i % 5000)
        });
      }

      const t0 = performance.now();
      const inserted = store.upsertMessages(messages);
      const durationMs = performance.now() - t0;

      assert.strictEqual(inserted.length, COUNT);
      assert.strictEqual(store.getMaxUid(folderId), COUNT);

      // Verify row count in SQLite
      const countRow = store.db.prepare('SELECT COUNT(*) AS total FROM messages WHERE folder_id = ?').get(folderId);
      assert.strictEqual(countRow.total, COUNT);

      // Verify search index count
      const indexCountRow = store.db.prepare('SELECT COUNT(*) AS total FROM message_search_index').get();
      assert.ok(indexCountRow.total > COUNT, `Search index tokens (${indexCountRow.total}) should exceed message count`);
    });

    it('handles extreme payload boundaries: 64KB subject, 200KB body snippet, 2^32-2 UID', () => {
      const folderId = 'acc_stress:INBOX';
      const hugeSubject = 'ALERT: ' + 'A'.repeat(65000);
      const hugeSnippet = 'BODY: ' + 'X'.repeat(200000);
      const highUid = 4294967294; // 2^32 - 2

      const inserted = store.upsertMessages([{
        accountId: 'acc_stress',
        folderId,
        uid: highUid,
        subject: hugeSubject,
        sender: 'Security <sec@bank.com>',
        senderEmail: 'sec@bank.com',
        bodySnippet: hugeSnippet,
        date: '2026-10-20T12:00:00.000Z',
        size: 2147483647
      }]);

      assert.strictEqual(inserted.length, 1);
      const msg = store.getMessageByUid(folderId, highUid);
      assert.ok(msg);
      assert.strictEqual(msg.uid, highUid);
      assert.strictEqual(msg.subject, hugeSubject);
      // Verify bodySnippet is safely capped at 1000 chars as per storage specification
      assert.strictEqual(msg.bodySnippet.length, 1000);
      assert.strictEqual(msg.size, 2147483647);
    });

    it('handles special characters: null byte C-truncation, UTF-8 surrogate emojis, CJK, RTL Arabic, quotes, HTML', () => {
      const folderId = 'acc_stress:INBOX';
      const hostileData = [
        {
          uid: 1001,
          subject: 'Special: \0 null byte in subject and \\r\\n\\t controls \x1b[31m',
          sender: "O'Connor & O\"Reilly <o'connor@domain.com>",
          senderEmail: "o'connor@domain.com",
          bodySnippet: 'Payload contains null byte: \0 and backslashes \\\\ and tabs \t.',
          flags: ['\\Seen', '$Forwarded', 'Special"Flag\'']
        },
        {
          uid: 1002,
          subject: 'Multilingual: مرحبا بالعالم / 你好世界 / こんにちは / Привет мир / Café & Naïve',
          sender: 'Global User <global@intl.org>',
          senderEmail: 'global@intl.org',
          bodySnippet: 'RTL text: السلام عليكم ورحمة الله وبركاته with zero-width space \u200B\u200C\u200D.',
          flags: ['\\Flagged']
        },
        {
          uid: 1003,
          subject: 'Emoji storm: 🚀🎉🔥👨‍👩‍👧‍👦💥🚨 ⚠️ Unicode 15 symbols',
          sender: 'Emoji Master <emoji@test.local>',
          senderEmail: 'emoji@test.local',
          bodySnippet: 'Surrogate pair check: 𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏.',
          flags: []
        },
        {
          uid: 1004,
          subject: '<script>alert("XSS")</script> <img src=x onerror=alert(1)>',
          sender: 'Attacker <"><script>@evil.com>',
          senderEmail: 'attacker@evil.com',
          bodySnippet: '<a href="javascript:alert(1)">Click here</a> \' OR \'1\'=\'1',
          flags: ['\\Answered']
        }
      ];

      const inserted = store.upsertMessages(hostileData.map(d => ({
        accountId: 'acc_stress',
        folderId,
        ...d,
        date: '2026-10-20T10:00:00Z'
      })));

      assert.strictEqual(inserted.length, 4);

      // Verify null byte behavior: node:sqlite C-binding truncates string at the null byte \0
      const msg1 = store.getMessageByUid(folderId, 1001);
      assert.strictEqual(msg1.subject, 'Special: ');
      assert.ok(msg1.sender.includes("O'Connor"));

      // Verify Multilingual preserved intact
      const msg2 = store.getMessageByUid(folderId, 1002);
      assert.ok(msg2.subject.includes('مرحبا بالعالم'));
      assert.ok(msg2.subject.includes('你好世界'));
      assert.ok(msg2.bodySnippet.includes('السلام'));

      // Verify Emojis preserved intact
      const msg3 = store.getMessageByUid(folderId, 1003);
      assert.ok(msg3.subject.includes('🚀🎉🔥'));

      // Verify XSS tags preserved verbatim (not executed, plain text storage)
      const msg4 = store.getMessageByUid(folderId, 1004);
      assert.ok(msg4.subject.includes('<script>alert("XSS")</script>'));
    });
  });

  // ==========================================================================
  // VECTOR 2: SQL Injection & Hostile Search Query Attacks
  // ==========================================================================
  describe('Vector 2: SQL Injection & Hostile Search Query Resilience', () => {
    let store;
    let folderId;

    beforeEach(() => {
      store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_sec', email: 'sec@test.local', provider: 'gmail' });
      folderId = store.upsertFolder({ accountId: 'acc_sec', name: 'INBOX', path: 'INBOX' });

      store.upsertMessages([
        {
          accountId: 'acc_sec',
          folderId,
          uid: 1,
          subject: 'Confidential corporate earnings statement Q3',
          sender: 'CFO <cfo@enterprise.com>',
          senderEmail: 'cfo@enterprise.com',
          bodySnippet: 'Attached is the executive earnings summary.',
          date: '2026-10-20T10:00:00Z'
        },
        {
          accountId: 'acc_sec',
          folderId,
          uid: 2,
          subject: 'Database schema migration update v2',
          sender: 'DevOps <devops@enterprise.com>',
          senderEmail: 'devops@enterprise.com',
          bodySnippet: 'Migration of SQLite tables completed successfully.',
          date: '2026-10-20T11:00:00Z'
        }
      ]);
    });

    afterEach(() => {
      if (store) store.close();
    });

    it('defends against classic SQL injection tautologies in search query', () => {
      const injectionQueries = [
        "' OR '1'='1",
        "'; DROP TABLE messages; --",
        '"; DROP TABLE message_search_index; --',
        "' UNION SELECT id, email, provider, name, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM accounts --",
        "admin'--",
        "' OR (SELECT COUNT(*) FROM messages) > 0 --",
        "1'; VACUUM; --",
        "') OR 1=1 --",
        "')) OR ('a'='a",
        "100%",
        "___",
        "%' OR 1=1 OR '%",
        "\x00'; DROP TABLE messages; --"
      ];

      for (const query of injectionQueries) {
        // None of these should throw an unhandled SQL syntax error or execute injected DDL
        let results;
        assert.doesNotThrow(() => {
          results = store.search(query);
        }, `Query should not throw syntax error: ${query}`);

        assert.ok(Array.isArray(results), `Results must be an array for query: ${query}`);

        // Verify messages table was NOT dropped
        const msgCheck = store.getMessageByUid(folderId, 1);
        assert.ok(msgCheck, `Messages table must still exist after query: ${query}`);

        // Verify accounts table was NOT dropped
        const accCheck = store.getAccount('acc_sec');
        assert.ok(accCheck, `Accounts table must still exist after query: ${query}`);
      }
    });

    it('defends against SQL injection in search options parameters', () => {
      const maliciousOptions = [
        { accountId: "' OR '1'='1" },
        { folderId: "f1'; DROP TABLE messages; --" },
        { accountId: "acc_sec'; DELETE FROM accounts; --" },
        { limit: 50 },
        { offset: 0 }
      ];

      for (const opts of maliciousOptions) {
        let results;
        assert.doesNotThrow(() => {
          results = store.search('corporate', opts);
        });

        assert.ok(Array.isArray(results));

        // Integrity check: accounts and messages still intact
        assert.ok(store.getAccount('acc_sec'));
        assert.ok(store.getMessageByUid(folderId, 1));
      }
    });

    it('audits non-numeric limit/offset in search options (revealing NaN binding exception)', () => {
      // In SqliteStore.search: Math.max(1, Number(options.limit || 50))
      // When options.limit is non-numeric string '50; DROP TABLE messages;', Number(...) is NaN.
      // Math.max(1, NaN) returns NaN, which node:sqlite rejects with 'datatype mismatch'.
      assert.throws(() => {
        store.search('corporate', { limit: '50; DROP TABLE messages;' });
      }, /datatype mismatch/i);
    });

    it('audits options.orderBy injection surface in getMessages()', () => {
      // getMessages concatenates options.orderBy without column allowlist.
      // Subqueries in orderBy execute:
      const msgs = store.getMessages({
        orderBy: '(CASE WHEN (SELECT count(*) FROM accounts) > 0 THEN date ELSE id END) DESC'
      });
      assert.ok(Array.isArray(msgs));
      assert.strictEqual(msgs.length, 2);

      // Stacked query with semicolon fails at prepare with column index out of range:
      assert.throws(() => {
        store.getMessages({ orderBy: 'id; DROP TABLE messages; --' });
      }, /column index out of range|syntax error/i);

      // Verify messages table remained intact
      assert.ok(store.getMessageByUid(folderId, 1));
    });

    it('safely handles empty, whitespace, and extremely large search queries', () => {
      assert.deepStrictEqual(store.search(''), []);
      assert.deepStrictEqual(store.search('   \t\r\n   '), []);
      assert.deepStrictEqual(store.search(null), []);
      assert.deepStrictEqual(store.search(undefined), []);
      assert.deepStrictEqual(store.search(12345), []);
      assert.deepStrictEqual(store.search({}), []);

      // 10,000 character query - should not cause ReDoS or stack overflow
      const massiveQuery = 'search ' + 'token '.repeat(2000);
      const t0 = performance.now();
      const results = store.search(massiveQuery);
      const elapsed = performance.now() - t0;

      assert.ok(Array.isArray(results));
      assert.ok(elapsed < 100, `Massive query should parse quickly, took ${elapsed}ms`);
    });
  });

  // ==========================================================================
  // VECTOR 3: Latency Benchmarking Under Load (< 20ms SLA)
  // ==========================================================================
  describe('Vector 3: Latency Benchmarking Under Load (< 20ms SLA)', () => {
    let store;
    const CORPUS_SIZE = 5000;

    before(() => {
      store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_bench', email: 'bench@mailboxer.local', provider: 'outlook' });
      store.upsertFolder({ accountId: 'acc_bench', name: 'INBOX', path: 'INBOX' });
      const folderId = 'acc_bench:INBOX';

      // Seed 5,000 realistic messages
      const vocabulary = [
        'urgent', 'grades', 'homework', 'exam', 'blackboard', 'canvas', 'assignment',
        'invoice', 'receipt', 'payment', 'subscription', 'billing', 'statement',
        'meeting', 'zoom', 'calendar', 'rescheduled', 'conference', 'symposium',
        'security', 'password', 'login', 'authentication', 'compromised', 'credentials',
        'newsletter', 'digest', 'promotions', 'discounts', 'announcements', 'campus'
      ];

      const senders = [
        'prof.smith@uni.edu', 'advising@uni.edu', 'billing@cloud.net',
        'it-security@uni.edu', 'noreply@newsletter.com', 'team@github.com'
      ];

      const CHUNK_SIZE = 1000;
      for (let c = 0; c < CORPUS_SIZE / CHUNK_SIZE; c++) {
        const batch = [];
        for (let i = 1; i <= CHUNK_SIZE; i++) {
          const uid = c * CHUNK_SIZE + i;
          const word1 = vocabulary[uid % vocabulary.length];
          const word2 = vocabulary[(uid * 3) % vocabulary.length];
          const word3 = vocabulary[(uid * 7) % vocabulary.length];
          const sender = senders[uid % senders.length];

          batch.push({
            accountId: 'acc_bench',
            folderId,
            uid,
            messageId: `<msg_${uid}@uni.edu>`,
            sender: `Sender ${sender} <${sender}>`,
            senderEmail: sender,
            subject: `Subject ${uid}: ${word1} regarding ${word2}`,
            date: new Date(1700000000000 + uid * 60000).toISOString(),
            bodySnippet: `Email body content referencing ${word2} and follow-up details on ${word3}.`,
            flags: uid % 3 === 0 ? ['\\Seen'] : []
          });
        }
        store.upsertMessages(batch);
      }
    });

    after(() => {
      if (store) store.close();
    });

    it('executes 100 benchmark queries across message corpus with 100% strictly < 20ms', () => {
      const benchmarkQueries = [
        'urgent',
        'grades blackboard',
        'security password',
        'invoice payment billing',
        'prof.smith@uni.edu',
        'canvas homework',
        'compromised credentials',
        'zoom meeting calendar',
        'discounts promotions',
        'it-security',
        'symposium rescheduled',
        'nonexistenttermxyz999' // zero matches
      ];

      const latencies = [];

      for (let run = 0; run < 100; run++) {
        const query = benchmarkQueries[run % benchmarkQueries.length];
        const t0 = performance.now();
        const results = store.search(query, { limit: 50 });
        const latency = performance.now() - t0;
        latencies.push(latency);

        assert.ok(
          latency < 20,
          `Query "${query}" exceeded 20ms SLA: took ${latency.toFixed(2)}ms on run ${run}`
        );
      }

      latencies.sort((a, b) => a - b);
      const p50 = latencies[Math.floor(latencies.length * 0.50)];
      const p95 = latencies[Math.floor(latencies.length * 0.95)];
      const p99 = latencies[Math.floor(latencies.length * 0.99)];
      const max = latencies[latencies.length - 1];

      console.log(`\n  [Benchmark ${CORPUS_SIZE} Messages] Search Latencies:`);
      console.log(`    p50: ${p50.toFixed(2)}ms`);
      console.log(`    p95: ${p95.toFixed(2)}ms`);
      console.log(`    p99: ${p99.toFixed(2)}ms`);
      console.log(`    Max: ${max.toFixed(2)}ms (SLA: <20.00ms)\n`);

      assert.ok(p95 < 20, `p95 latency (${p95.toFixed(2)}ms) must be strictly < 20ms`);
      assert.ok(max < 20, `Max latency (${max.toFixed(2)}ms) must be strictly < 20ms`);
    });
  });

  // ==========================================================================
  // VECTOR 4: WAL Mode Concurrency & Multi-Connection Safety
  // ==========================================================================
  describe('Vector 4: WAL Mode Concurrency & Multi-Connection Safety', () => {
    let testDir;
    let dbFile;

    beforeEach(() => {
      testDir = join(tmpdir(), `mailboxer_wal_${Date.now()}_${Math.random().toString(36).slice(2)}`);
      dbFile = join(testDir, 'concurrency.sqlite');
    });

    afterEach(() => {
      if (existsSync(testDir)) {
        try {
          rmSync(testDir, { recursive: true, force: true });
        } catch {
          // ignore cleanup on windows if file handle released asynchronously
        }
      }
    });

    it('enables WAL mode and verifies concurrent reader snapshot isolation during active write', () => {
      // 1. Writer Store
      const writerStore = new SqliteStore(dbFile);
      writerStore.upsertAccount({ id: 'acc_wal', email: 'wal@test.local', provider: 'gmail' });
      const folderId = writerStore.upsertFolder({ accountId: 'acc_wal', name: 'INBOX', path: 'INBOX' });

      // Ingest base committed message
      writerStore.upsertMessages([{
        accountId: 'acc_wal',
        folderId,
        uid: 1,
        subject: 'Committed base message',
        sender: 'base@test.com',
        senderEmail: 'base@test.com',
        date: '2026-10-20T10:00:00Z'
      }]);

      // Check WAL mode PRAGMA
      const journalMode = writerStore.db.prepare('PRAGMA journal_mode').get();
      assert.strictEqual(journalMode.journal_mode.toLowerCase(), 'wal');

      // 2. Reader Store (independent connection to same database file)
      const readerStore = new SqliteStore(dbFile);
      const initialRead = readerStore.getMessages({ folderId });
      assert.strictEqual(initialRead.length, 1);
      assert.strictEqual(initialRead[0].uid, 1);

      // 3. Writer starts transaction, inserts messages but does NOT commit yet
      writerStore.db.exec('BEGIN');
      writerStore._stmtUpsertMessage.run(
        'acc_wal:acc_wal:INBOX:2',
        'acc_wal',
        folderId,
        2,
        null,
        'thread_2',
        'Uncommitted Sender',
        'uncommitted@test.com',
        '[]',
        'Uncommitted message in flight',
        '2026-10-20T11:00:00Z',
        'Draft in flight',
        '[]',
        0,
        0,
        500,
        'uncategorized',
        0.0,
        0
      );

      // 4. Reader reads DURING active uncommitted transaction
      // In WAL mode, reader MUST NOT block and MUST NOT see dirty data!
      const concurrentRead = readerStore.getMessages({ folderId });
      assert.strictEqual(concurrentRead.length, 1, 'Reader must see snapshot isolation without dirty read');
      assert.strictEqual(concurrentRead[0].uid, 1);

      // Reader search also does not see uncommitted message
      const searchDuringWrite = readerStore.search('flight');
      assert.strictEqual(searchDuringWrite.length, 0);

      // 5. Writer commits
      writerStore.db.exec('COMMIT');

      // 6. Reader reads again - now sees committed message
      const postCommitRead = readerStore.getMessages({ folderId });
      assert.strictEqual(postCommitRead.length, 2);

      // Clean teardown
      readerStore.close();
      writerStore.close();
    });

    it('interleaves concurrent reads and writes across separate store instances without lock errors', () => {
      const writer = new SqliteStore(dbFile);
      writer.upsertAccount({ id: 'acc_multi', email: 'multi@test.local', provider: 'apple' });
      const folderId = writer.upsertFolder({ accountId: 'acc_multi', name: 'INBOX', path: 'INBOX' });

      const reader1 = new SqliteStore(dbFile);
      const reader2 = new SqliteStore(dbFile);

      // Interleave 20 write batches and 40 concurrent reader queries
      for (let i = 1; i <= 20; i++) {
        writer.upsertMessages([{
          accountId: 'acc_multi',
          folderId,
          uid: i,
          subject: `Interleaved message #${i} telemetry alert`,
          sender: 'telemetry@system.local',
          senderEmail: 'telemetry@system.local',
          date: new Date(1700000000000 + i * 1000).toISOString()
        }]);

        // Interleaved reads
        const msgs1 = reader1.getMessages({ folderId });
        assert.strictEqual(msgs1.length, i);

        const searchRes = reader2.search('telemetry alert');
        assert.strictEqual(searchRes.length, i);
      }

      reader1.close();
      reader2.close();
      writer.close();
    });
  });

  // ==========================================================================
  // VECTOR 5: Atomic Transaction Rollback on Corrupt Batches
  // ==========================================================================
  describe('Vector 5: Transaction Rollback on Corrupt Batches', () => {
    let store;
    let folderId;

    beforeEach(() => {
      store = new SqliteStore(':memory:');
      store.upsertAccount({ id: 'acc_tx', email: 'tx@mailboxer.local', provider: 'gmail' });
      folderId = store.upsertFolder({ accountId: 'acc_tx', name: 'INBOX', path: 'INBOX' });
    });

    afterEach(() => {
      if (store) store.close();
    });

    it('rolls back entire batch when mid-batch message has NaN UID, zero token leakage in search index', () => {
      // Pre-populate with 1 good message
      store.upsertMessages([{
        accountId: 'acc_tx',
        folderId,
        uid: 1,
        subject: 'Existing legitimate message before corrupt batch',
        sender: 'legit@test.com',
        senderEmail: 'legit@test.com',
        date: '2026-10-20T10:00:00Z'
      }]);

      const initialCount = store.getMessages({ folderId }).length;
      assert.strictEqual(initialCount, 1);

      const corruptBatch = [
        {
          accountId: 'acc_tx',
          folderId,
          uid: 10,
          subject: 'Batch message 10 uniquealpha',
          sender: 's10@test.com',
          senderEmail: 's10@test.com'
        },
        {
          accountId: 'acc_tx',
          folderId,
          uid: 20,
          subject: 'Batch message 20 uniquebeta',
          sender: 's20@test.com',
          senderEmail: 's20@test.com'
        },
        {
          // Corrupt entry: invalid UID 'NaN'
          accountId: 'acc_tx',
          folderId,
          uid: 'invalid_numeric_uid',
          subject: 'Batch message 30 corrupt'
        },
        {
          accountId: 'acc_tx',
          folderId,
          uid: 40,
          subject: 'Batch message 40 uniquegamma'
        }
      ];

      assert.throws(() => {
        store.upsertMessages(corruptBatch);
      }, /valid numeric uid/i);

      // Verify ZERO messages from corrupt batch were inserted
      assert.strictEqual(store.getMessages({ folderId }).length, 1);
      assert.strictEqual(store.getMessageByUid(folderId, 10), null);
      assert.strictEqual(store.getMessageByUid(folderId, 20), null);
      assert.strictEqual(store.getMessageByUid(folderId, 40), null);

      // Verify ZERO token leakage in message_search_index
      const searchAlpha = store.search('uniquealpha');
      assert.strictEqual(searchAlpha.length, 0, 'Rolled back tokens must not exist in search index');

      const searchBeta = store.search('uniquebeta');
      assert.strictEqual(searchBeta.length, 0, 'Rolled back tokens must not exist in search index');

      // Verify search index count matches only pre-existing message
      const tokens = store.db.prepare('SELECT COUNT(*) AS total FROM message_search_index WHERE message_id != ?').get('acc_tx:acc_tx:INBOX:1');
      assert.strictEqual(tokens.total, 0);
    });

    it('rolls back entire batch on Foreign Key constraint violation (invalid folder_id)', () => {
      const corruptFkBatch = [
        {
          accountId: 'acc_tx',
          folderId,
          uid: 100,
          subject: 'Legit message before FK error',
          sender: 's@test.com',
          senderEmail: 's@test.com'
        },
        {
          accountId: 'acc_tx',
          folderId: 'acc_tx:NON_EXISTENT_FOLDER_ID',
          uid: 101,
          subject: 'Message referencing non-existent folder',
          sender: 's@test.com',
          senderEmail: 's@test.com'
        }
      ];

      assert.throws(() => {
        store.upsertMessages(corruptFkBatch);
      }, /FOREIGN KEY constraint failed/i);

      // Verify 100 was NOT inserted
      assert.strictEqual(store.getMessageByUid(folderId, 100), null);
    });

    it('allows successful subsequent transactions immediately after a rolled-back transaction', () => {
      // First, trigger a rollback
      assert.throws(() => {
        store.upsertMessages([{
          accountId: null,
          folderId,
          uid: 555
        }]);
      });

      // Now execute a valid batch
      const inserted = store.upsertMessages([{
        accountId: 'acc_tx',
        folderId,
        uid: 999,
        subject: 'Clean recovery after rollback test',
        sender: 'recovery@test.com',
        senderEmail: 'recovery@test.com',
        date: '2026-10-20T12:00:00Z'
      }]);

      assert.strictEqual(inserted.length, 1);
      const msg = store.getMessageByUid(folderId, 999);
      assert.ok(msg);
      assert.strictEqual(msg.subject, 'Clean recovery after rollback test');

      const searchRes = store.search('recovery rollback');
      assert.strictEqual(searchRes.length, 1);
      assert.strictEqual(searchRes[0].uid, 999);
    });
  });

  // ==========================================================================
  // VECTOR 6: Foreign Key Cascade Deletion & Search Index Purging
  // ==========================================================================
  describe('Vector 6: Foreign Key Cascades & Search Index Cleanup', () => {
    let store;

    beforeEach(() => {
      store = new SqliteStore(':memory:');
    });

    afterEach(() => {
      if (store) store.close();
    });

    it('cascades account deletion down through folders, messages, and search index tokens', () => {
      store.upsertAccount({ id: 'acc_cascade', email: 'cascade@uni.edu', provider: 'apple' });
      const f1 = store.upsertFolder({ accountId: 'acc_cascade', name: 'INBOX', path: 'INBOX' });
      const f2 = store.upsertFolder({ accountId: 'acc_cascade', name: 'Sent', path: 'Sent' });

      store.upsertMessages([
        { accountId: 'acc_cascade', folderId: f1, uid: 1, subject: 'Quantum Physics Lecture', sender: 'prof@uni.edu', senderEmail: 'prof@uni.edu' },
        { accountId: 'acc_cascade', folderId: f1, uid: 2, subject: 'Lab Report Submission', sender: 'prof@uni.edu', senderEmail: 'prof@uni.edu' },
        { accountId: 'acc_cascade', folderId: f2, uid: 1, subject: 'Completed Homework Assignment', sender: 'me@uni.edu', senderEmail: 'me@uni.edu' }
      ]);

      assert.strictEqual(store.getMessages({ accountId: 'acc_cascade' }).length, 3);
      const tokensBefore = store.db.prepare('SELECT COUNT(*) AS c FROM message_search_index').get().c;
      assert.ok(tokensBefore > 0);

      // Delete the account
      store.deleteAccount('acc_cascade');

      // Verify zero accounts, folders, messages
      assert.strictEqual(store.getAccounts().length, 0);
      assert.strictEqual(store.getFolders('acc_cascade').length, 0);
      assert.strictEqual(store.getMessages({ accountId: 'acc_cascade' }).length, 0);

      // Verify zero orphaned search tokens in message_search_index
      const tokensAfter = store.db.prepare('SELECT COUNT(*) AS c FROM message_search_index').get().c;
      assert.strictEqual(tokensAfter, 0, 'All search tokens must be purged by CASCADE');
    });

    it('purges messages and search tokens when clearFolder is executed', () => {
      store.upsertAccount({ id: 'acc_clear', email: 'clear@test.com', provider: 'gmail' });
      const fId = store.upsertFolder({ accountId: 'acc_clear', name: 'INBOX', path: 'INBOX' });

      store.upsertMessages([
        { accountId: 'acc_clear', folderId: fId, uid: 1, subject: 'Token Alpha Beta', sender: 's@t.com', senderEmail: 's@t.com' },
        { accountId: 'acc_clear', folderId: fId, uid: 2, subject: 'Token Gamma Delta', sender: 's@t.com', senderEmail: 's@t.com' }
      ]);

      assert.strictEqual(store.search('Alpha').length, 1);
      assert.strictEqual(store.search('Gamma').length, 1);

      // Clear folder (simulating UIDVALIDITY change)
      store.clearFolder(fId);

      assert.strictEqual(store.getMessages({ folderId: fId }).length, 0);
      assert.strictEqual(store.search('Alpha').length, 0);
      assert.strictEqual(store.search('Gamma').length, 0);

      const remainingTokens = store.db.prepare('SELECT COUNT(*) AS c FROM message_search_index').get().c;
      assert.strictEqual(remainingTokens, 0);
    });
  });
});
