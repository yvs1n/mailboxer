/**
 * Unit Tests: MIME Cleaning, 2025 Freshness & PWA Manifest Assets
 *
 * Verifies:
 * 1. cleanMimeBody & decodeQuotedPrintable RFC 2045 compliance
 * 2. Purging legacy messages older than 2025-01-01
 * 3. Sync engine 2025 date enforcement
 * 4. PWA manifest and mobile app icons integrity
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanMimeBody, decodeQuotedPrintable, htmlToCleanText } from '../../src/connection/imap-client.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');

describe('MIME Cleaning, 2025 Freshness & PWA Tests', () => {
  describe('1. MIME Multipart & Quoted-Printable Cleaning', () => {
    it('decodes quoted-printable strings with =3D, soft wraps, and hex values', () => {
      const qp = 'Hello=20World=21=\r\nThis is a test with =3D signs and soft wraps=\r\n.';
      const decoded = decodeQuotedPrintable(qp);
      assert.ok(decoded.includes('Hello World!'));
      assert.ok(decoded.includes('with = signs and soft wraps.'));
    });

    it('cleans multipart MIME boundary, stripping headers and extracting text/plain', () => {
      const rawMime = `--boundary_12345\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nWelcome to Mailboxer!\r\nCheck your schedule at https://example.com/calendar?id=3D42\r\n--boundary_12345\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML version</p>\r\n--boundary_12345--`;

      const cleaned = cleanMimeBody(rawMime);
      assert.ok(!cleaned.includes('--boundary_12345'));
      assert.ok(!cleaned.includes('Content-Type: text/plain'));
      assert.ok(!cleaned.includes('Content-Transfer-Encoding'));
      assert.ok(cleaned.includes('Welcome to Mailboxer!'));
      assert.ok(cleaned.includes('https://example.com/calendar?id=42'));
    });

    it('falls back gracefully to text/html when no text/plain part exists', () => {
      const rawHtmlMime = `--boundary_999\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<div><p>Hello <b>Student</b></p><br><p>Assignment is due soon.</p></div>\r\n--boundary_999--`;

      const cleaned = cleanMimeBody(rawHtmlMime);
      assert.ok(!cleaned.includes('<div'));
      assert.ok(!cleaned.includes('<p>'));
      assert.ok(!cleaned.includes('<b>'));
      assert.ok(cleaned.includes('Hello Student'));
      assert.ok(cleaned.includes('Assignment is due soon.'));
    });
  });

  describe('2. Legacy Purge & 2025 Freshness Storage', () => {
    let store;
    const testDbPath = path.join(ROOT_DIR, `test-freshness-${Date.now()}.sqlite`);

    before(async () => {
      store = new SqliteStore(testDbPath);
      store.upsertAccount({ id: 'acc_test', email: 'test@example.com', provider: 'custom' });
      store.upsertFolder({ id: 'f_inbox', accountId: 'acc_test', name: 'INBOX', path: 'INBOX' });
    });

    after(async () => {
      if (store) store.close();
      await fs.unlink(testDbPath).catch(() => {});
    });

    it('purges messages dated before 2025-01-01 while keeping 2025+ messages', () => {
      // Insert mixed historical and fresh messages
      store.upsertMessages([
        {
          id: 'msg_2022',
          accountId: 'acc_test',
          folderId: 'f_inbox',
          uid: 101,
          subject: 'Old 2022 receipt',
          date: '2022-05-15T12:00:00.000Z',
          bodySnippet: 'Legacy message from 2022'
        },
        {
          id: 'msg_2023',
          accountId: 'acc_test',
          folderId: 'f_inbox',
          uid: 102,
          subject: 'Old 2023 update',
          date: '2023-11-20T10:00:00.000Z',
          bodySnippet: 'Legacy message from 2023'
        },
        {
          id: 'msg_2024',
          accountId: 'acc_test',
          folderId: 'f_inbox',
          uid: 103,
          subject: 'Old 2024 newsletter',
          date: '2024-12-31T23:59:59.000Z',
          bodySnippet: 'Legacy message from 2024'
        },
        {
          id: 'msg_2025_fresh',
          accountId: 'acc_test',
          folderId: 'f_inbox',
          uid: 104,
          subject: 'Fresh 2025 course announcement',
          date: '2025-01-15T09:30:00.000Z',
          bodySnippet: 'Fresh 2025 email'
        },
        {
          id: 'msg_2026_future',
          accountId: 'acc_test',
          folderId: 'f_inbox',
          uid: 105,
          subject: 'Current 2026 message',
          date: '2026-10-20T15:00:00.000Z',
          bodySnippet: 'Active current message'
        }
      ]);

      assert.equal(store.getMessageCount(), 5);

      // Purge older than 2025
      const purged = store.purgeOlderThan('2025-01-01T00:00:00.000Z');
      assert.equal(purged, 3, 'Should purge exactly 3 messages from 2022, 2023, and 2024');

      const remaining = store.getMessages();
      assert.equal(remaining.length, 2);
      assert.ok(remaining.every(m => new Date(m.date).getFullYear() >= 2025));
    });
  });

  describe('3. PWA Manifest & App Icon Integrity', () => {
    it('verifies public/manifest.json is valid JSON with standalone display and theme color', async () => {
      const manifestPath = path.join(ROOT_DIR, 'public/manifest.json');
      const content = await fs.readFile(manifestPath, 'utf8');
      const manifest = JSON.parse(content);

      assert.equal(manifest.name, 'Mailboxer — All-in-One Mailbox');
      assert.equal(manifest.short_name, 'Mailboxer');
      assert.equal(manifest.display, 'standalone');
      assert.equal(manifest.theme_color, '#0b0d11');
      assert.ok(Array.isArray(manifest.icons) && manifest.icons.length > 0);
    });

    it('verifies public/icon.svg exists and contains scalable vector definitions', async () => {
      const iconPath = path.join(ROOT_DIR, 'public/icon.svg');
      const content = await fs.readFile(iconPath, 'utf8');
      assert.ok(content.includes('<svg'));
      assert.ok(content.includes('viewBox="0 0 512 512"'));
    });

    it('verifies public/index.html includes PWA meta tags and link rel=manifest', async () => {
      const htmlPath = path.join(ROOT_DIR, 'public/index.html');
      const html = await fs.readFile(htmlPath, 'utf8');
      assert.ok(html.includes('<link rel="manifest" href="/manifest.json">'));
      assert.ok(html.includes('apple-mobile-web-app-capable'));
      assert.ok(html.includes('viewport-fit=cover'));
      assert.ok(html.includes('id="mobile-bottom-nav"'));
      assert.ok(html.includes('id="btn-mobile-menu"'));
    });
  });
});
