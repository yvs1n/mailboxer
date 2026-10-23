/**
 * Server routes for the full reader, attachments, sending and message state,
 * wired to a real SyncEngine/MailService over an in-memory fake IMAP server.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import crypto from 'node:crypto';
import { WebServer } from '../../src/server/web-server.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { MailService } from '../../src/mail/mail-service.js';
import { AuthGuard } from '../../src/server/auth.js';
import { FakeImapServerState, FakeImapClient } from '../helpers/fake-imap-client.js';

const ACC = 'acc_routes';
const CRLF = '\r\n';

const RAW = [
  'From: Alice <alice@example.com>',
  'Subject: Report',
  'Message-ID: <report@example.com>',
  'Content-Type: multipart/mixed; boundary="b"',
  '',
  '--b',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<p>Hello <b>there</b></p><script>alert(1)</script>',
  '--b',
  'Content-Type: text/csv',
  'Content-Disposition: attachment; filename="data.csv"',
  '',
  'a,b',
  '1,2',
  '--b--',
  ''
].join(CRLF);

describe('Mail routes (src/server/web-server.js)', () => {
  let server;
  let baseUrl;
  let state;
  let store;
  let engine;
  const sent = [];

  before(async () => {
    state = new FakeImapServerState();
    state.addFolder('INBOX');
    state.addFolder('Sent', ['\\Sent']);
    state.addFolder('Trash', ['\\Trash']);
    state.addMessage('INBOX', { subject: 'Report', from: 'Alice <alice@example.com>', raw: RAW });
    state.addMessage('INBOX', { subject: 'Second' });

    store = new SqliteStore(':memory:');
    const account = { id: ACC, email: 'me@example.com', provider: 'apple', auth: { user: 'me@example.com', pass: 'app-pass' } };
    store.upsertAccount({ id: ACC, email: account.email, provider: 'apple' });
    const accountManager = {
      init: async () => {},
      listAccounts: async () => [],
      getAccounts: async () => [account],
      getAccount: async (id) => (id === ACC ? account : null),
      getImapConfig: async (id) => {
        if (id !== ACC) throw new Error('Account not found');
        return account;
      }
    };
    engine = new SyncEngine({ store, accountManager, folders: 'INBOX', createClient: () => new FakeImapClient(state) });
    const mailService = new MailService({
      syncEngine: engine,
      store,
      accountManager,
      createSmtpClient: (cfg) => ({
        send: async (params) => {
          sent.push({ cfg, ...params });
          return { accepted: params.recipients, response: '250 ok' };
        }
      })
    });
    server = new WebServer({
      port: 0,
      host: '127.0.0.1',
      accountManager,
      store,
      syncEngine: engine,
      mailService,
      enableIdle: false,
      auth: new AuthGuard({ secret: crypto.randomBytes(32), password: '', production: false })
    });
    baseUrl = await server.start();
    await engine.syncAccount(ACC);
  });

  after(async () => {
    await server?.stop();
  });

  const report = () => store.getMessages({}).find(m => m.subject === 'Report');

  it('returns the full sanitized body and attachment list', async () => {
    const res = await fetch(`${baseUrl}/api/messages/${report().id}/body`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.match(body.html, /Hello <b>there<\/b>/);
    assert.doesNotMatch(body.html, /script/);
    assert.equal(body.text.trim(), 'Hello there');
    assert.deepEqual(body.attachments.map(a => a.filename), ['data.csv']);
  });

  it('caches the body after the first fetch', async () => {
    const before = state.commands.filter(c => c.startsWith('FETCHRAW')).length;
    await fetch(`${baseUrl}/api/messages/${report().id}/body`);
    const afterCount = state.commands.filter(c => c.startsWith('FETCHRAW')).length;
    assert.equal(afterCount, before);
  });

  it('serves attachments as downloads only', async () => {
    const res = await fetch(`${baseUrl}/api/messages/${report().id}/attachments/0`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/octet-stream');
    assert.match(res.headers.get('content-disposition'), /^attachment; filename="data\.csv"/);
    assert.equal((await res.text()).replace(/\r\n/g, '\n'), 'a,b\n1,2');

    assert.equal((await fetch(`${baseUrl}/api/messages/${report().id}/attachments/5`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/messages/nope/body`)).status, 404);
  });

  it('sends a reply with threading headers and saves it to Sent', async () => {
    const original = report();
    const res = await fetch(`${baseUrl}/api/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId: ACC, to: 'alice@example.com', subject: 'Re: Report', text: 'Thanks!', replyToMessageId: original.id })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.savedToSent, true);

    const last = sent.at(-1);
    assert.deepEqual(last.recipients, ['alice@example.com']);
    assert.equal(last.auth.pass, 'app-pass');
    assert.ok(original.messageId);
    assert.ok(last.raw.includes(`In-Reply-To: ${original.messageId}\r\n`));
    assert.ok(state.commands.includes('APPEND Sent'));
  });

  it('validates send input', async () => {
    const post = (payload) => fetch(`${baseUrl}/api/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.equal((await post({ to: 'a@b.co' })).status, 400);
    assert.equal((await post({ accountId: ACC, to: 'not an email' })).status, 400);
    assert.equal((await post({ accountId: 'missing', to: 'a@b.co' })).status, 404);
  });

  it('marks read and stars through the server', async () => {
    const msg = store.getMessages({}).find(m => m.subject === 'Second');
    const applied = once(engine, 'remoteOpApplied');
    const res = await fetch(`${baseUrl}/api/messages/${msg.id}/star`, { method: 'POST' });
    assert.equal(res.status, 200);
    await applied;
    assert.ok(state.messages('INBOX').get(msg.uid).flags.has('\\Flagged'));
    assert.equal((await fetch(`${baseUrl}/api/messages/nope/read`, { method: 'POST' })).status, 404);
  });

  it('deletes by moving to Trash', async () => {
    const msg = store.getMessages({}).find(m => m.subject === 'Second');
    const applied = once(engine, 'remoteOpApplied');
    const res = await fetch(`${baseUrl}/api/messages/${msg.id}`, { method: 'DELETE' });
    assert.equal(res.status, 200);
    await applied;
    assert.equal(state.messages('INBOX').has(msg.uid), false);
    assert.equal((await fetch(`${baseUrl}/api/messages/${msg.id}`, { method: 'DELETE' })).status, 404);
  });
});
