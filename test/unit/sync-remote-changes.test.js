/**
 * SyncEngine: pushing local changes to the server, folder selection,
 * and the date-horizon refetch fix.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { SqliteStore } from '../../src/storage/sqlite-store.js';
import { SyncEngine, isSyncableFolder } from '../../src/sync/sync-engine.js';
import { FakeImapServerState, FakeImapClient } from '../helpers/fake-imap-client.js';

const ACC = 'acc_test';

function setup({ folders = 'INBOX' } = {}) {
  const state = new FakeImapServerState();
  state.addFolder('INBOX');
  state.addFolder('Trash', ['\\HasNoChildren', '\\Trash']);
  const store = new SqliteStore(':memory:');
  store.upsertAccount({ id: ACC, email: 'me@example.com', provider: 'apple' });
  const accountManager = {
    getAccount: async (id) => (id === ACC ? { id: ACC, email: 'me@example.com', provider: 'apple', auth: { user: 'me@example.com', pass: 'x' } } : null)
  };
  const engine = new SyncEngine({
    store,
    accountManager,
    folders,
    createClient: () => new FakeImapClient(state)
  });
  return { state, store, engine };
}

describe('SyncEngine remote changes (src/sync/sync-engine.js)', () => {
  let ctx;
  beforeEach(() => { ctx = setup(); });

  it('pushes "mark read" to the server instead of reverting on the next sync', async () => {
    const { state, store, engine } = ctx;
    const uid = state.addMessage('INBOX', { subject: 'Hello' });
    await engine.syncAccount(ACC);
    const msg = store.getMessageByUid(`${ACC}:INBOX`, uid);
    assert.equal(msg.isSeen, false);

    const applied = once(engine, 'remoteOpApplied');
    engine.setMessageState(msg, { seen: true });
    assert.equal(store.getMessage(msg.id).isSeen, true, 'local copy changes immediately');
    await applied;

    assert.ok(state.commands.some(c => c === `STORE ${uid} +FLAGS \\Seen`));
    assert.ok(state.messages('INBOX').get(uid).flags.has('\\Seen'));

    await engine.syncAccount(ACC);
    assert.equal(store.getMessage(msg.id).isSeen, true, 'still read after a full sync');
  });

  it('keeps a pending change even if a sync runs before the server is updated', async () => {
    const { state, store, engine } = ctx;
    const uid = state.addMessage('INBOX', { subject: 'Star me' });
    await engine.syncAccount(ACC);
    const msg = store.getMessageByUid(`${ACC}:INBOX`, uid);

    // Hold the push: the first SELECT on the op connection fails transiently
    state.failNext = { prefix: 'STORE', error: new Error('temporary network blip') };
    const failedOnce = new Promise((resolve) => {
      const check = () => (state.commands.filter(c => c.startsWith('STORE')).length > 0 ? resolve() : setTimeout(check, 5));
      check();
    });
    engine.setMessageState(msg, { flagged: true });
    await failedOnce;

    // Server still says "not flagged", but the op is pending -> local state is kept
    await engine.syncAccount(ACC);
    assert.equal(store.getMessage(msg.id).isFlagged, true);
    engine.stopPeriodicSync(); // clears the retry timer
  });

  it('syncs starred state from the server', async () => {
    const { state, store, engine } = ctx;
    const uid = state.addMessage('INBOX', { subject: 'Starred elsewhere' });
    await engine.syncAccount(ACC);
    state.messages('INBOX').get(uid).flags.add('\\Flagged');
    await engine.syncAccount(ACC);
    assert.equal(store.getMessageByUid(`${ACC}:INBOX`, uid).isFlagged, true);
  });

  it('deletes by moving to Trash, and the message does not come back', async () => {
    const { state, store, engine } = ctx;
    const uid = state.addMessage('INBOX', { subject: 'Delete me' });
    await engine.syncAccount(ACC);
    const msg = store.getMessageByUid(`${ACC}:INBOX`, uid);

    const applied = once(engine, 'remoteOpApplied');
    engine.deleteMessage(msg);
    assert.equal(store.getMessage(msg.id), null);
    await applied;

    assert.ok(state.commands.includes(`MOVE ${uid} Trash`));
    assert.equal(state.messages('INBOX').has(uid), false);
    assert.equal(state.messages('Trash').size, 1);

    await engine.syncAccount(ACC);
    assert.equal(store.getMessageByUid(`${ACC}:INBOX`, uid), null);
  });

  it('expunges when the account has no Trash folder', async () => {
    const { state, store, engine } = ctx;
    state.folders.delete('Trash');
    const uid = state.addMessage('INBOX', { subject: 'No trash' });
    await engine.syncAccount(ACC);
    const msg = store.getMessageByUid(`${ACC}:INBOX`, uid);
    const applied = once(engine, 'remoteOpApplied');
    engine.deleteMessage(msg);
    await applied;
    assert.ok(state.commands.includes(`EXPUNGE ${uid}`));
  });

  it('records an account error when the server rejects a change permanently', async () => {
    const { store, engine } = ctx;
    store.upsertAccount({ id: 'ghost', email: 'ghost@example.com', provider: 'apple' });
    store.upsertFolder({ id: 'ghost:INBOX', accountId: 'ghost', path: 'INBOX' });
    store.upsertMessage({ id: 'g1', accountId: 'ghost', folderId: 'ghost:INBOX', uid: 1, subject: 's', sender: 'a', senderEmail: 'a@b.c', date: '2026-01-01T00:00:00Z' });
    // accountManager.getAccount returns null for "ghost"; the store fallback has no credentials
    // so connecting fails; the op is retried, which we skip by stopping timers.
    const failed = once(engine, 'remoteOpFailed');
    engine._getAuthenticatedClient = async () => { const e = new Error('Account gone'); e.permanent = true; throw e; };
    engine.setMessageState(store.getMessage('g1'), { seen: true });
    await failed;
    assert.match(engine.getAccountStatus('ghost').lastError, /Account gone/);
  });

  it('does not re-download messages dropped by the 2025 date horizon', async () => {
    const { state, store, engine } = ctx;
    await engine.syncAccount(ACC); // initial sync of empty folder
    // Server-side date passes SINCE, but the Date header is from 2019
    state.addMessage('INBOX', { subject: 'Old header', date: '2026-01-01T00:00:00Z' });
    const folder = state.messages('INBOX');
    const [uid] = [...folder.keys()];
    const realFetch = FakeImapClient.prototype.fetchMessages;
    FakeImapClient.prototype.fetchMessages = async function (range) {
      const out = await realFetch.call(this, range);
      return out.map(m => ({ ...m, date: '2019-05-01T00:00:00.000Z' }));
    };
    try {
      await engine.syncAccount(ACC);
      await engine.syncAccount(ACC);
    } finally {
      FakeImapClient.prototype.fetchMessages = realFetch;
    }
    const fetches = state.commands.filter(c => c.startsWith('FETCH') && c.includes(String(uid)));
    assert.equal(fetches.length, 1, 'fetched once, then remembered as too old');
    assert.equal(store.getMessageByUid(`${ACC}:INBOX`, uid), null);
  });

  it('marks only genuinely new arrivals as isNew', async () => {
    const { state, engine } = ctx;
    state.addMessage('INBOX', { subject: 'First' });
    const first = await engine.syncFolder(ACC, 'INBOX');
    assert.equal(first.messages[0].isNew, false, 'initial sync is not "new mail"');

    state.addMessage('INBOX', { subject: 'Second' });
    const second = await engine.syncFolder(ACC, 'INBOX');
    assert.equal(second.messages.length, 1);
    assert.equal(second.messages[0].isNew, true);
  });

  it('fetches the full raw message for the reader', async () => {
    const { state, store, engine } = ctx;
    const uid = state.addMessage('INBOX', { subject: 'Read me' });
    await engine.syncAccount(ACC);
    const msg = store.getMessageByUid(`${ACC}:INBOX`, uid);
    const { raw } = await engine.fetchFullMessage(msg);
    assert.match(raw.toString('utf8'), /Full body of Read me/);
  });
});

describe('Folder selection', () => {
  it('skips special-use and junk folders under "*"', () => {
    assert.equal(isSyncableFolder({ path: 'INBOX', flags: [] }), true);
    assert.equal(isSyncableFolder({ path: 'Projects', name: 'Projects', flags: [] }), true);
    assert.equal(isSyncableFolder({ path: '[Gmail]/All Mail', flags: ['\\All'] }), false);
    assert.equal(isSyncableFolder({ path: '[Gmail]/Spam', name: 'Spam', flags: [] }), false);
    assert.equal(isSyncableFolder({ path: 'Junk', name: 'Junk', flags: [] }), false);
    assert.equal(isSyncableFolder({ path: 'Deleted Messages', name: 'Deleted Messages', flags: [] }), false);
    assert.equal(isSyncableFolder({ path: 'Sent Items', name: 'Sent Items', flags: [] }), false);
    assert.equal(isSyncableFolder({ path: 'Whatever', flags: ['\\Trash'] }), false);
  });

  it('syncs only the configured folders and drops previously cached others', async () => {
    const { state, store, engine } = setup({ folders: 'INBOX' });
    state.addMessage('INBOX', { subject: 'keep' });
    state.addMessage('Projects', { subject: 'skip' });
    // Simulate a cached folder from an older version
    store.upsertFolder({ id: `${ACC}:Spam`, accountId: ACC, path: 'Spam' });
    store.upsertMessage({ accountId: ACC, folderId: `${ACC}:Spam`, uid: 9, subject: 'spam', sender: 'x', senderEmail: 'x@y.z', date: '2026-01-01T00:00:00Z' });

    const result = await engine.syncAccount(ACC);
    assert.deepEqual(result.folders.map(f => f.folder), ['INBOX']);
    assert.equal(store.getFolderById(`${ACC}:Spam`), null);
    assert.equal(store.getMessages({}).length, 1);
  });

  it('"*" syncs every regular folder', async () => {
    const { state, engine } = setup({ folders: '*' });
    state.addMessage('INBOX', { subject: 'a' });
    state.addMessage('Projects', { subject: 'b' });
    const result = await engine.syncAccount(ACC);
    assert.deepEqual(result.folders.map(f => f.folder).sort(), ['INBOX', 'Projects']);
  });
});
