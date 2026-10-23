/**
 * Mailboxer Incremental IMAP Synchronization Engine
 *
 * Coordinates RFC 3501 synchronization lifecycle across multi-provider email accounts.
 * Manages UIDVALIDITY invalidation, incremental delta UID fetching, flag reconciliation,
 * remote deletion pruning, and pushing local changes (read, star, delete) back to the server.
 *
 * @module sync/sync-engine
 */

import { EventEmitter } from 'node:events';
import { ImapClient } from '../connection/imap-client.js';
import { SqliteStore } from '../storage/sqlite-store.js';
import { defaultAccountManager } from '../auth/account-manager.js';
import { defaultClassifier } from '../triage/classifier.js';

/** RFC 6154 special-use flags for folders that never belong in a unified inbox. */
const SKIPPED_SPECIAL_USE = new Set(['\\all', '\\junk', '\\trash', '\\drafts', '\\sent', '\\flagged', '\\important']);

/** Name fallbacks for servers that don't advertise special-use flags. */
const SKIPPED_FOLDER_NAMES = new Set([
  'trash', 'deleted', 'deleted items', 'deleted messages', 'bin',
  'junk', 'junk email', 'junk e-mail', 'spam', 'bulk mail',
  'drafts', 'draft', 'sent', 'sent items', 'sent messages', 'sent mail', 'outbox',
  'all mail', 'starred', 'important',
  'notes', 'conversation history', 'sync issues', 'conflicts', 'local failures', 'server failures'
]);

const TRASH_NAMES = ['trash', 'deleted items', 'deleted messages', 'bin', '[gmail]/trash', '[google mail]/trash'];

const OP_RETRY_DELAYS_MS = [5000, 30000, 120000];
const OP_MEMORY_MS = 10 * 60 * 1000;

/**
 * Decides whether a LIST entry is a regular mail folder worth syncing.
 * @param {{path?: string, name?: string, flags?: string[]}} folder
 * @returns {boolean}
 */
export function isSyncableFolder(folder) {
  if (!folder || folder.selectable === false) return false;
  const flags = (folder.flags || []).map(f => String(f).toLowerCase());
  if (flags.some(f => SKIPPED_SPECIAL_USE.has(f) || f === '\\noselect' || f === '\\nonexistent')) return false;
  const path = String(folder.path || folder.name || '');
  if (path.toUpperCase() === 'INBOX') return true;
  // Gmail system labels ([Gmail]/All Mail, [Gmail]/Spam, ...)
  if (/^\[(gmail|google mail)\]/i.test(path)) return false;
  const leaf = String(folder.name || path).toLowerCase();
  return !SKIPPED_FOLDER_NAMES.has(leaf) && !SKIPPED_FOLDER_NAMES.has(path.toLowerCase());
}

/**
 * Parses a folder selection setting: '*' (all regular folders) or a comma list.
 * @param {string|string[]|undefined} value
 * @returns {'*'|string[]}
 */
function parseFolderSelection(value) {
  if (Array.isArray(value)) return value.length ? value : '*';
  if (!value || String(value).trim() === '*') return '*';
  const list = String(value).split(',').map(s => s.trim()).filter(Boolean);
  return list.length ? list : '*';
}

/**
 * Synchronization Engine orchestrating background sync and local SQLite persistence.
 */
export class SyncEngine extends EventEmitter {
  /**
   * @param {object} [options={}]
   * @param {SqliteStore} [options.store] - Database store instance
   * @param {string} [options.dbPath] - Database path if store is not injected
   * @param {object} [options.accountManager] - Account manager for credential resolution
   * @param {Function} [options.createClient] - Optional factory for creating ImapClient
   * @param {number} [options.batchSize=50] - Batch size for UID fetch
   * @param {number} [options.syncIntervalMs=60000] - Default periodic sync interval
   * @param {object} [options.classifier] - Triage classifier instance
   * @param {string|string[]} [options.folders] - '*' (all regular folders, default) or folder paths
   *   (default: MAILBOXER_SYNC_FOLDERS env)
   */
  constructor(options = {}) {
    super();

    this.options = { ...options };
    this.store = options.store || options.db || new SqliteStore(options.dbPath || ':memory:');
    this.accountManager = options.accountManager || defaultAccountManager;
    this.classifier = options.classifier || defaultClassifier;
    this.createClient = options.createClient ||
      (this.accountManager?.imapClientFactory ? (cfg) => this.accountManager.imapClientFactory(cfg) : null) ||
      (this.accountManager?._createImapClient ? (cfg) => this.accountManager._createImapClient(cfg) : null) ||
      ((config) => new ImapClient({ accountConfig: config, ...options.clientOptions }));
    this.batchSize = options.batchSize || 50;
    this.syncIntervalMs = options.syncIntervalMs || 60000;
    this.folderSelection = parseFolderSelection(options.folders ?? process.env.MAILBOXER_SYNC_FOLDERS);

    this._isSyncing = new Map();
    this._periodicTimer = null;
    this.lastSyncAt = null;

    /** accountId -> { lastSyncAt, lastError, lastErrorAt } */
    this.accountStatus = new Map();

    // UIDs fetched once but dropped by the date horizon: folderId -> Set<uid>.
    // Prevents re-downloading the same old messages on every cycle.
    this._skippedOldUids = new Map();

    // Local changes being pushed to the server: folderId -> Map<uid, {pending, doneAt}>.
    // Sync leaves these messages alone so they don't flip back mid-push.
    this._localOps = new Map();

    // Queued remote operations per account.
    this._opQueues = new Map();
    this._opRunners = new Set();
    this._opTimers = new Set();
    this._trashFolderCache = new Map();
  }

  /**
   * Whether a background periodic sync is currently active.
   * @returns {boolean}
   */
  get isPeriodicSyncActive() {
    return this._periodicTimer !== null;
  }

  /**
   * Sync state for one account (for the UI).
   * @param {string} accountId
   */
  getAccountStatus(accountId) {
    return this.accountStatus.get(accountId) || { lastSyncAt: null, lastError: null, lastErrorAt: null };
  }

  _setAccountStatus(accountId, patch) {
    this.accountStatus.set(accountId, { ...this.getAccountStatus(accountId), ...patch });
  }

  /**
   * Creates, connects, and authenticates an ImapClient for the given account.
   * @private
   */
  async _getAuthenticatedClient(accountId, options = {}) {
    let accountConfig = options.accountConfig;
    if (!accountConfig && this.accountManager?.getAccount) {
      try {
        accountConfig = await this.accountManager.getAccount(accountId);
      } catch {
        // Fall back to subsequent resolution strategies
      }
    }
    if (!accountConfig && this.accountManager?.getAccounts) {
      try {
        const all = await this.accountManager.getAccounts();
        accountConfig = all.find(a => a.id === accountId);
      } catch {
        // Fall back to subsequent resolution strategies
      }
    }
    if (!accountConfig) {
      // Fallback: check SQLite accounts table
      const storedAccount = this.store.getAccount(accountId);
      if (storedAccount) {
        accountConfig = storedAccount;
      }
    }

    if (!accountConfig) {
      const err = new Error(`Account "${accountId}" not found in account manager or storage`);
      err.permanent = true;
      throw err;
    }

    const client = this.createClient(accountConfig);
    try {
      if (!client.isConnected) {
        await client.connect({
          host: accountConfig.imap?.host || accountConfig.host,
          port: accountConfig.imap?.port || accountConfig.port,
          secure: accountConfig.imap?.secure ?? accountConfig.secure ?? true,
          provider: accountConfig.provider
        });
      }

      if (!client.isAuthenticated) {
        const user = accountConfig.auth?.user || accountConfig.email;
        const pass = accountConfig.auth?.pass || accountConfig.appPassword || accountConfig.password;
        await client.login(user, pass, {
          type: accountConfig.auth?.type,
          accessToken: accountConfig.auth?.accessToken
        });
      }

      return client;
    } catch (err) {
      try {
        await client.destroy?.();
      } catch {}
      throw err;
    }
  }

  // ==========================================
  // LOCAL CHANGE TRACKING
  // ==========================================

  /** Marks a message as having a local change in flight. Returns a finish callback. @private */
  _beginLocalOp(folderId, uid) {
    let folderOps = this._localOps.get(folderId);
    if (!folderOps) {
      folderOps = new Map();
      this._localOps.set(folderId, folderOps);
    }
    const entry = folderOps.get(uid) || { pending: 0, doneAt: 0 };
    entry.pending++;
    folderOps.set(uid, entry);
    let finished = false;
    return () => {
      if (finished) return;
      finished = true;
      entry.pending = Math.max(0, entry.pending - 1);
      entry.doneAt = Date.now();
    };
  }

  /**
   * UIDs whose server snapshot may be stale: changes still pending, or pushed
   * after `sinceTs` (i.e. after this sync read the server state).
   * @private
   */
  _protectedUids(folderId, sinceTs) {
    const folderOps = this._localOps.get(folderId);
    const out = new Set();
    if (!folderOps) return out;
    const now = Date.now();
    for (const [uid, entry] of folderOps) {
      if (entry.pending > 0 || entry.doneAt >= sinceTs) {
        out.add(uid);
      } else if (now - entry.doneAt > OP_MEMORY_MS) {
        folderOps.delete(uid);
      }
    }
    return out;
  }

  /**
   * Synchronizes a single IMAP folder / mailbox for an account.
   *
   * Lifecycle:
   * 1. Mailbox Selection: queries UIDVALIDITY, UIDNEXT, total messages.
   * 2. Cache Invalidation: if UIDVALIDITY changed, purges cached local messages.
   * 3. Delta UID Fetch: new UIDs above the local maximum, plus any missing 2025+ messages.
   * 4. Flag Reconciliation: read (UNSEEN) and starred (FLAGGED) state from the server.
   * 5. Deleted UID Pruning: purges messages removed from the remote mailbox.
   *
   * @param {string} accountId - Account ID
   * @param {string} folderName - Mailbox name (e.g. 'INBOX')
   * @param {object} [options={}] - Options
   * @returns {Promise<object>} FolderSyncResult (includes `messages`: newly stored records)
   */
  async syncFolder(accountId, folderName, options = {}) {
    if (!accountId || !folderName) {
      throw new TypeError('accountId and folderName are required to sync folder');
    }

    let client = options.client;
    let ownsClient = false;

    if (!client) {
      client = await this._getAuthenticatedClient(accountId, options);
      ownsClient = true;
    }

    this.emit('syncFolderStart', { accountId, folder: folderName, timestamp: new Date().toISOString() });
    const startedAt = Date.now();

    try {
      // 1. SELECT Mailbox & inspect UIDVALIDITY / UIDNEXT
      const selectResult = await client.selectMailbox(folderName);
      const folderPath = folderName;
      const folderId = `${accountId}:${folderPath}`;

      // 2. UIDVALIDITY Invalidation Check
      let existingFolder = this.store.getFolder(accountId, folderPath);
      let flushed = false;

      if (
        existingFolder &&
        existingFolder.uidvalidity !== null &&
        selectResult.uidValidity !== null &&
        existingFolder.uidvalidity !== selectResult.uidValidity
      ) {
        // UIDVALIDITY mismatch: server mailbox was rebuilt or UIDs reassigned
        this.store.clearFolder(folderId);
        this._skippedOldUids.delete(folderId);
        this._localOps.delete(folderId);
        flushed = true;
        this.emit('cacheInvalidated', {
          accountId,
          folder: folderName,
          oldUidValidity: existingFolder.uidvalidity,
          newUidValidity: selectResult.uidValidity
        });
      }

      const folderFlags = options.folderFlags || existingFolder?.flags || selectResult.flags || [];

      // Upsert folder metadata in SQLite
      this.store.upsertFolder({
        id: folderId,
        accountId,
        name: options.folderDisplayName || folderName,
        path: folderPath,
        delimiter: options.folderDelimiter || existingFolder?.delimiter || '/',
        flags: folderFlags,
        uidvalidity: selectResult.uidValidity,
        uidnext: selectResult.uidNext,
        totalMessages: selectResult.exists || 0,
        lastSyncedAt: new Date().toISOString(),
        syncStatus: 'SYNCING'
      });

      // 3. Delta UID Fetch (restricted to 2025 onwards for a fresh inbox)
      const sinceCriteria = options.since || process.env.MAILBOXER_SYNC_SINCE || 'SINCE 1-Jan-2025';
      const minDateStr = options.minDate || process.env.MAILBOXER_MIN_DATE || '2025-01-01T00:00:00.000Z';
      const minTimestamp = new Date(minDateStr).getTime();

      // One date-bounded search serves backfill and deletion pruning.
      let remoteUids;
      try {
        remoteUids = await client.searchUids(sinceCriteria);
      } catch {
        remoteUids = await client.searchUids('ALL');
      }

      const maxLocalUid = this.store.getMaxUid(folderId);
      const isInitialSync = maxLocalUid === null || maxLocalUid === 0;
      const skippedOld = this._skippedOldUids.get(folderId) || new Set();
      const protectedUids = this._protectedUids(folderId, startedAt);
      let uidsToFetch = [];

      if (isInitialSync) {
        const fresh = remoteUids.filter(u => !skippedOld.has(u));
        uidsToFetch = options.initialLimit ? fresh.slice(-options.initialLimit) : fresh;
      } else {
        // New arrivals above the local maximum (catches mail with old INTERNALDATE too)
        const candidateUids = await client.searchUids(`UID ${maxLocalUid + 1}:*`);
        // Exclude any UID <= maxLocalUid (RFC 3501: "n:*" always returns the highest UID)
        const newUids = candidateUids.filter(u => u > maxLocalUid && !skippedOld.has(u));
        const newSet = new Set(newUids);

        // Backfill missing 2025+ messages, newest first
        const localUids = new Set(this.store.getFolderUids(folderId));
        const missingUids = remoteUids
          .filter(u => !localUids.has(u) && !newSet.has(u) && !skippedOld.has(u) && !protectedUids.has(u))
          .sort((a, b) => b - a);

        uidsToFetch = [...newUids, ...missingUids];
      }

      let fetchedCount = 0;
      const storedRecords = [];
      if (uidsToFetch.length > 0) {
        const batchSize = options.batchSize || this.batchSize || 50;
        for (let i = 0; i < uidsToFetch.length; i += batchSize) {
          const chunk = uidsToFetch.slice(i, i + batchSize);
          const range = chunk.join(',');
          const fetchedMessages = await client.fetchMessages(range);

          // Strictly filter out messages older than the date horizon, and remember
          // them so they are not downloaded again next cycle.
          const freshMessages = [];
          for (const m of fetchedMessages) {
            const t = m.date ? new Date(m.date).getTime() : NaN;
            if (!m.date || isNaN(t) || t >= minTimestamp) {
              freshMessages.push(m);
            } else {
              skippedOld.add(m.uid);
            }
          }

          const records = freshMessages.map(m => {
            let triage = { category: 'NORMAL', score: 50, isNoise: false, reason: null, shouldNotify: false };
            if (this.classifier?.classify) {
              triage = this.classifier.classify(m);
            }
            return {
              accountId,
              folderId,
              uid: m.uid,
              messageId: m.messageId,
              threadId: m.threadId,
              sender: m.sender || m.from,
              senderEmail: m.senderEmail,
              recipients: m.recipients,
              subject: m.subject,
              date: m.date,
              bodySnippet: m.bodySnippet,
              flags: m.flags,
              isSeen: m.isSeen,
              isFlagged: m.isFlagged,
              size: m.size,
              category: triage.category || 'NORMAL',
              triageCategory: triage.category || 'NORMAL',
              triageScore: triage.score ?? 50,
              isNoise: triage.isNoise ? 1 : 0,
              triageReason: triage.reason || null,
              shouldNotify: Boolean(triage.shouldNotify),
              // Genuinely new arrival (not first sync, not historical backfill)
              isNew: !isInitialSync && m.uid > maxLocalUid
            };
          });

          const ids = this.store.upsertMessages(records);
          records.forEach((rec, idx) => { rec.id = ids[idx]; });
          fetchedCount += records.length;
          storedRecords.push(...records);

          for (const rec of records) {
            this.emit('messageAdded', rec);
          }
        }
      }
      if (skippedOld.size > 0) this._skippedOldUids.set(folderId, skippedOld);

      // 4. Flag Reconciliation. Messages with local changes in flight are left alone.
      const unseenUids = await client.searchUids('UNSEEN');
      this.store.reconcileSeenFlags(folderId, unseenUids, this._protectedUids(folderId, startedAt));

      let flaggedUids = null;
      try {
        flaggedUids = await client.searchUids('FLAGGED');
      } catch {
        flaggedUids = null; // server refused; keep local starred state
      }
      if (flaggedUids && this.store.reconcileFlaggedFlags) {
        this.store.reconcileFlaggedFlags(folderId, flaggedUids, this._protectedUids(folderId, startedAt));
      }

      this.emit('flagsReconciled', {
        accountId,
        folder: folderName,
        unseenCount: unseenUids.length
      });

      // 5. Remote Deletion Pruning (same date-bounded set as backfill)
      const prunedCount = this.store.pruneDeletedUids(folderId, remoteUids, this._protectedUids(folderId, startedAt));
      if (prunedCount > 0) {
        this.emit('messagesPruned', {
          accountId,
          folder: folderName,
          count: prunedCount
        });
      }

      // Mark folder IDLE and record completion
      this.store.upsertFolder({
        id: folderId,
        accountId,
        name: options.folderDisplayName || folderName,
        path: folderPath,
        delimiter: options.folderDelimiter || existingFolder?.delimiter || '/',
        flags: folderFlags,
        uidvalidity: selectResult.uidValidity,
        uidnext: selectResult.uidNext,
        totalMessages: selectResult.exists || 0,
        unseenMessages: unseenUids.length,
        lastSyncedAt: new Date().toISOString(),
        syncStatus: 'IDLE',
        syncError: null
      });

      const folderSyncResult = {
        accountId,
        folder: folderName,
        folderId,
        flushed,
        newMessagesCount: fetchedCount,
        messages: storedRecords,
        prunedCount,
        uidValidity: selectResult.uidValidity,
        uidNext: selectResult.uidNext,
        totalMessages: selectResult.exists || 0,
        unseenCount: unseenUids.length,
        timestamp: new Date().toISOString()
      };

      this.emit('folderSynced', folderSyncResult);
      return folderSyncResult;
    } catch (err) {
      const folderId = `${accountId}:${folderName}`;
      try {
        this.store.upsertFolder({
          id: folderId,
          accountId,
          name: folderName,
          path: folderName,
          syncStatus: 'ERROR',
          syncError: err.message || String(err),
          lastSyncedAt: new Date().toISOString()
        });
      } catch {}
      throw err;
    } finally {
      if (ownsClient) {
        try {
          await client.logout();
        } catch {
          // ignore teardown error
        }
      }
    }
  }

  /**
   * Picks which of the server's folders to sync.
   * @private
   */
  _selectFolders(folders, selection = this.folderSelection) {
    if (selection === '*') {
      const chosen = folders.filter(isSyncableFolder);
      return chosen.length > 0 ? chosen : [{ name: 'INBOX', path: 'INBOX', flags: [] }];
    }
    const wanted = new Set(selection.map(s => s.toLowerCase()));
    const chosen = folders.filter(f => f.selectable !== false && wanted.has(String(f.path || f.name).toLowerCase()));
    // INBOX is always selectable even when LIST failed or omitted it
    if (chosen.length === 0 && wanted.has('inbox')) {
      return [{ name: 'INBOX', path: 'INBOX', flags: [] }];
    }
    return chosen;
  }

  /**
   * Performs an incremental sync of the selected folders for an account.
   *
   * @param {string} accountId - Account identifier
   * @param {object} [options={}] - Sync options (`folders` overrides the engine's selection)
   * @returns {Promise<object>} AccountSyncResult
   */
  async syncAccount(accountId, options = {}) {
    if (!accountId) {
      throw new TypeError('accountId is required to sync account');
    }

    if (this._isSyncing.get(accountId)) {
      if (options.skipIfActive !== false) {
        return {
          accountId,
          skipped: true,
          reason: 'Sync already in progress for this account'
        };
      }
    }

    this._isSyncing.set(accountId, true);
    const startTime = Date.now();
    this.emit('syncStart', { accountId, timestamp: new Date().toISOString() });

    let client = null;
    const folderResults = [];

    try {
      client = await this._getAuthenticatedClient(accountId, options);

      // Folder discovery
      let folders = [];
      let listed = false;
      try {
        folders = await client.listMailboxes('', '*');
        listed = true;
      } catch {
        folders = [];
      }

      const selection = options.folders !== undefined ? parseFolderSelection(options.folders) : this.folderSelection;
      const selectedFolders = this._selectFolders(folders, selection);

      // Drop cached folders we no longer sync (e.g. Spam/Trash from older versions)
      if (listed && this.store.getFolders) {
        const keep = new Set(selectedFolders.map(f => f.path || f.name));
        for (const local of this.store.getFolders(accountId)) {
          if (!keep.has(local.path)) {
            this.store.deleteFolder(local.id);
            this._skippedOldUids.delete(local.id);
          }
        }
      }

      for (const folder of selectedFolders) {
        const folderName = folder.path || folder.name;
        try {
          const res = await this.syncFolder(accountId, folderName, {
            ...options,
            client,
            folderFlags: folder.flags,
            folderDelimiter: folder.delimiter || undefined
          });
          folderResults.push(res);
        } catch (fErr) {
          if (options.continueOnError !== false) {
            folderResults.push({
              accountId,
              folder: folderName,
              error: fErr.message,
              success: false
            });
          } else {
            throw fErr;
          }
        }
      }

      const folderErrors = folderResults.filter(r => r.error);
      // Nothing synced at all (e.g. the connection dropped): that's an account failure
      if (folderResults.length > 0 && folderErrors.length === folderResults.length) {
        throw new Error(`${folderErrors[0].folder}: ${folderErrors[0].error}`);
      }

      this.lastSyncAt = new Date().toISOString();
      const totalNew = folderResults.reduce((acc, r) => acc + (r.newMessagesCount || 0), 0);
      const totalPruned = folderResults.reduce((acc, r) => acc + (r.prunedCount || 0), 0);

      this._setAccountStatus(accountId, {
        lastSyncAt: this.lastSyncAt,
        lastError: folderErrors.length ? `${folderErrors[0].folder}: ${folderErrors[0].error}` : null,
        lastErrorAt: folderErrors.length ? this.lastSyncAt : null
      });

      const syncResult = {
        accountId,
        success: true,
        durationMs: Date.now() - startTime,
        folders: folderResults,
        totalNewMessages: totalNew,
        totalPruned,
        timestamp: this.lastSyncAt
      };

      this.emit('syncComplete', syncResult);
      return syncResult;
    } catch (err) {
      this._setAccountStatus(accountId, {
        lastError: err.message || String(err),
        lastErrorAt: new Date().toISOString()
      });
      this.emit('syncError', { accountId, error: err });
      if (options.throwOnError !== false) {
        throw err;
      }
      return {
        accountId,
        success: false,
        error: err.message,
        durationMs: Date.now() - startTime,
        folders: folderResults,
        timestamp: new Date().toISOString()
      };
    } finally {
      this._isSyncing.set(accountId, false);
      if (client) {
        try {
          await client.logout();
        } catch {
          // ignore cleanup errors
        }
      }
    }
  }

  /**
   * Starts periodic background synchronization across all configured accounts.
   *
   * @param {number} [intervalMs] - Polling interval in milliseconds
   */
  startPeriodicSync(intervalMs) {
    if (this._periodicTimer) {
      this.stopPeriodicSync();
    }

    const interval = Math.max(5000, Number(intervalMs || this.syncIntervalMs || 60000));
    this.syncIntervalMs = interval;

    const runSyncCycle = async () => {
      try {
        let accounts = [];
        if (this.accountManager?.getAccounts) {
          accounts = await this.accountManager.getAccounts();
        } else {
          accounts = this.store.getAccounts();
        }

        for (const acc of accounts) {
          const id = acc.id || acc.email;
          if (id) {
            const result = await this.syncAccount(id, { throwOnError: false }).catch(() => null);
            if (result && result.success === false) {
              console.error(`[Mailboxer] Sync failed for ${id}: ${result.error}`);
            }
          }
        }
      } catch (err) {
        if (this.listenerCount('error') > 0) this.emit('error', err);
        else console.error('[Mailboxer] Periodic sync cycle failed:', err.message || err);
      }
    };

    this._periodicTimer = setInterval(runSyncCycle, interval);
    if (this._periodicTimer.unref) {
      this._periodicTimer.unref();
    }
  }

  /**
   * Stops periodic background synchronization and pending retries.
   */
  stopPeriodicSync() {
    if (this._periodicTimer) {
      clearInterval(this._periodicTimer);
      this._periodicTimer = null;
    }
    for (const t of this._opTimers) clearTimeout(t);
    this._opTimers.clear();
  }

  // ==========================================
  // PUSHING LOCAL CHANGES TO THE SERVER
  // ==========================================

  /** Resolves the IMAP folder path for a stored message. @private */
  _folderPathFor(message) {
    const folderId = message.folderId || message.folder_id;
    const accountId = message.accountId || message.account_id;
    const folder = this.store.getFolderById?.(folderId);
    if (folder?.path) return folder.path;
    if (folderId && accountId && folderId.startsWith(`${accountId}:`)) return folderId.slice(accountId.length + 1);
    return 'INBOX';
  }

  /**
   * Marks a message read/unread and/or starred/unstarred. The local copy changes
   * immediately; the server is updated in the background (with retries).
   *
   * @param {object} message - Stored message record
   * @param {{seen?: boolean, flagged?: boolean}} changes
   */
  setMessageState(message, changes = {}) {
    if (!message) return;
    if (changes.seen !== undefined) this.store.setMessageSeen(message.id, changes.seen);
    if (changes.flagged !== undefined) this.store.setMessageFlag(message.id, changes.flagged);
    this._enqueueOp(message, { type: 'flags', ...changes });
  }

  /**
   * Deletes a message: removed locally now, moved to Trash (or expunged) on the server
   * in the background.
   *
   * @param {object} message - Stored message record
   */
  deleteMessage(message) {
    if (!message) return;
    this.store.deleteMessage(message.id);
    this._enqueueOp(message, { type: 'delete' });
  }

  /** @private */
  _enqueueOp(message, op) {
    const accountId = message.accountId || message.account_id;
    const folderId = message.folderId || message.folder_id;
    const uid = Number(message.uid);
    if (!accountId || !folderId || !Number.isFinite(uid)) return;

    const entry = {
      ...op,
      accountId,
      folderId,
      folderPath: this._folderPathFor(message),
      uid,
      attempts: 0,
      finish: this._beginLocalOp(folderId, uid)
    };

    const queue = this._opQueues.get(accountId) || [];
    queue.push(entry);
    this._opQueues.set(accountId, queue);
    this._runOps(accountId);
  }

  /**
   * Resolves (and caches) the account's Trash folder path.
   * @private
   */
  async _findTrashFolder(client, accountId) {
    if (this._trashFolderCache.has(accountId)) return this._trashFolderCache.get(accountId);
    let trash = null;
    try {
      const folders = await client.listMailboxes('', '*');
      const byFlag = folders.find(f => (f.flags || []).some(fl => String(fl).toLowerCase() === '\\trash'));
      const byName = folders.find(f => TRASH_NAMES.includes(String(f.path || '').toLowerCase()) || TRASH_NAMES.includes(String(f.name || '').toLowerCase()));
      trash = (byFlag || byName)?.path || null;
    } catch {}
    this._trashFolderCache.set(accountId, trash);
    return trash;
  }

  /** Applies one queued operation on an open, authenticated client. @private */
  async _applyOp(client, op, selected) {
    if (selected.path !== op.folderPath) {
      await client.selectMailbox(op.folderPath);
      selected.path = op.folderPath;
    }
    if (op.type === 'flags') {
      if (op.seen !== undefined) {
        await client.storeFlags(op.uid, ['\\Seen'], op.seen ? '+FLAGS' : '-FLAGS');
      }
      if (op.flagged !== undefined) {
        await client.storeFlags(op.uid, ['\\Flagged'], op.flagged ? '+FLAGS' : '-FLAGS');
      }
    } else if (op.type === 'delete') {
      const trash = await this._findTrashFolder(client, op.accountId);
      if (trash && trash !== op.folderPath) {
        await client.moveMessages(op.uid, trash);
      } else {
        await client.deleteMessages(op.uid);
      }
    }
  }

  /** Drains an account's operation queue over a single connection. @private */
  async _runOps(accountId) {
    if (this._opRunners.has(accountId)) return;
    this._opRunners.add(accountId);
    try {
      while ((this._opQueues.get(accountId) || []).length > 0) {
        const batch = this._opQueues.get(accountId);
        this._opQueues.set(accountId, []);

        let client = null;
        try {
          client = await this._getAuthenticatedClient(accountId);
        } catch (err) {
          for (const op of batch) this._retryOrDrop(op, err);
          continue;
        }

        const selected = { path: null };
        try {
          for (let i = 0; i < batch.length; i++) {
            const op = batch[i];
            try {
              await this._applyOp(client, op, selected);
              op.finish();
              this.emit('remoteOpApplied', { accountId, type: op.type, uid: op.uid, folder: op.folderPath });
            } catch (err) {
              this._retryOrDrop(op, err);
              if (!client.isAuthenticated) {
                // Connection died: requeue the rest and reconnect on the next pass.
                for (const rest of batch.slice(i + 1)) this._retryOrDrop(rest, err);
                break;
              }
            }
          }
        } finally {
          try { await client.logout(); } catch { client.destroy?.(); }
        }
      }
    } finally {
      this._opRunners.delete(accountId);
    }
  }

  /** @private */
  _retryOrDrop(op, err) {
    const delay = OP_RETRY_DELAYS_MS[op.attempts];
    op.attempts++;
    if (!err?.permanent && delay !== undefined) {
      const timer = setTimeout(() => {
        this._opTimers.delete(timer);
        const queue = this._opQueues.get(op.accountId) || [];
        queue.push(op);
        this._opQueues.set(op.accountId, queue);
        this._runOps(op.accountId);
      }, delay);
      timer.unref?.();
      this._opTimers.add(timer);
      return;
    }
    // Give up: next sync restores the server's state for this message.
    op.finish();
    const message = `Could not ${op.type === 'delete' ? 'delete' : 'update'} message on server: ${err?.message || err}`;
    this._setAccountStatus(op.accountId, { lastError: message, lastErrorAt: new Date().toISOString() });
    this.emit('remoteOpFailed', { accountId: op.accountId, type: op.type, uid: op.uid, error: err });
    if (!err?.permanent) console.error(`[Mailboxer] ${message}`);
  }

  /**
   * Fetches, parses and caches the full body of a message from the server.
   *
   * @param {object} message - Stored message record
   * @param {(raw: Buffer) => object} parse - MIME parser (raw -> {text, html, attachments, headers})
   * @returns {Promise<{parsed: object, raw: Buffer}>}
   */
  async fetchFullMessage(message, parse) {
    const accountId = message.accountId || message.account_id;
    const client = await this._getAuthenticatedClient(accountId);
    try {
      await client.selectMailbox(this._folderPathFor(message), true);
      const [result] = await client.fetchRawMessages(message.uid);
      if (!result) {
        const err = new Error('Message no longer exists on the server');
        err.statusCode = 404;
        throw err;
      }
      return { raw: result.raw, parsed: parse ? parse(result.raw) : null };
    } finally {
      try { await client.logout(); } catch { client.destroy?.(); }
    }
  }

  // ==========================================
  // CONVENIENCE STORAGE PROXIES
  // ==========================================

  /**
   * Retrieves messages from local SQLite store.
   */
  getMessages(options = {}) {
    return this.store.getMessages(options);
  }

  /**
   * Fast full-text search across local messages.
   */
  search(query, options = {}) {
    return this.store.search(query, options);
  }

  /**
   * Updates flags for a message in local SQLite store and queues remote UID STORE.
   */
  async updateMessageFlags(folderId, uid, flags, options = {}) {
    this.store.updateMessageFlags(folderId, uid, flags);

    if (options.client) {
      await options.client.storeFlags(uid, flags, options.mode || 'FLAGS');
    }
  }
}
