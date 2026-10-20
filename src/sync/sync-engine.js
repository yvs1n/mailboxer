/**
 * Mailboxer Incremental IMAP Synchronization Engine
 *
 * Coordinates RFC 3501 synchronization lifecycle across multi-provider email accounts.
 * Manages UIDVALIDITY invalidation, incremental delta UID fetching, flag reconciliation,
 * and remote deletion pruning with persistent SQLite backing.
 *
 * @module sync/sync-engine
 */

import { EventEmitter } from 'node:events';
import { ImapClient } from '../connection/imap-client.js';
import { SqliteStore } from '../storage/sqlite-store.js';
import { defaultAccountManager } from '../auth/account-manager.js';
import { defaultClassifier } from '../triage/classifier.js';

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

    this._isSyncing = new Map();
    this._periodicTimer = null;
    this.lastSyncAt = null;
  }

  /**
   * Whether a background periodic sync is currently active.
   * @returns {boolean}
   */
  get isPeriodicSyncActive() {
    return this._periodicTimer !== null;
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
      throw new Error(`Account "${accountId}" not found in account manager or storage`);
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

  /**
   * Synchronizes a single IMAP folder / mailbox for an account.
   *
   * Lifecycle:
   * 1. Mailbox Selection: queries UIDVALIDITY, UIDNEXT, total messages.
   * 2. Cache Invalidation: if UIDVALIDITY changed, purges cached local messages.
   * 3. Delta UID Fetch: queries UID <maxLocalUid + 1>:* and fetches missing messages.
   * 4. Flag Reconciliation: updates local read/unread state using UID SEARCH UNSEEN.
   * 5. Deleted UID Pruning: purges messages removed from the remote mailbox.
   *
   * @param {string} accountId - Account ID
   * @param {string} folderName - Mailbox name (e.g. 'INBOX')
   * @param {object} [options={}] - Options
   * @returns {Promise<object>} FolderSyncResult
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
        flushed = true;
        this.emit('cacheInvalidated', {
          accountId,
          folder: folderName,
          oldUidValidity: existingFolder.uidvalidity,
          newUidValidity: selectResult.uidValidity
        });
      }

      // Upsert folder metadata in SQLite
      this.store.upsertFolder({
        id: folderId,
        accountId,
        name: folderName,
        path: folderPath,
        delimiter: existingFolder?.delimiter || '/',
        flags: selectResult.flags || [],
        uidvalidity: selectResult.uidValidity,
        uidnext: selectResult.uidNext,
        totalMessages: selectResult.exists || 0,
        lastSyncedAt: new Date().toISOString(),
        syncStatus: 'SYNCING'
      });

      // 3. Delta UID Fetch (Restricted to 2025 onwards for fresh inbox)
      const sinceCriteria = options.since || process.env.MAILBOXER_SYNC_SINCE || 'SINCE 1-Jan-2025';
      const minDateStr = options.minDate || process.env.MAILBOXER_MIN_DATE || '2025-01-01T00:00:00.000Z';
      const minTimestamp = new Date(minDateStr).getTime();

      const maxLocalUid = this.store.getMaxUid(folderId);
      let uidsToFetch = [];

      if (maxLocalUid === null || maxLocalUid === 0) {
        // Initial sync: fetch fresh UIDs from 2025 onwards
        let freshUids = [];
        try {
          freshUids = await client.searchUids(sinceCriteria);
        } catch {
          freshUids = await client.searchUids('ALL');
        }
        uidsToFetch = options.initialLimit ? freshUids.slice(-options.initialLimit) : freshUids;
      } else {
        // Incremental sync & Historical Backfill:
        const rangeCriteria = `UID ${maxLocalUid + 1}:*`;
        const candidateUids = await client.searchUids(rangeCriteria);
        // Exclude any UID <= maxLocalUid (RFC 3501 quirk fallback)
        const newUids = candidateUids.filter(u => u > maxLocalUid);

        // Also backfill any missing historical messages from 2025 onwards
        let missingUids = [];
        if (this.store.getFolderUids) {
          let allRemoteUids = [];
          try {
            allRemoteUids = await client.searchUids(sinceCriteria);
          } catch {
            allRemoteUids = await client.searchUids('ALL');
          }
          const localUids = new Set(this.store.getFolderUids(folderId));
          missingUids = allRemoteUids.filter(u => !localUids.has(u) && !newUids.includes(u));
        }

        uidsToFetch = [...newUids, ...missingUids];
      }

      let fetchedCount = 0;
      if (uidsToFetch.length > 0) {
        const batchSize = options.batchSize || this.batchSize || 50;
        for (let i = 0; i < uidsToFetch.length; i += batchSize) {
          const chunk = uidsToFetch.slice(i, i + batchSize);
          const range = chunk.join(',');
          const fetchedMessages = await client.fetchMessages(range);

          // Strictly filter out messages older than 2025
          const freshMessages = fetchedMessages.filter(m => {
            if (!m.date) return true;
            const t = new Date(m.date).getTime();
            return isNaN(t) || t >= minTimestamp;
          });

          const records = freshMessages.map(m => {
            let triage = { category: 'NORMAL', score: 50, isNoise: false, reason: null };
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
              triageReason: triage.reason || null
            };
          });

          this.store.upsertMessages(records);
          fetchedCount += records.length;

          for (const rec of records) {
            this.emit('messageAdded', rec);
          }
        }
      }

      // 4. Flag Reconciliation via UID SEARCH UNSEEN
      const unseenUids = await client.searchUids('UNSEEN');
      this.store.reconcileSeenFlags(folderId, unseenUids);
      this.emit('flagsReconciled', {
        accountId,
        folder: folderName,
        unseenCount: unseenUids.length
      });

      // 5. Remote Deletion Pruning via UID SEARCH (matching sinceCriteria)
      let allRemoteUids = [];
      try {
        allRemoteUids = await client.searchUids(sinceCriteria);
      } catch {
        allRemoteUids = await client.searchUids('ALL');
      }
      const prunedCount = this.store.pruneDeletedUids(folderId, allRemoteUids);
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
        name: folderName,
        path: folderPath,
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
      this.store.upsertFolder({
        id: folderId,
        accountId,
        name: folderName,
        path: folderName,
        syncStatus: 'ERROR',
        syncError: err.message || String(err),
        lastSyncedAt: new Date().toISOString()
      });
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
   * Performs an incremental sync of all selectable folders for an account.
   *
   * @param {string} accountId - Account identifier
   * @param {object} [options={}] - Sync options
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
      try {
        folders = await client.listMailboxes('', '*');
      } catch {
        folders = [];
      }

      // Filter selectable folders or default to INBOX
      let selectableFolders = folders.filter(f => f.selectable !== false);
      if (selectableFolders.length === 0) {
        selectableFolders = [{ name: 'INBOX', path: 'INBOX' }];
      }

      for (const folder of selectableFolders) {
        const folderName = folder.path || folder.name;
        try {
          const res = await this.syncFolder(accountId, folderName, {
            ...options,
            client
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

      this.lastSyncAt = new Date().toISOString();
      const totalNew = folderResults.reduce((acc, r) => acc + (r.newMessagesCount || 0), 0);
      const totalPruned = folderResults.reduce((acc, r) => acc + (r.prunedCount || 0), 0);

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
            await this.syncAccount(id, { throwOnError: false }).catch(() => {});
          }
        }
      } catch (err) {
        this.emit('error', err);
      }
    };

    this._periodicTimer = setInterval(runSyncCycle, interval);
    if (this._periodicTimer.unref) {
      this._periodicTimer.unref();
    }
  }

  /**
   * Stops periodic background synchronization.
   */
  stopPeriodicSync() {
    if (this._periodicTimer) {
      clearInterval(this._periodicTimer);
      this._periodicTimer = null;
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
