/**
 * Mailboxer Real-Time IMAP IDLE Manager & Adaptive Polling Fallback
 *
 * Implements RFC 2177 real-time event streaming across multi-provider accounts
 * with 25-minute keepalive renewal, exponential backoff reconnection with jitter,
 * adaptive polling fallback for servers without IDLE capability, and automated
 * triage sync dispatching.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module connection/idle-manager
 */

import { EventEmitter } from 'node:events';
import { ImapClient, IMAP_STATES } from './imap-client.js';
import { defaultClassifier } from '../triage/classifier.js';

/**
 * Default timing constants.
 */
export const IDLE_CONSTANTS = Object.freeze({
  KEEPALIVE_INTERVAL_MS: 25 * 60 * 1000, // 25 minutes (RFC 2177 recommends < 29 minutes)
  ACTIVE_POLL_INTERVAL_MS: 60 * 1000,    // 60 seconds (daytime / active hours)
  NIGHT_POLL_INTERVAL_MS: 300 * 1000,    // 300 seconds (5 mins, inactive hours)
  INITIAL_BACKOFF_MS: 1000,
  MAX_BACKOFF_MS: 60000
});

/**
 * Manages IMAP IDLE and polling fallback sessions across configured accounts.
 */
export class IdleManager extends EventEmitter {
  /**
   * @param {object} [options={}]
   * @param {import('../sync/sync-engine.js').SyncEngine} [options.syncEngine] - Sync engine instance
   * @param {import('../storage/sqlite-store.js').SqliteStore} [options.store] - Database store instance
   * @param {object} [options.accountManager] - Account manager instance
   * @param {import('../notifications/manager.js').NotificationManager} [options.notificationManager] - Notification dispatcher
   * @param {import('../triage/classifier.js').Classifier} [options.classifier] - Email classifier
   * @param {Function} [options.createClient] - Optional custom ImapClient factory
   * @param {number} [options.keepaliveIntervalMs] - Keepalive interval in ms (default: 25 min)
   * @param {number} [options.pollIntervalMs] - Adaptive poll interval in ms (default: 60s)
   */
  constructor(options = {}) {
    super();

    this.syncEngine = options.syncEngine || null;
    this.store = options.store || options.db || this.syncEngine?.store || null;
    this.accountManager = options.accountManager || this.syncEngine?.accountManager || null;
    this.notificationManager = options.notificationManager || null;
    this.classifier = options.classifier || defaultClassifier;
    this.createClient = options.createClient || ((config) => new ImapClient({ accountConfig: config }));

    this.keepaliveIntervalMs = options.keepaliveIntervalMs || IDLE_CONSTANTS.KEEPALIVE_INTERVAL_MS;
    this.pollIntervalMs = options.pollIntervalMs || IDLE_CONSTANTS.ACTIVE_POLL_INTERVAL_MS;
    this.nightPollIntervalMs = options.nightPollIntervalMs || IDLE_CONSTANTS.NIGHT_POLL_INTERVAL_MS;

    // Map of accountId -> SessionState
    this._sessions = new Map();
    this._running = false;
  }

  /**
   * Whether the IdleManager is actively running.
   * @returns {boolean}
   */
  get isRunning() {
    return this._running;
  }

  /**
   * Starts IDLE / polling monitoring across all configured accounts.
   */
  async start() {
    this._running = true;
    let accounts = [];

    if (this.accountManager?.getAccounts) {
      accounts = await this.accountManager.getAccounts();
    } else if (this.accountManager?.listAccounts) {
      accounts = await this.accountManager.listAccounts();
    } else if (this.store?.getAccounts) {
      accounts = this.store.getAccounts();
    }

    const startPromises = accounts.map(a => this.startAccount(a.id || a).catch(err => {
      this.emit('error', { accountId: a.id || a, error: err });
    }));

    await Promise.allSettled(startPromises);
  }

  /**
   * Starts monitoring one account if it isn't already monitored.
   * Lets callers start accounts individually (e.g. after their first good sync)
   * instead of all at once with start().
   *
   * @param {string} accountId
   */
  async ensureAccount(accountId) {
    if (!accountId || this._sessions.has(accountId)) return;
    this._running = true;
    await this.startAccount(accountId);
  }

  /**
   * Stops all active monitoring sessions cleanly.
   */
  async stop() {
    this._running = false;
    const stopPromises = Array.from(this._sessions.keys()).map(id => this.stopAccount(id));
    await Promise.allSettled(stopPromises);
    this._sessions.clear();
  }

  /**
   * Checks if an account is currently monitoring via IDLE.
   * @param {string} accountId
   * @returns {boolean}
   */
  isAccountIdling(accountId) {
    const session = this._sessions.get(accountId);
    return session ? session.mode === 'IDLE' && session.client?.state === IMAP_STATES.IDLE : false;
  }

  /**
   * Checks if an account is currently monitoring via adaptive polling fallback.
   * @param {string} accountId
   * @returns {boolean}
   */
  isAccountPolling(accountId) {
    const session = this._sessions.get(accountId);
    return session ? session.mode === 'POLLING' : false;
  }

  /**
   * Returns diagnostic status metrics across all monitored accounts.
   * @returns {object}
   */
  getStatus() {
    const result = {
      running: this._running,
      totalMonitored: this._sessions.size,
      idleAccounts: 0,
      pollingAccounts: 0,
      sessions: {}
    };

    for (const [id, s] of this._sessions.entries()) {
      if (s.mode === 'IDLE') result.idleAccounts++;
      if (s.mode === 'POLLING') result.pollingAccounts++;

      result.sessions[id] = {
        mode: s.mode,
        folder: s.folderName,
        lastKnownExists: s.lastKnownExists,
        lastKeepaliveAt: s.lastKeepaliveAt,
        lastSyncAt: s.lastSyncAt,
        reconnectAttempts: s.reconnectAttempts,
        status: s.client?.state || 'STOPPED'
      };
    }

    return result;
  }

  /**
   * Starts monitoring for a specific account.
   *
   * @param {string} accountId - Target account identifier
   * @param {object} [options={}]
   * @param {string} [options.folderName='INBOX'] - Folder to idle on
   */
  async startAccount(accountId, options = {}) {
    if (!accountId) return;
    if (this._sessions.has(accountId)) {
      await this.stopAccount(accountId);
    }

    const folderName = options.folderName || 'INBOX';
    const session = {
      accountId,
      folderName,
      mode: 'INITIALIZING',
      client: null,
      keepaliveTimer: null,
      pollTimer: null,
      reconnectTimer: null,
      reconnectAttempts: 0,
      lastKnownExists: null,
      lastKeepaliveAt: null,
      lastSyncAt: null,
      destroyed: false
    };

    this._sessions.set(accountId, session);

    try {
      await this._connectAndStartMonitoring(session);
    } catch (err) {
      this.emit('error', { accountId, error: err });
      this._scheduleReconnect(session);
    }
  }

  /**
   * Stops monitoring for a specific account.
   *
   * @param {string} accountId
   */
  async stopAccount(accountId) {
    const session = this._sessions.get(accountId);
    if (!session) return;

    session.destroyed = true;
    if (session.keepaliveTimer) clearTimeout(session.keepaliveTimer);
    if (session.pollTimer) clearTimeout(session.pollTimer);
    if (session.reconnectTimer) clearTimeout(session.reconnectTimer);

    if (session.client) {
      try {
        if (session.client.state === IMAP_STATES.IDLE) {
          await session.client.done({ timeoutMs: 2000 }).catch(() => {});
        }
        await session.client.logout().catch(() => {});
      } catch {
        // Safe teardown
      }
      session.client = null;
    }

    this._sessions.delete(accountId);
    this.emit('stopped', { accountId });
  }

  /**
   * Resolves account credentials and connects an ImapClient.
   * @private
   */
  async _resolveAccountConfig(accountId) {
    let accountConfig = null;
    if (this.accountManager?.getAccount) {
      accountConfig = await this.accountManager.getAccount(accountId);
    }
    if (!accountConfig && this.accountManager?.getAccounts) {
      const all = await this.accountManager.getAccounts();
      accountConfig = all.find(a => a.id === accountId);
    }
    if (!accountConfig && this.store?.getAccount) {
      accountConfig = this.store.getAccount(accountId);
    }
    if (!accountConfig) {
      throw new Error(`Account "${accountId}" not found`);
    }
    return accountConfig;
  }

  /**
   * Connects, selects mailbox, inspects capabilities, and enters IDLE or Polling mode.
   * @private
   */
  async _connectAndStartMonitoring(session) {
    if (session.destroyed || !this._running) return;

    const accountConfig = await this._resolveAccountConfig(session.accountId);
    const client = this.createClient(accountConfig);
    session.client = client;

    // Connect
    if (!client.isConnected) {
      await client.connect({
        host: accountConfig.imap?.host || accountConfig.host,
        port: accountConfig.imap?.port || accountConfig.port,
        secure: accountConfig.imap?.secure ?? accountConfig.secure ?? true,
        provider: accountConfig.provider
      });
    }

    // Authenticate
    if (!client.isAuthenticated) {
      const user = accountConfig.auth?.user || accountConfig.email;
      const pass = accountConfig.auth?.pass || accountConfig.appPassword || accountConfig.password;
      await client.login(user, pass, {
        type: accountConfig.auth?.type,
        accessToken: accountConfig.auth?.accessToken
      });
    }

    // Select mailbox
    const selectRes = await client.selectMailbox(session.folderName);
    session.lastKnownExists = selectRes.totalMessages ?? null;
    session.reconnectAttempts = 0;

    // Setup socket drop / close recovery
    client.on('close', () => {
      if (!session.destroyed && this._running) {
        this.emit('disconnected', { accountId: session.accountId, mode: session.mode });
        this._scheduleReconnect(session);
      }
    });

    client.on('error', (err) => {
      this.emit('clientError', { accountId: session.accountId, error: err });
    });

    // Check IDLE capability
    const supportsIdle = client.hasCapability('IDLE');

    if (supportsIdle) {
      await this._enterIdleMode(session);
    } else {
      this._enterPollingMode(session);
    }
  }

  /**
   * Sets up RFC 2177 IDLE state machine with keepalive timer and exists event handling.
   * @private
   */
  async _enterIdleMode(session) {
    session.mode = 'IDLE';

    const client = session.client;
    if (!client || session.destroyed) return;

    // Listen for unsolicited EXISTS push notifications
    const onExists = async (count) => {
      if (session.destroyed) return;
      const prevCount = session.lastKnownExists;
      session.lastKnownExists = count;

      this.emit('exists', { accountId: session.accountId, count, prevCount });

      // Trigger sync if count increased or unknown
      if (prevCount === null || count > prevCount) {
        await this._handleNewMessagesDetected(session);
      }
    };

    client.on('exists', onExists);

    // Enter IDLE
    await client.idle();
    session.lastKeepaliveAt = new Date().toISOString();
    this.emit('idle', { accountId: session.accountId, folder: session.folderName });

    // Schedule 25-minute keepalive cycling (RFC 2177)
    this._scheduleKeepalive(session);
  }

  /**
   * Schedules the 25-minute keepalive cycle (DONE then re-IDLE).
   * @private
   */
  _scheduleKeepalive(session) {
    if (session.keepaliveTimer) clearTimeout(session.keepaliveTimer);
    if (session.destroyed || !this._running || session.mode !== 'IDLE') return;

    session.keepaliveTimer = setTimeout(async () => {
      if (session.destroyed || !this._running || session.mode !== 'IDLE') return;

      try {
        const client = session.client;
        if (client && client.state === IMAP_STATES.IDLE) {
          await client.done();
          await client.idle();
          session.lastKeepaliveAt = new Date().toISOString();
          this.emit('keepalive', { accountId: session.accountId, timestamp: session.lastKeepaliveAt });
          this._scheduleKeepalive(session);
        }
      } catch (err) {
        this.emit('keepaliveError', { accountId: session.accountId, error: err });
        this._scheduleReconnect(session);
      }
    }, this.keepaliveIntervalMs);
  }

  /**
   * Starts adaptive polling loop when IDLE capability is unavailable on server.
   * @private
   */
  _enterPollingMode(session) {
    session.mode = 'POLLING';
    this.emit('pollingFallback', { accountId: session.accountId, folder: session.folderName });
    this._schedulePoll(session);
  }

  /**
   * Computes adaptive polling interval based on active daytime vs quiet night hours.
   * @private
   */
  _getAdaptivePollInterval() {
    const hour = new Date().getHours();
    // Active daytime hours: 08:00 - 22:00
    if (hour >= 8 && hour < 22) {
      return this.pollIntervalMs;
    }
    return this.nightPollIntervalMs;
  }

  /**
   * Schedules the next polling execution.
   * @private
   */
  _schedulePoll(session) {
    if (session.pollTimer) clearTimeout(session.pollTimer);
    if (session.destroyed || !this._running || session.mode !== 'POLLING') return;

    const interval = this._getAdaptivePollInterval();
    session.pollTimer = setTimeout(async () => {
      if (session.destroyed || !this._running || session.mode !== 'POLLING') return;

      try {
        const client = session.client;
        if (client && client.isConnected) {
          const status = await client.getStatus(session.folderName);
          const prevCount = session.lastKnownExists;
          session.lastKnownExists = status.totalMessages;

          if (prevCount === null || status.totalMessages > prevCount) {
            await this._handleNewMessagesDetected(session);
          }
        }
        this._schedulePoll(session);
      } catch (err) {
        this.emit('pollError', { accountId: session.accountId, error: err });
        this._scheduleReconnect(session);
      }
    }, interval);
  }

  /**
   * Handles newly arrived emails: exits IDLE if needed, performs incremental sync,
   * runs messages through classifier, and dispatches VIP notifications.
   * @private
   */
  async _handleNewMessagesDetected(session) {
    // Several EXISTS updates can arrive back to back; run one sync at a time.
    if (session.handling) {
      session.pendingRecheck = true;
      return;
    }
    session.handling = true;

    const client = session.client;
    const wasIdling = client && client.state === IMAP_STATES.IDLE;

    try {
      if (wasIdling) {
        await client.done();
      }

      session.lastSyncAt = new Date().toISOString();

      let newMessages = [];
      let syncReportedMessages = false;

      // If SyncEngine is injected, run incremental sync on this folder
      if (this.syncEngine?.syncFolder) {
        const syncResult = await this.syncEngine.syncFolder(session.accountId, session.folderName);
        if (syncResult && Array.isArray(syncResult.fetchedMessages)) {
          newMessages = syncResult.fetchedMessages;
          syncReportedMessages = true;
        } else if (syncResult && Array.isArray(syncResult.messages)) {
          // Only genuinely new arrivals, not historical backfill
          newMessages = syncResult.messages.filter(m => m.isNew !== false);
          syncReportedMessages = true;
        }
      }

      // Without a sync result, fall back to the most recent stored messages.
      // (Skipped when the sync engine reported what it stored, so the same
      // messages are not alerted on again.)
      if (!syncReportedMessages && newMessages.length === 0 && this.store?.getMessages) {
        const folder = this.store.getFolder(session.accountId, session.folderName);
        if (folder) {
          newMessages = this.store.getMessages({
            accountId: session.accountId,
            folderId: folder.id,
            limit: 5,
            orderBy: 'date DESC'
          });
        }
      }

      // Process new messages through Classifier and NotificationManager
      for (const msg of newMessages) {
        const triageResult = this.classifier.classifyMessage
          ? this.classifier.classifyMessage(msg)
          : this.classifier.classify(msg);

        this.emit('triage', { accountId: session.accountId, message: msg, triage: triageResult });

        if (triageResult.shouldNotify || triageResult.category === 'VIP') {
          if (this.notificationManager?.dispatch) {
            await this.notificationManager.dispatch(msg, triageResult).catch(() => {});
          }
          this.emit('notification', { accountId: session.accountId, message: msg, triage: triageResult });
        }
      }
    } catch (err) {
      this.emit('syncError', { accountId: session.accountId, error: err });
    } finally {
      session.handling = false;
      // Re-enter IDLE if we were previously idling
      if (wasIdling && !session.destroyed && this._running && client && client.isConnected) {
        try {
          await client.idle();
          session.lastKeepaliveAt = new Date().toISOString();
          this._scheduleKeepalive(session);
        } catch (err) {
          this._scheduleReconnect(session);
        }
      }
      if (session.pendingRecheck && !session.destroyed && this._running) {
        session.pendingRecheck = false;
        this._handleNewMessagesDetected(session).catch(() => {});
      }
    }
  }

  /**
   * Reconnects with exponential backoff and jitter.
   * @private
   */
  _scheduleReconnect(session) {
    if (session.reconnectTimer) clearTimeout(session.reconnectTimer);
    if (session.destroyed || !this._running) return;

    if (session.client) {
      try { session.client.destroy?.(); } catch {}
      session.client = null;
    }

    session.reconnectAttempts++;
    const attempts = Math.min(session.reconnectAttempts, 6);
    const baseDelay = Math.min(IDLE_CONSTANTS.MAX_BACKOFF_MS, IDLE_CONSTANTS.INITIAL_BACKOFF_MS * Math.pow(2, attempts));
    const jitter = Math.floor(Math.random() * 1000);
    const delay = baseDelay + jitter;

    this.emit('reconnecting', {
      accountId: session.accountId,
      attempt: session.reconnectAttempts,
      delayMs: delay
    });

    session.reconnectTimer = setTimeout(async () => {
      if (session.destroyed || !this._running) return;
      try {
        await this._connectAndStartMonitoring(session);
      } catch (err) {
        this.emit('error', { accountId: session.accountId, error: err });
        this._scheduleReconnect(session);
      }
    }, delay);
  }
}
