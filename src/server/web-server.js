/**
 * Mailboxer Native HTTP Web Server & Onboarding Gateway
 *
 * Serves the responsive client onboarding dashboard and REST API endpoints:
 * - One-click OAuth 2.0 popup flows for Google Mail and Microsoft Outlook
 * - Guided Apple Mail App-Specific Password onboarding
 * - Encrypted account management with permanent login sessions
 * - Live IMAP connection diagnostics
 *
 * Zero-dependency native Node.js 22 implementation using node:http and node:fs.
 *
 * @module server/web-server
 */

import http from 'node:http';
import fs from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultAccountManager } from '../auth/account-manager.js';
import { SqliteStore } from '../storage/sqlite-store.js';
import { Classifier } from '../triage/classifier.js';
import { NotificationManager } from '../notifications/manager.js';
import { SyncEngine } from '../sync/sync-engine.js';
import { IdleManager } from '../connection/idle-manager.js';
import { ImapClient } from '../connection/imap-client.js';
import { MailService } from '../mail/mail-service.js';
import { AuthGuard, isCrossSiteRequest } from './auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../../public');

let APP_VERSION = '0.0.0';
try {
  APP_VERSION = JSON.parse(readFileSync(path.resolve(__dirname, '../../package.json'), 'utf8')).version || APP_VERSION;
} catch {}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

export class WebServer {
  /**
   * @param {object} [options={}]
   * @param {number} [options.port=3000]
   * @param {string} [options.host='localhost']
   * @param {AccountManager} [options.accountManager]
   * @param {SqliteStore} [options.store]
   * @param {NotificationManager} [options.notificationManager]
   * @param {Classifier} [options.classifier]
   * @param {SyncEngine} [options.syncEngine]
   * @param {IdleManager} [options.idleManager]
   * @param {AuthGuard} [options.auth] - Login guard (default reads MAILBOXER_PASSWORD)
   */
  constructor(options = {}) {
    const parsedOptPort = options.port !== undefined && options.port !== null && options.port !== '' && !Number.isNaN(Number(options.port)) ? Number(options.port) : null;
    const parsedEnvPort = process.env.PORT !== undefined && process.env.PORT !== '' && !Number.isNaN(Number(process.env.PORT)) ? Number(process.env.PORT) : null;
    this.port = parsedOptPort ?? parsedEnvPort ?? 3000;

    const validOptHost = typeof options.host === 'string' && options.host.trim().length > 0 ? options.host.trim() : null;
    const validEnvHost = typeof process.env.HOST === 'string' && process.env.HOST.trim().length > 0 ? process.env.HOST.trim() : null;
    this.host = validOptHost || validEnvHost || '0.0.0.0';
    this.accountManager = options.accountManager || defaultAccountManager;
    this.dataDir = options.dataDir || options.accountManager?.vault?.dataDir || process.env.DATA_DIR || path.resolve(process.cwd(), 'data');

    const defaultDbPath = options.dbPath || (this.accountManager?.vault?.dataDir
      ? path.join(this.accountManager.vault.dataDir, 'mailboxer.sqlite')
      : (process.env.SQLITE_PATH || path.resolve(this.dataDir, 'mailboxer.sqlite')));

    this.auth = options.auth || new AuthGuard({ dataDir: this.dataDir });

    this.store = options.store || new SqliteStore(defaultDbPath);
    if (this.store && !this.accountManager.store) {
      this.accountManager.store = this.store;
    }

    // Auto-clean pre-2025 legacy backlog to ensure fresh mailbox
    try {
      if (this.store && typeof this.store.purgeOlderThan === 'function') {
        const minCutoff = process.env.MAILBOXER_MIN_DATE || '2025-01-01T00:00:00.000Z';
        this.store.purgeOlderThan(minCutoff);
      }
    } catch {}
    this.classifier = options.classifier || new Classifier({ store: this.store });
    this.notificationManager = options.notificationManager || new NotificationManager({ store: this.store });
    this.syncEngine = options.syncEngine || new SyncEngine({
      store: this.store,
      accountManager: this.accountManager,
      classifier: this.classifier,
      // A unified inbox: only INBOX by default (no Spam/Trash/All Mail duplicates)
      folders: process.env.MAILBOXER_SYNC_FOLDERS || 'INBOX'
    });

    // Real-time new-mail detection. Notifications are sent from one place (see
    // _onMessageAdded), so the IDLE manager itself doesn't dispatch them.
    this.enableIdle = options.enableIdle ?? (process.env.MAILBOXER_IDLE !== 'false');
    this.idleManager = options.idleManager || new IdleManager({
      syncEngine: this.syncEngine,
      store: this.store,
      accountManager: this.accountManager,
      notificationManager: null,
      classifier: this.classifier,
      createClient: (cfg) => (this.accountManager._createImapClient ? this.accountManager._createImapClient(cfg) : new ImapClient({ accountConfig: cfg }))
    });
    // Reconnects retry with backoff; log each distinct error once per account.
    const lastIdleError = new Map();
    this.idleManager.on?.('error', ({ accountId, error } = {}) => {
      const msg = error?.message || String(error);
      if (lastIdleError.get(accountId) === msg) return;
      lastIdleError.set(accountId, msg);
      console.error(`[Mailboxer] IDLE monitor error for ${accountId}: ${msg}`);
    });
    this.idleManager.on?.('idle', ({ accountId } = {}) => lastIdleError.delete(accountId));

    this.mailService = options.mailService || new MailService({
      syncEngine: this.syncEngine,
      store: this.store,
      accountManager: this.accountManager
    });

    this._onMessageAdded = this._onMessageAdded.bind(this);
    this.syncEngine.on?.('messageAdded', this._onMessageAdded);

    this.server = null;
  }

  /**
   * Starts syncing and live monitoring for a newly connected account.
   * @private
   */
  _onAccountAdded(accountId) {
    if (!accountId) return;
    // IDLE monitoring begins once this first sync succeeds (see start())
    this.syncEngine?.syncAccount(accountId, { throwOnError: false }).catch(() => {});
  }

  /**
   * Sends a VIP alert for genuinely new, unread inbox mail.
   * @private
   */
  _onMessageAdded(record) {
    if (!record?.isNew || record.isSeen || !this.notificationManager?.dispatch) return;
    const isInbox = String(record.folderId || '').toUpperCase().endsWith(':INBOX');
    const ageMs = Date.now() - new Date(record.date).getTime();
    // Skip mail that only looks new (moved in from elsewhere, or very old)
    if (!isInbox || !(ageMs < 48 * 60 * 60 * 1000)) return;
    const triage = {
      category: record.category,
      score: record.triageScore,
      shouldNotify: Boolean(record.shouldNotify)
    };
    if (!triage.shouldNotify && triage.category !== 'VIP') return;
    this.notificationManager.dispatch(record, triage).catch((err) => {
      console.error(`[Mailboxer] Notification dispatch failed: ${err.message}`);
    });
  }

  async start() {
    if (this.server && this.server.listening) {
      const actualPort = this.server.address()?.port || this.port;
      const isWildcard = this.host === '0.0.0.0' || this.host === '::';
      const loopbackHost = this.host === '::' ? '[::1]' : '127.0.0.1';
      const clientHost = isWildcard ? loopbackHost : this.host;
      const formattedHost = clientHost.includes(':') && !clientHost.startsWith('[') ? `[${clientHost}]` : clientHost;
      return `http://${formattedHost}:${actualPort}`;
    }

    await this.accountManager.init();

    if (this.auth.mode === 'locked') {
      console.warn('[Mailboxer] MAILBOXER_PASSWORD is not set. The API is locked until you set it.');
    } else if (this.auth.mode === 'disabled') {
      console.warn('[Mailboxer] MAILBOXER_PASSWORD is not set. Login is disabled (development mode only).');
    }

    this.server = http.createServer((req, res) => {
      this._handleRequest(req, res).catch((err) => {
        console.error('Unhandled server error:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: err.message || 'Internal server error' }));
        }
      });
    });

    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject);
        const actualPort = this.server.address()?.port || this.port;
        const isWildcard = this.host === '0.0.0.0' || this.host === '::';
        const loopbackHost = this.host === '::' ? '[::1]' : '127.0.0.1';
        const clientHost = isWildcard ? loopbackHost : this.host;
        const formattedHost = clientHost.includes(':') && !clientHost.startsWith('[') ? `[${clientHost}]` : clientHost;
        const address = `http://${formattedHost}:${actualPort}`;

        // Start background email synchronization engine. With IDLE pushing new
        // mail instantly, the full sweep (flags, deletions) can run less often.
        if (this.syncEngine) {
          const envInterval = Number(process.env.MAILBOXER_SYNC_INTERVAL_MS);
          const interval = envInterval > 0 ? envInterval : (this.enableIdle ? 5 * 60 * 1000 : 60000);
          this.syncEngine.startPeriodicSync(interval);
          this.accountManager.listAccounts().then((accounts) => {
            for (const acc of accounts) {
              const id = acc.id || acc.email;
              if (id) {
                this.syncEngine.syncAccount(id, { throwOnError: false }).catch(() => {});
              }
            }
          }).catch(() => {});
        }
        // Live IDLE monitoring starts per account after its first successful sync,
        // so accounts with bad credentials aren't hammered by two retry loops.
        if (this.enableIdle && this.idleManager?.ensureAccount && this.syncEngine?.on) {
          this._onSyncComplete = ({ accountId } = {}) => {
            if (this.server?.listening && accountId) this.idleManager.ensureAccount(accountId).catch(() => {});
          };
          this.syncEngine.on('syncComplete', this._onSyncComplete);
        }

        resolve(address);
      });
    });
  }

  async stop() {
    if (this._onSyncComplete) {
      this.syncEngine?.removeListener?.('syncComplete', this._onSyncComplete);
      this._onSyncComplete = null;
    }
    this.syncEngine?.removeListener?.('messageAdded', this._onMessageAdded);
    if (this.idleManager) {
      await this.idleManager.stop().catch(() => {});
    }
    if (this.syncEngine) {
      this.syncEngine.stopPeriodicSync();
    }
    if (this.store) {
      this.store.close();
    }
    if (this.server) {
      this.server.closeAllConnections?.();
      return new Promise((resolve) => this.server.close(resolve));
    }
  }

  /**
   * Request router
   * @private
   */
  async _handleRequest(req, res) {
    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || 'localhost:3000'}`);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Bad Request: Invalid Host header', code: 'INVALID_HOST' }));
      return;
    }
    const pathname = url.pathname;
    const method = req.method.toUpperCase();

    // The web client is served from this same origin, so no CORS headers are sent.
    // Without them, browsers block other sites from reading API responses.
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Block other websites from making state-changing calls with the user's cookie.
    if (isCrossSiteRequest(req, this.auth.trustProxy)) {
      this._json(res, 403, { error: 'Cross-site request blocked', code: 'CROSS_SITE_FORBIDDEN' });
      return;
    }

    // Helper to safely parse JSON body with HTTP 400 / 413 error handling
    const getBody = async () => {
      try {
        const parsed = await this._parseJsonBody(req);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          const err = new Error('Request payload must be a non-empty JSON object');
          err.statusCode = 400;
          err.code = 'VALIDATION_ERROR';
          throw err;
        }
        return parsed;
      } catch (err) {
        this._json(res, err.statusCode || 400, {
          error: err.message,
          code: err.code || 'VALIDATION_ERROR'
        });
        return null;
      }
    };

    // --- AUTH ENDPOINTS (public) ---
    if (method === 'POST' && pathname === '/api/auth/login') {
      const body = await getBody();
      if (body === null) return;
      const result = this.auth.login(req, body.password);
      if (!result.ok) {
        if (result.retryAfter) res.setHeader('Retry-After', String(result.retryAfter));
        this._json(res, result.status, { error: result.error, code: result.code });
        return;
      }
      if (result.cookie) res.setHeader('Set-Cookie', result.cookie);
      this._json(res, 200, { success: true });
      return;
    }

    if (method === 'POST' && pathname === '/api/auth/logout') {
      res.setHeader('Set-Cookie', this.auth.clearCookie(req));
      this._json(res, 200, { success: true });
      return;
    }

    if (method === 'GET' && pathname === '/api/auth/session') {
      this._json(res, 200, {
        authenticated: this.auth.isAuthenticated(req),
        authRequired: this.auth.required,
        configured: this.auth.mode !== 'locked'
      });
      return;
    }

    const isAuthenticated = this.auth.isAuthenticated(req);

    // Public health check: only says the server is up. Details need a login.
    if (method === 'GET' && pathname === '/health' && !isAuthenticated) {
      this._json(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
      return;
    }

    // Every other API route requires a login.
    if (pathname.startsWith('/api/') && !isAuthenticated) {
      if (this.auth.mode === 'locked') {
        this._json(res, 503, {
          error: 'Login is not configured. Set MAILBOXER_PASSWORD on the server.',
          code: 'AUTH_NOT_CONFIGURED'
        });
        return;
      }
      this._json(res, 401, { error: 'Login required', code: 'UNAUTHORIZED' });
      return;
    }

    // --- REST API ENDPOINTS ---

    // 1. List accounts
    if (method === 'GET' && pathname === '/api/accounts') {
      const accounts = await this.accountManager.listAccounts();
      // Attach last sync time and last error so the UI can flag broken accounts
      const withStatus = accounts.map((acc) => {
        const status = this.syncEngine?.getAccountStatus?.(acc.id);
        return status ? { ...acc, lastSyncAt: status.lastSyncAt, syncError: status.lastError, syncErrorAt: status.lastErrorAt } : acc;
      });
      this._json(res, 200, { accounts: withStatus });
      return;
    }

    // 1b. Trigger on-demand sync cycle across accounts
    if (method === 'POST' && pathname === '/api/sync') {
      const wait = url.searchParams.get('await') === 'true';
      if (this.syncEngine) {
        const accounts = await this.accountManager.listAccounts();
        const promises = [];
        for (const acc of accounts) {
          const id = acc.id || acc.email;
          if (id) {
            const p = this.syncEngine.syncAccount(id, { throwOnError: false }).catch(() => {});
            promises.push(p);
          }
        }
        if (wait) {
          await Promise.all(promises);
        }
      }
      this._json(res, 200, {
        success: true,
        message: 'Sync cycle triggered',
        lastSyncAt: this.syncEngine?.lastSyncAt || new Date().toISOString()
      });
      return;
    }

    // 2. Add an account (Apple, Google, Outlook, custom IMAP)
    const addAccountHandlers = {
      '/api/accounts/apple': 'addAppleAccount',
      '/api/accounts/gmail': 'addGoogleAccount',
      '/api/accounts/google': 'addGoogleAccount',
      '/api/accounts/outlook': 'addOutlookAccount',
      '/api/accounts/custom': 'addCustomAccount'
    };
    if (method === 'POST' && Object.hasOwn(addAccountHandlers, pathname)) {
      const body = await getBody();
      if (body === null) return;
      try {
        const result = await this.accountManager[addAccountHandlers[pathname]](body);
        this._onAccountAdded(result.account?.id);
        this._json(res, 201, result);
      } catch (err) {
        this._json(res, 400, {
          error: err.message,
          code: err.code || 'VALIDATION_ERROR',
          remediationAdvice: err.remediationAdvice || ''
        });
      }
      return;
    }

    // 4. Test account connection
    const testMatch = pathname.match(/^\/api\/accounts\/([^/]+)\/test$/);
    if (method === 'POST' && testMatch) {
      const accountId = decodeURIComponent(testMatch[1]);
      try {
        const result = await this.accountManager.testAccount(accountId);
        this._json(res, 200, result);
      } catch (err) {
        const notFound = err.message?.includes('Account not found');
        this._json(res, notFound ? 404 : 400, {
          error: err.message,
          code: err.code || (notFound ? 'ACCOUNT_NOT_FOUND' : 'CONNECTION_FAILED'),
          remediationAdvice: err.remediationAdvice || ''
        });
      }
      return;
    }

    // 5. Get Account by ID (Public details)
    const getAccountMatch = pathname.match(/^\/api\/accounts\/([^/]+)$/);
    if (method === 'GET' && getAccountMatch) {
      const accountId = decodeURIComponent(getAccountMatch[1]);
      const account = await this.accountManager.vault.getById(accountId);
      if (!account) {
        this._json(res, 404, { error: `Account not found: ${accountId}`, code: 'ACCOUNT_NOT_FOUND' });
        return;
      }
      this._json(res, 200, {
        account: {
          id: account.id,
          provider: account.provider,
          label: account.label,
          email: account.email,
          authType: account.auth?.type || 'password',
          connected: true,
          lastVerifiedAt: account.lastVerifiedAt || null,
          createdAt: account.createdAt || null,
          updatedAt: account.updatedAt || null,
          expiresAt: account.auth?.expiresAt || null,
          inboxStatus: account.inboxStatus || null
        }
      });
      return;
    }

    // 6. Logout / Remove Account (Explicit User Action)
    const deleteMatch = pathname.match(/^\/api\/accounts\/([^/]+)$/);
    if (method === 'DELETE' && deleteMatch) {
      const accountId = decodeURIComponent(deleteMatch[1]);
      if (this.idleManager?.stopAccount) {
        await this.idleManager.stopAccount(accountId).catch(() => {});
      }
      const removed = await this.accountManager.logoutAccount(accountId);
      this._json(res, removed ? 200 : 404, { success: removed });
      return;
    }

    // 6. OAuth Authorization URL generator
    const authUrlMatch = pathname.match(/^\/api\/auth\/(gmail|outlook)\/url$/);
    if (method === 'GET' && authUrlMatch) {
      const provider = authUrlMatch[1];
      try {
        const authData = this.accountManager.oauth.getAuthorizationUrl(provider);
        this._json(res, 200, authData);
      } catch (err) {
        this._json(res, 400, {
          error: err.message,
          configured: this.accountManager.oauth.isConfigured(provider)
        });
      }
      return;
    }

    // 7. OAuth Status Checker
    if (method === 'GET' && pathname === '/api/oauth/status') {
      this._json(res, 200, {
        gmail: this.accountManager.oauth.isConfigured('gmail'),
        outlook: this.accountManager.oauth.isConfigured('outlook')
      });
      return;
    }

    // 8. OAuth Credentials Configurator
    if (method === 'POST' && pathname === '/api/oauth/credentials') {
      const body = await getBody();
      if (body === null) return;
      if (!body.provider || !['gmail', 'outlook'].includes(body.provider)) {
        this._json(res, 400, { error: 'Provider must be "gmail" or "outlook"', code: 'INVALID_PROVIDER' });
        return;
      }
      if (!body.clientId || typeof body.clientId !== 'string' || !body.clientId.trim()) {
        this._json(res, 400, { error: 'Missing or invalid clientId', code: 'MISSING_CLIENT_ID' });
        return;
      }
      this.accountManager.oauth.setCredentials(body.provider, {
        clientId: body.clientId.trim(),
        clientSecret: typeof body.clientSecret === 'string' ? body.clientSecret.trim() : ''
      });
      this._json(res, 200, { success: true });
      return;
    }

    // 9. OAuth Callback Endpoint (Handles browser popup redirect and API callback)
    const callbackMatch = pathname.match(/^\/api\/auth\/(gmail|outlook)\/callback$/);
    if ((method === 'GET' || method === 'POST') && callbackMatch) {
      const provider = callbackMatch[1];
      let code = url.searchParams.get('code');
      let state = url.searchParams.get('state');
      let error = url.searchParams.get('error');
      let errorDesc = url.searchParams.get('error_description');

      // If POST, also inspect body parameters
      if (method === 'POST') {
        try {
          const body = await this._parseRequestBody(req);
          if (body && typeof body === 'object') {
            code = code || body.code;
            state = state || body.state;
            error = error || body.error;
            errorDesc = errorDesc || body.error_description || body.errorDescription;
          }
        } catch (err) {
          this._json(res, err.statusCode || 400, {
            error: err.message,
            code: err.code || 'BAD_REQUEST'
          });
          return;
        }
      }

      const wantsJson = (method === 'POST' && !req.headers.accept?.includes('text/html')) || req.headers.accept?.includes('application/json');

      if (error) {
        if (state) {
          this.accountManager.oauth.validateAndConsumeState(state, provider);
        }
        if (wantsJson) {
          this._json(res, 400, {
            error: errorDesc || error,
            code: 'OAUTH_ERROR'
          });
          return;
        }
        this._sendOAuthPopupResult(res, false, null, errorDesc || error);
        return;
      }

      // CSRF state verification: if pending states exist, state must be valid
      if (this.accountManager.oauth.hasPendingStates()) {
        const stateValidation = this.accountManager.oauth.validateAndConsumeState(state, provider);
        if (!stateValidation.valid) {
          const errMsg = stateValidation.error || 'Invalid or missing OAuth state parameter (CSRF protection).';
          if (wantsJson) {
            this._json(res, 400, {
              error: errMsg,
              code: 'CSRF_STATE_INVALID'
            });
            return;
          }
          this._sendOAuthPopupResult(res, false, null, errMsg);
          return;
        }
      }

      if (!code) {
        const errMsg = 'No authorization code received.';
        if (wantsJson) {
          this._json(res, 400, {
            error: errMsg,
            code: 'MISSING_CODE'
          });
          return;
        }
        this._sendOAuthPopupResult(res, false, null, errMsg);
        return;
      }

      try {
        const account = await this.accountManager.handleOAuthCallback(provider, code);
        this._onAccountAdded(account?.id);
        if (wantsJson) {
          this._json(res, 200, { success: true, account });
          return;
        }
        this._sendOAuthPopupResult(res, true, account);
      } catch (err) {
        if (wantsJson) {
          this._json(res, 400, {
            error: err.message,
            code: err.code || 'AUTH_FAILED'
          });
          return;
        }
        this._sendOAuthPopupResult(res, false, null, err.message);
      }
      return;
    }

    // --- HEALTH & TELEMETRY ENDPOINT (R4 / Botkeep Cloud) ---
    if (method === 'GET' && pathname === '/health') {
      const uptimeSeconds = process.uptime();
      let accountCount = 0;
      let connectedCount = 0;
      try {
        const accounts = await this.accountManager.listAccounts();
        accountCount = accounts.length;
        connectedCount = accounts.filter(a => a.connected).length;
      } catch {}

      let pushSubsCount = 0;
      try {
        pushSubsCount = this.store.getPushSubscriptions().length;
      } catch {}

      const idleStatus = this.idleManager?.getStatus() || {
        running: false,
        idleAccounts: 0,
        pollingAccounts: 0
      };

      const mem = process.memoryUsage();
      const dataDir = this.dataDir || this.accountManager?.vault?.dataDir || process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
      let isWritable = true;
      try {
        await fs.mkdir(dataDir, { recursive: true });
        await fs.access(dataDir, fs.constants.W_OK);
      } catch {
        isWritable = false;
      }

      const isHealthy = isWritable && Boolean(this.store?.db);
      const status = isHealthy ? 'healthy' : 'degraded';
      const vault = this.accountManager?.vault;
      const vaultInitialized = Boolean(vault?._initialized);
      const vaultHasKey = Boolean(vault?._key);

      this._json(res, 200, {
        status,
        timestamp: new Date().toISOString(),
        uptimeSeconds: Math.round(uptimeSeconds * 10) / 10,
        version: APP_VERSION,
        environment: process.env.NODE_ENV || 'development',
        system: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          memoryUsageMb: {
            rss: +(mem.rss / 1048576).toFixed(1),
            heapTotal: +(mem.heapTotal / 1048576).toFixed(1),
            heapUsed: +(mem.heapUsed / 1048576).toFixed(1)
          },
          pid: process.pid
        },
        storage: {
          dataDir,
          persistent: true,
          writable: isWritable,
          databasePath: this.store?.dbPath || path.resolve(dataDir, 'mailboxer.sqlite'),
          vaultPath: this.accountManager?.vault?.vaultFilePath || path.resolve(dataDir, 'accounts.vault.json'),
          sqlite: {
            connected: Boolean(this.store?.db),
            journalMode: 'wal',
            tables: ['accounts', 'folders', 'messages', 'triage_rules', 'push_subscriptions']
          },
          vault: {
            initialized: vaultInitialized,
            hasKey: vaultHasKey,
            accountCount
          }
        },
        accounts: {
          total: accountCount,
          connected: connectedCount
        },
        idle: {
          running: Boolean(idleStatus.running),
          idleAccounts: idleStatus.idleAccounts || 0,
          pollingAccounts: idleStatus.pollingAccounts || 0
        },
        syncEngine: {
          active: Boolean(this.syncEngine?.isPeriodicSyncActive),
          status: this.syncEngine?.isPeriodicSyncActive ? 'running' : 'idle',
          totalAccounts: accountCount,
          idleMonitoredAccounts: idleStatus.idleAccounts || 0,
          pollingFallbackAccounts: idleStatus.pollingAccounts || 0,
          lastSyncAt: this.syncEngine?.lastSyncAt || null,
          lastSyncTimestamp: this.syncEngine?.lastSyncAt || null
        },
        notifications: {
          webPushEnabled: Boolean(this.notificationManager?.webPush),
          ntfyEnabled: Boolean(this.notificationManager?.ntfy?.isConfigured),
          webPush: {
            configured: Boolean(this.notificationManager?.webPush),
            activeSubscriptions: pushSubsCount
          },
          ntfy: {
            configured: Boolean(this.notificationManager?.ntfy?.isConfigured),
            topic: this.notificationManager?.ntfy?.topic || null
          },
          lastDispatchedTimestamp: this.notificationManager?.lastDispatchedAt || null
        }
      });
      return;
    }

    // --- TRIAGE RULES ENDPOINTS ---
    if (method === 'GET' && pathname === '/api/triage/rules') {
      const rules = this.store.getTriageRules();
      this._json(res, 200, { rules, count: rules.length });
      return;
    }

    if (method === 'POST' && pathname === '/api/triage/rules') {
      const body = await getBody();
      if (body === null) return;
      try {
        const id = this.store.upsertTriageRule(body);
        const rule = this.store.getTriageRule(id);
        this._json(res, 201, { success: true, id, rule });
      } catch (err) {
        this._json(res, 400, { error: err.message, code: 'VALIDATION_ERROR' });
      }
      return;
    }

    const deleteRuleMatch = pathname.match(/^\/api\/triage\/rules\/([^/]+)$/);
    if (method === 'DELETE' && deleteRuleMatch) {
      const ruleId = decodeURIComponent(deleteRuleMatch[1]);
      const deleted = this.store.deleteTriageRule(ruleId);
      this._json(res, deleted ? 200 : 404, { success: deleted });
      return;
    }

    // --- NOTIFICATIONS & WEB PUSH ENDPOINTS ---
    if (method === 'GET' && pathname === '/api/notifications/vapid-public-key') {
      const publicKey = this.notificationManager.webPush.getPublicKey();
      this._json(res, 200, { publicKey });
      return;
    }

    if (method === 'POST' && pathname === '/api/notifications/subscribe') {
      const body = await getBody();
      if (body === null) return;
      try {
        const id = this.store.upsertPushSubscription(body);
        this._json(res, 201, { success: true, id });
      } catch (err) {
        this._json(res, 400, { error: err.message, code: 'INVALID_SUBSCRIPTION' });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/notifications/unsubscribe') {
      const body = await getBody();
      if (body === null) return;
      const removed = body.endpoint ? this.store.deletePushSubscription(body.endpoint) : false;
      this._json(res, 200, { success: Boolean(removed) });
      return;
    }

    if (method === 'POST' && pathname === '/api/notifications/test') {
      const body = (await getBody()) || {};
      try {
        const result = await this.notificationManager.sendTestAlert(body);
        this._json(res, 200, { success: true, result });
      } catch (err) {
        this._json(res, 500, { error: err.message, code: 'DISPATCH_FAILED' });
      }
      return;
    }

    // --- MESSAGES & SEARCH ENDPOINTS ---
    if (method === 'GET' && pathname === '/api/mailbox/summary') {
      try {
        const summary = this.store.getMailboxSummary();
        summary.lastSyncAt = this.syncEngine?.lastSyncAt || null;
        this._json(res, 200, summary);
      } catch (err) {
        this._json(res, 500, { error: err.message });
      }
      return;
    }

    if (method === 'GET' && pathname === '/api/messages') {
      const q = url.searchParams.get('q');
      const category = url.searchParams.get('category');
      const accountId = url.searchParams.get('accountId');
      const folderId = url.searchParams.get('folderId');
      const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 1000);
      const offset = Number(url.searchParams.get('offset')) || 0;

      let isSeen;
      if (url.searchParams.has('isSeen')) {
        isSeen = url.searchParams.get('isSeen') === 'true';
      } else if (url.searchParams.get('unread') === 'true') {
        isSeen = false;
      }

      let isFlagged;
      if (url.searchParams.has('isFlagged')) {
        isFlagged = url.searchParams.get('isFlagged') === 'true';
      } else if (url.searchParams.get('starred') === 'true') {
        isFlagged = true;
      }

      const filterCategory = category && category !== 'ALL' ? category : undefined;

      if (q) {
        // Every filter runs in SQL, so pages are full and `total` is the real match count
        const { messages, total } = this.store.searchWithTotal(q, {
          accountId,
          folderId,
          limit,
          offset,
          category: filterCategory,
          isSeen,
          isFlagged
        });
        this._json(res, 200, {
          messages,
          count: messages.length,
          total,
          query: q,
          category: category || 'ALL',
          limit,
          offset
        });
        return;
      }

      const total = this.store.getMessageCount({
        accountId,
        folderId,
        category: filterCategory,
        isSeen,
        isFlagged
      });

      const messages = this.store.getMessages({
        accountId,
        folderId,
        category: filterCategory,
        isSeen,
        isFlagged,
        limit,
        offset
      });
      this._json(res, 200, {
        messages,
        count: messages.length,
        total,
        category: category || 'ALL',
        accountId: accountId || null,
        folderId: folderId || null,
        limit,
        offset
      });
      return;
    }

    // Send an email (new message or reply)
    if (method === 'POST' && pathname === '/api/messages/send') {
      const body = await getBody();
      if (body === null) return;
      if (!body.accountId) {
        this._json(res, 400, { error: 'Choose an account to send from', code: 'VALIDATION_ERROR' });
        return;
      }
      try {
        const result = await this.mailService.send(body);
        this._json(res, 200, { success: true, ...result });
      } catch (err) {
        const status = err.statusCode || (err.message?.includes('Account not found') ? 404 : 502);
        this._json(res, status, { error: err.message, code: err.code || (status === 502 ? 'SEND_FAILED' : 'VALIDATION_ERROR') });
      }
      return;
    }

    const singleMsgMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (method === 'GET' && singleMsgMatch) {
      const msg = this.store.findMessage(decodeURIComponent(singleMsgMatch[1]));
      if (!msg) {
        this._json(res, 404, { error: 'Message not found' });
        return;
      }
      this._json(res, 200, { message: msg });
      return;
    }

    // Delete: removed locally now, moved to Trash on the server in the background
    if (method === 'DELETE' && singleMsgMatch) {
      const messageId = decodeURIComponent(singleMsgMatch[1]);
      const msg = this.store.findMessage(messageId);
      if (!msg) {
        this._json(res, 404, { success: false, error: 'Message not found', messageId });
        return;
      }
      if (this.syncEngine?.deleteMessage) this.syncEngine.deleteMessage(msg);
      else this.store.deleteMessage(msg.id);
      this._json(res, 200, { success: true, messageId: msg.id });
      return;
    }

    // Full body (text, sanitized HTML, attachment list); cached after the first open
    const bodyMatch = pathname.match(/^\/api\/messages\/([^/]+)\/body$/);
    if (method === 'GET' && bodyMatch) {
      const msg = this.store.findMessage(decodeURIComponent(bodyMatch[1]));
      if (!msg) {
        this._json(res, 404, { error: 'Message not found' });
        return;
      }
      try {
        const body = await this.mailService.getBody(msg, { refresh: url.searchParams.get('refresh') === 'true' });
        this._json(res, 200, { messageId: msg.id, ...body });
      } catch (err) {
        this._json(res, err.statusCode || 502, { error: err.message, code: 'BODY_FETCH_FAILED' });
      }
      return;
    }

    const attachmentMatch = pathname.match(/^\/api\/messages\/([^/]+)\/attachments\/(\d+)$/);
    if (method === 'GET' && attachmentMatch) {
      const msg = this.store.findMessage(decodeURIComponent(attachmentMatch[1]));
      if (!msg) {
        this._json(res, 404, { error: 'Message not found' });
        return;
      }
      try {
        const att = await this.mailService.getAttachment(msg, Number(attachmentMatch[2]));
        if (!att) {
          this._json(res, 404, { error: 'Attachment not found' });
          return;
        }
        const safeName = att.filename.replace(/[\r\n"\\]/g, '_');
        res.writeHead(200, {
          // Always download; never render untrusted attachment content on our origin
          'Content-Type': 'application/octet-stream',
          'Content-Length': att.content.length,
          'Content-Disposition': `attachment; filename="${safeName.replace(/[^\x20-\x7e]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(att.filename)}`,
          'Cache-Control': 'private, no-store'
        });
        res.end(att.content);
      } catch (err) {
        this._json(res, err.statusCode || 502, { error: err.message, code: 'ATTACHMENT_FETCH_FAILED' });
      }
      return;
    }

    // Read / unread / star / unstar: local change now, pushed to the server in the background
    const stateMatch = pathname.match(/^\/api\/messages\/([^/]+)\/(read|unread|star|flag|unstar|unflag)$/);
    if (method === 'POST' && stateMatch) {
      const messageId = decodeURIComponent(stateMatch[1]);
      const action = stateMatch[2];
      const msg = this.store.findMessage(messageId);
      if (!msg) {
        this._json(res, 404, { success: false, error: 'Message not found', messageId });
        return;
      }
      const changes = {
        read: { seen: true },
        unread: { seen: false },
        star: { flagged: true },
        flag: { flagged: true },
        unstar: { flagged: false },
        unflag: { flagged: false }
      }[action];
      if (this.syncEngine?.setMessageState) {
        this.syncEngine.setMessageState(msg, changes);
      } else {
        if (changes.seen !== undefined) this.store.setMessageSeen(msg.id, changes.seen);
        if (changes.flagged !== undefined) this.store.setMessageFlag(msg.id, changes.flagged);
      }
      const payload = { success: true, messageId: msg.id };
      if (changes.seen !== undefined) payload.isSeen = changes.seen;
      if (changes.flagged !== undefined) payload.isFlagged = changes.flagged;
      this._json(res, 200, payload);
      return;
    }

    const accountSyncMatch = pathname.match(/^\/api\/accounts\/([^/]+)\/sync$/);
    if (method === 'POST' && accountSyncMatch) {
      const accountId = decodeURIComponent(accountSyncMatch[1]);
      if (this.syncEngine) {
        this.syncEngine.syncAccount(accountId, { throwOnError: false }).catch(() => {});
      }
      this._json(res, 200, { success: true, accountId, message: 'Account sync triggered' });
      return;
    }

    // --- STATIC ASSET SERVING ---
    // Prevent directory/path traversal outside PUBLIC_DIR
    const safePath = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
    let filePath = path.resolve(PUBLIC_DIR, '.' + path.sep + (safePath === path.sep || safePath === '.' ? 'index.html' : safePath));

    if (!filePath.startsWith(PUBLIC_DIR)) {
      this._json(res, 403, { error: 'Forbidden' });
      return;
    }

    try {
      const stat = await fs.stat(filePath);
      if (stat.isDirectory()) {
        filePath = path.join(filePath, 'index.html');
      }

      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      const content = await fs.readFile(filePath);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    } catch {
      // 404 fallback
      this._json(res, 404, { error: 'Not found' });
    }
  }

  /**
   * Generates a clean HTML page inside the OAuth popup that communicates with parent window and closes.
   * @private
   */
  _sendOAuthPopupResult(res, success, account, errorMessage = '') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    const payload = {
      type: 'MAILBOXER_OAUTH_RESULT',
      success,
      account,
      error: errorMessage
    };

    const safeJsonPayload = JSON.stringify(payload).replace(/</g, '\\u003c');
    const safeErrorDisplay = String(errorMessage || 'An error occurred during authentication.')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mailboxer Authentication</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f1115;
      color: #fff;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      text-align: center;
    }
    .card {
      background: #1a1d24;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 32px;
      max-width: 400px;
    }
    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #3b82f6;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .success { color: #10b981; font-weight: 600; font-size: 18px; }
    .error { color: #ef4444; font-weight: 600; font-size: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    ${success
      ? `<div class="success">Connected Successfully!</div><p style="color:#94a3b8;font-size:14px;margin-top:8px;">Closing popup and updating your accounts...</p>`
      : `<div class="error">Authentication Failed</div><p style="color:#94a3b8;font-size:14px;margin-top:8px;">${safeErrorDisplay}</p>`
    }
  </div>
  <script>
    const data = ${safeJsonPayload};
    try {
      localStorage.setItem('mailboxer_oauth_result', JSON.stringify({ ...data, timestamp: Date.now() }));
    } catch (e) {}

    if (window.opener) {
      window.opener.postMessage(data, window.location.origin);
      setTimeout(() => window.close(), 1200);
    } else {
      setTimeout(() => window.close(), 3000);
    }
  </script>
</body>
</html>`;

    res.end(html);
  }

  /**
   * Helper to write JSON responses
   * @private
   */
  _json(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
  }

  /**
   * Helper to parse request body (JSON or URL-encoded form data)
   * @private
   */
  async _parseRequestBody(req) {
    return new Promise((resolve, reject) => {
      let body = '';
      let tooLarge = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024 * 1024) {
          tooLarge = true;
          const err = new Error('Payload too large (maximum 1MB)');
          err.statusCode = 413;
          err.code = 'PAYLOAD_TOO_LARGE';
          reject(err);
        }
      });
      req.on('end', () => {
        if (tooLarge) return;
        const trimmed = body.trim();
        if (!trimmed) {
          resolve(null);
          return;
        }

        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/x-www-form-urlencoded')) {
          try {
            const params = new URLSearchParams(trimmed);
            resolve(Object.fromEntries(params.entries()));
          } catch (err) {
            const parseErr = new Error(`Invalid URL-encoded body: ${err.message}`);
            parseErr.statusCode = 400;
            parseErr.code = 'INVALID_FORM_DATA';
            reject(parseErr);
          }
          return;
        }

        try {
          resolve(JSON.parse(trimmed));
        } catch (err) {
          if (trimmed.includes('=') && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
            try {
              const params = new URLSearchParams(trimmed);
              resolve(Object.fromEntries(params.entries()));
              return;
            } catch {}
          }
          const parseErr = new Error(`Invalid JSON body: ${err.message}`);
          parseErr.statusCode = 400;
          parseErr.code = 'INVALID_JSON';
          reject(parseErr);
        }
      });
      req.on('error', reject);
    });
  }

  /**
   * Helper to parse request JSON body
   * @private
   */
  async _parseJsonBody(req) {
    return this._parseRequestBody(req);
  }
}
