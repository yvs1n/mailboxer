# Project: Mailboxer Multi-Account Engine & Triage Hub (Steps 1, 2, 3 & Cloud Deployment)

## Architecture
Mailboxer is a unified personal email client and anti-noise triage hub integrating Apple Mail (iCloud), Google Mail (Gmail), and Microsoft Outlook (University / Office 365).
The core engine is built on a zero-dependency, native ES Module architecture on Node.js 22 (`"type": "module"`) leveraging:
- Native networking & TLS (`node:tls`, `node:net`, `node:stream`, `node:crypto`)
- Native SQLite caching store (`node:sqlite` DatabaseSync) with WAL mode and sub-millisecond search indexing
- Native Web Push (RFC 8291 aes128gcm payload encryption via native ECDH/HKDF, RFC 8292 VAPID P-256 JWT) & ntfy.sh alert conduits
- Real-time IMAP IDLE with adaptive polling fallback
- Native testing (`node:test`, `node:assert/strict`) with 100% offline hermetic mocks
- Botkeep Cloud Docker deployment with non-root user and persistent `/data` volume.

```
+---------------------------------------------------------------------------------------------------------+
|                                          MAILBOXER ARCHITECTURE                                         |
+---------------------------------------------------------------------------------------------------------+
|  1. Guided Onboarding & Vault   |  2. SQLite & Sync Engine      |  3. Smart Triage & Notification Hub   |
|  - Apple / Google / MS 30s links|  - Native node:sqlite store   |  - Rule classifier: VIP / Update /    |
|  - 4x4 input auto-formatter     |  - accounts, folders, msgs    |    Noise (RFC headers, keywords)      |
|  - Live pre-flight IMAP check   |  - Incremental UID sync       |  - IMAP IDLE + adaptive polling       |
|  - AES-256-GCM encrypted vault  |  - Full-text search (<20ms)   |  - Web Push (VAPID) + ntfy.sh alerts  |
+---------------------------------------------------------------------------------------------------------+
|  4. Web Server & Cloud Platform |  5. Dual-Track Hermetic Test Suite & Adversarial Hardening            |
|  - HTTP REST endpoints & static |  - 100% offline unit & integration suites (npm test)                  |
|  - /health endpoint             |  - MockSocketTransport & MockImapServer                               |
|  - Dockerfile (Node 22, /data)  |  - Adversarial stress testing & Forensic Integrity Audit             |
+---------------------------------------------------------------------------------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Apple Mail Preset | Accurate target: IMAP `imap.mail.me.com:993` (SSL/TLS), SMTP `smtp.mail.me.com:587` (STARTTLS) | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F2 | Gmail Preset | Accurate target: IMAP `imap.gmail.com:993` (SSL/TLS), SMTP `smtp.gmail.com:465` / `587` | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F3 | Outlook Preset | Accurate target: IMAP `outlook.office365.com:993` (SSL/TLS), SMTP `smtp.office365.com:587` (STARTTLS) | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F4 | Strict Schema Validation | Schema validator enforcing non-empty IDs, RFC 5322 emails, ports 1-65535, TLS options, normalized app-passwords | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F5 | Environment Loader & Masking | Native Node 22 environment loader without hardcoded credentials, placeholder detection, defensive credential masking | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F6 | Documented `.env.example` | Template with setup instructions for Apple, Gmail, Outlook app-passwords | M1 (Step 1) | ORIGINAL_REQUEST §R1 |
| F7 | Pluggable Socket Transport | Transport abstraction supporting live `TlsSocketTransport` and zero-network `MockSocketTransport` | M2 (Step 1) | ORIGINAL_REQUEST §R2 |
| F8 | TLS Handshake & Cipher Audit | Secure TLS connection, cipher extraction (`socket.getCipher()`), protocol version (`socket.getProtocol()`), peer cert audit | M2 (Step 1) | ORIGINAL_REQUEST §R2 |
| F9 | IMAP State Machine & Mailbox Status | Full lifecycle: Greeting, CAPABILITY query, authentication, INBOX STATUS, clean LOGOUT | M2 (Step 1) | ORIGINAL_REQUEST §R2 |
| F10 | Diagnostic Error Taxonomy | 12-code error taxonomy distinguishing invalid credentials, missing app-specific passwords, timeouts, socket drops | M2 (Step 1) | ORIGINAL_REQUEST §R2 |
| F11 | 3-Provider 30s Direct Links | Dedicated 1-click links to Apple (`appleid.apple.com`), Google (`myaccount.google.com/apppasswords`), and Outlook (`account.live.com`) generator portals | M1 | ORIGINAL_REQUEST §R1 (Step 2/3) |
| F12 | 4x4 Input Auto-Formatting | Real-time 16-character 4x4 auto-formatting (`xxxx-xxxx-xxxx-xxxx`) with smart backspace and paste handling | M1 | ORIGINAL_REQUEST §R1 (Step 2/3) |
| F13 | Pre-Flight IMAP Verification | Live connection check (`ImapClient.verify()`) executing TLS handshake, LOGIN, and STATUS before vault persistence | M1 | ORIGINAL_REQUEST §R1 (Step 2/3) |
| F14 | Permanent AES-256-GCM Vault | Machine-keyed AES-256-GCM authenticated vault with atomic writes and zero secret leaks in public endpoints | M1 | ORIGINAL_REQUEST §R1 (Step 2/3) |
| F15 | Guided Onboarding UI Cards | Responsive cards for Apple Mail, Google Mail, Outlook 365, replacing OAuth console friction with 30s onboarding | M1 | ORIGINAL_REQUEST §R1 (Step 2/3) |
| F16 | Persistent SQLite Store | Database schema with `accounts`, `folders`, `messages`, and search index using native `node:sqlite` DatabaseSync | M2 | ORIGINAL_REQUEST §R2 (Step 2/3) |
| F17 | IMAP Sync Protocol Extensions | IMAP commands `LIST`, `SELECT`, `UID SEARCH`, `UID FETCH` with `BODY.PEEK` (preventing remote \Seen modification), `UID STORE` | M2 | ORIGINAL_REQUEST §R2 (Step 2/3) |
| F18 | Incremental Sync Engine | UIDVALIDITY tracking, delta UID sync (`UID <max+1>:*`), flag reconciliation, deleted UID pruning | M2 | ORIGINAL_REQUEST §R2 (Step 2/3) |
| F19 | Sub-20ms Search Index | Cross-account instant search over sender, subject, and body snippet executing in <20ms (benchmark <5ms) | M2 | ORIGINAL_REQUEST §R2 (Step 2/3) |
| F20 | Anti-Noise Triage Rules Engine | Classification into VIP/Urgent, Updates/Coursework, Noise based on sender, RFC headers (List-Unsubscribe, Precedence), keywords, and user rules | M3 | ORIGINAL_REQUEST §R3 (Step 2/3) |
| F21 | Real-Time IMAP IDLE Listener | RFC 2177 IMAP IDLE state machine with keepalive cycling, socket drop recovery, and adaptive polling fallback | M3 | ORIGINAL_REQUEST §R3 (Step 2/3) |
| F22 | Web Push Notification Conduit | RFC 8291 `aes128gcm` payload encryption + RFC 8292 VAPID P-256 JWT generation using native Node crypto, service worker alerts | M3 | ORIGINAL_REQUEST §R3 (Step 2/3) |
| F23 | ntfy.sh Alert Conduit | Instant high-priority alerts with configurable topic, click URLs, and interactive action buttons | M3 | ORIGINAL_REQUEST §R3 (Step 2/3) |
| F24 | Botkeep Cloud Dockerfile | Production Dockerfile running Node 22 slim with non-root `node` user and persistent `/data` volume | M4 | ORIGINAL_REQUEST §R4 (Step 2/3) |
| F25 | Dynamic PORT & Health Endpoint | Server binds `0.0.0.0:${PORT:-3000}` and provides `/health` returning 200 OK with system, storage, account, and sync metrics | M4 | ORIGINAL_REQUEST §R4 (Step 2/3) |
| F26 | E2E Dual-Track Test Suite | 100% offline hermetic unit, integration, and E2E test suite passing cleanly with exit code 0 via `npm test` | M5 | ORIGINAL_REQUEST §R3/Acceptance |
| F27 | Forensic Integrity Audit | Independent runtime tracing and static analysis verifying authentic logic with zero dummy facades or hardcoded outputs | M5 | ORIGINAL_REQUEST §Integrity |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Simplified 3-Provider Guided App Password Onboarding & Vault | F11, F12, F13, F14, F15: Apple, Google, Outlook 30s generator links, 4x4 formatter, pre-flight verify, vault endpoints & UI cards | none | DONE |
| M2 | Persistent SQLite Storage & Incremental IMAP Sync Engine | F16, F17, F18, F19: SQLite schema (`accounts`, `folders`, `messages`), IMAP protocol extensions (LIST, SELECT, UID SEARCH/FETCH), incremental sync, <20ms search | M1 | DONE |
| M3 | Smart Anti-Noise Triage & Real-Time Notification Engine | F20, F21, F22, F23: Triage classifier (VIP, Updates, Noise), IMAP IDLE + adaptive polling, Web Push (VAPID) + ntfy conduits | M2 | DONE |
| M4 | Botkeep Cloud Packaging & Volume Configuration | F24, F25: Production Dockerfile (Node 22, non-root), dynamic PORT binding, `/health` endpoint, `/data` volume configuration | M1, M2, M3 | DONE |
| M5 | E2E Dual-Track Testing & Final Hardening | F26, F27: Complete automated test suite passing cleanly with 100% exit code 0 via `npm test`, Tier 5 adversarial stress testing, Forensic Integrity Audit | M1, M2, M3, M4 | IN_PROGRESS |

## Interface Contracts

### 1. Onboarding API & Account Manager
```javascript
// POST /api/accounts/apple
// POST /api/accounts/gmail
// POST /api/accounts/outlook
// POST /api/accounts/custom
export interface AccountAddRequest {
  email: string;
  appPassword?: string;
  password?: string;
  label?: string;
}

export interface PublicAccountSummary {
  id: string;
  provider: 'apple' | 'gmail' | 'outlook' | 'custom';
  label: string;
  email: string;
  authType: 'app_password' | 'password';
  connected: boolean;
  lastVerifiedAt: string;
  inboxStatus?: {
    totalMessages: number;
    unseen: number;
    recent: number;
  };
}
```

### 2. SQLite Database & Storage Engine
```javascript
export interface StorageEngine {
  db: DatabaseSync;
  initSchema(): void;
  upsertAccount(account: AccountRecord): void;
  upsertFolder(folder: FolderRecord): void;
  upsertMessages(messages: MessageRecord[]): void;
  getFolder(accountId: string, folderName: string): FolderRecord | null;
  getMessages(options: { accountId?: string; folderId?: string; limit?: number; offset?: number; category?: string }): MessageRecord[];
  search(query: string, options?: { accountId?: string; limit?: number }): MessageRecord[];
  updateMessageFlags(folderId: string, uid: number, flags: string[]): void;
  pruneDeletedUids(folderId: string, remoteUids: number[]): number;
}
```

### 3. Sync Engine Contract
```javascript
export interface SyncEngine {
  syncAccount(accountId: string): Promise<SyncResult>;
  syncFolder(accountId: string, folderName: string): Promise<FolderSyncResult>;
  startPeriodicSync(intervalMs: number): void;
  stopPeriodicSync(): void;
}
```

### 4. Triage & Notification Engine Contract
```javascript
export type TriageCategory = 'VIP' | 'UPDATE' | 'NOISE' | 'NORMAL';

export interface TriageResult {
  category: TriageCategory;
  score: number;
  reason: string;
  matchedRule?: string;
  shouldNotify: boolean;
}

export interface NotificationConduit {
  send(notification: {
    title: string;
    body: string;
    category: TriageCategory;
    data?: Record<string, unknown>;
  }): Promise<boolean>;
}
```

### 5. Botkeep Cloud Health Contract
```javascript
// GET /health -> 200 OK
export interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  timestamp: string;
  uptimeSeconds: number;
  environment: string;
  storage: {
    writable: boolean;
    databasePath: string;
    vaultPath: string;
  };
  accounts: {
    total: number;
    connected: number;
  };
  syncEngine: {
    active: boolean;
    lastSyncAt: string | null;
  };
  notifications: {
    webPushEnabled: boolean;
    ntfyEnabled: boolean;
  };
}
```

## Code Layout
```
c:\Users\yassi\Documents\coding\HTML, CSS And JS\Mailboxer\
├── Dockerfile                        # Production Node 22 non-root container for Botkeep Cloud
├── .dockerignore                     # Docker ignore rules (node_modules, data, .git)
├── .env.example                      # Documented credentials template & app password instructions
├── .gitignore                        # Git ignore (.env, data, *.vault.json, node_modules)
├── package.json                      # Native ESM ("type": "module"), test and server scripts
├── README.md                         # Project documentation and usage guide
├── bin/
│   ├── server.js                     # Main application entry point (HTTP, IMAP Sync, Triage)
│   └── verify.js                     # Diagnostic CLI runner
├── public/                           # Web Dashboard assets
│   ├── index.html                    # 3-provider guided onboarding cards & triage dashboard
│   ├── app.js                        # 4x4 input formatting, form submissions, triage feeds
│   ├── style.css                     # Responsive styling & provider branding
│   └── sw.js                         # Service worker for Web Push notifications
├── src/
│   ├── index.js                      # Main library exports
│   ├── auth/
│   │   ├── vault.js                  # AES-256-GCM encrypted credential vault
│   │   └── account-manager.js        # Account lifecycle, pre-flight verification, provider helpers
│   ├── config/
│   │   ├── presets.js                # Apple, Gmail, Outlook provider presets
│   │   ├── schema.js                 # Strict schema validator & secret normalizers
│   │   └── env.js                    # Environment credential loader
│   ├── connection/
│   │   ├── transport.js              # Socket transport (TlsSocketTransport, MockSocketTransport)
│   │   ├── imap-client.js            # IMAP protocol state machine (LOGIN, STATUS, IDLE, FETCH)
│   │   └── idle-manager.js           # IMAP IDLE connection listener & keepalive cycling
│   ├── storage/
│   │   ├── schema.js                 # SQLite schema DDL (accounts, folders, messages, search index)
│   │   └── sqlite-store.js           # Database operations with node:sqlite DatabaseSync
│   ├── sync/
│   │   └── sync-engine.js            # Incremental IMAP synchronization engine
│   ├── triage/
│   │   ├── classifier.js             # Anti-noise rule classifier (VIP, Updates, Noise)
│   │   └── rules.js                  # Default heuristics & customizable user rules
│   ├── notifications/
│   │   ├── manager.js                # Notification dispatcher orchestrating conduits
│   │   ├── web-push.js               # Zero-dependency RFC 8291/8292 Web Push sender
│   │   └── ntfy.js                   # ntfy.sh webhook conduit with action buttons
│   ├── server/
│   │   └── web-server.js             # Native HTTP server, REST API, /health endpoint
│   └── errors/
│       ├── taxonomy.js               # Error codes and typed error classes
│       └── classifier.js             # Wire error classifier and remediation advice
└── test/
    ├── helpers/
    │   ├── mock-socket.js            # In-memory duplex socket mock
    │   └── mock-imap-server.js       # In-memory IMAP server mock with IDLE and FETCH
    ├── unit/
    │   ├── vault.test.js             # Vault AES-256-GCM unit tests
    │   ├── account-manager.test.js   # Account manager unit tests
    │   ├── sqlite-store.test.js      # SQLite schema, indexing & query unit tests
    │   ├── sync-engine.test.js       # Incremental sync unit tests
    │   ├── classifier.test.js        # Triage classifier unit tests
    │   ├── notifications.test.js     # Web Push & ntfy conduit unit tests
    │   └── idle.test.js              # IMAP IDLE state machine unit tests
    ├── integration/
    │   ├── web-server.test.js        # API endpoints, onboarding & health check integration tests
    │   └── full-sync.test.js         # End-to-end sync, cache & search integration tests
    └── e2e/
        └── full-triage.test.js       # Complete scenario: onboarding -> sync -> triage -> alert
```
