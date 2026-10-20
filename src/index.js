/**
 * Mailboxer Core Library
 *
 * Multi-account email triage and verification engine unifying
 * Apple Mail (iCloud), Google Mail (Gmail), and Microsoft Outlook / Office 365.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module mailboxer
 */

// Configuration & Presets
export {
  PROVIDER_PRESETS,
  SUPPORTED_PROVIDERS,
  getPreset,
  isSupportedProvider,
  inferProviderFromEmail,
  deepFreeze
} from './config/presets.js';

// Schema & Resolution
export {
  validateAccountConfig,
  safeValidateAccountConfig,
  resolveAccountConfig,
  normalizeSecret,
  normalizeAppPassword,
  isValidEmail,
  isValidPort,
  isValidHostname,
  validateServerConfig,
  collectAccountConfigErrors,
  ValidationError,
  ConfigurationError
} from './config/schema.js';

// Environment & Masking
export {
  loadEnvironmentAccounts,
  loadConfigFromEnv,
  loadEnv,
  parseEnvContent,
  detectPlaceholders,
  isPlaceholder,
  isAccountConfigured,
  maskSecret,
  maskEmail,
  TEMPLATE_PLACEHOLDERS,
  PROVIDER_ENV_DEFINITIONS
} from './config/env.js';

// Connection Transports
export {
  SocketTransport,
  TlsSocketTransport,
  MockSocketTransport,
  extractTlsDetails,
  resolveServername,
  TRANSPORT_STATES,
  DEFAULT_TLS_OPTIONS
} from './connection/transport.js';

// IMAP Protocol Client
export {
  ImapClient,
  IMAP_STATES,
  escapeImapString,
  parseStatusResponse,
  parseCapabilities,
  parseListResponse,
  parseSelectResponse,
  parseSearchResponse,
  parseFetchResponses,
  decodeMimeHeader,
  extractEmail
} from './connection/imap-client.js';

// Errors & Taxonomy
export {
  ERROR_CODES,
  MailboxerError,
  NetworkError,
  TlsError,
  AuthenticationError,
  ProtocolError,
  DnsResolutionError,
  ConnectionTimeoutError,
  ConnectionRefusedError,
  ConnectionDroppedError,
  TlsHandshakeError,
  AuthInvalidCredentialsError,
  AuthAppPasswordRequiredError,
  AuthTenantPolicyBlockedError,
  AuthImapDisabledError,
  ProtocolViolationError,
  ServerTemporarilyUnavailableError,
  MailboxNotFoundError,
  createErrorByCode,
  isMailboxerError
} from './errors/taxonomy.js';

// Classifier & Remediation
export {
  classifyError,
  classifyProtocolResponse,
  classifyProtocolError,
  classifySocketError,
  getRemediationAdvice,
  maskSensitiveData,
  REMEDIATION_CATALOG
} from './errors/classifier.js';

// Encrypted Credential Vault & Permanent Login
export {
  CredentialVault,
  defaultVault
} from './auth/vault.js';

// OAuth 2.0 Engine & Auto-Refresh
export {
  OAuthManager,
  defaultOAuthManager,
  OAUTH_CONFIGS
} from './auth/oauth.js';

// Account Management & Onboarding
export {
  AccountManager,
  defaultAccountManager
} from './auth/account-manager.js';

// HTTP Web Server & Onboarding Gateway
export {
  WebServer
} from './server/web-server.js';

// SQLite Storage Engine & Schema
export {
  SCHEMA_VERSION,
  initSchema,
  tokenize,
  CREATE_TABLES_SQL,
  CREATE_INDEXES_SQL
} from './storage/schema.js';

export {
  SqliteStore,
  MailboxDatabase
} from './storage/sqlite-store.js';

// Incremental IMAP Sync Engine
export {
  SyncEngine
} from './sync/sync-engine.js';

// Real-Time IMAP IDLE Manager
export {
  IdleManager,
  IDLE_CONSTANTS
} from './connection/idle-manager.js';

// Anti-Noise Smart Triage & Rules
export {
  Classifier,
  defaultClassifier
} from './triage/classifier.js';

export {
  TRIAGE_CATEGORIES,
  TRIAGE_ACTIONS,
  PROMOTIONAL_KEYWORDS_REGEX,
  URGENT_KEYWORDS_REGEX,
  ACADEMIC_TITLES_REGEX,
  COURSEWORK_KEYWORDS_REGEX,
  LMS_DOMAINS,
  BULK_MAILER_HEADERS,
  matchWildcard,
  getHeaderValue,
  evaluateCondition,
  evaluateUserRule
} from './triage/rules.js';

// Notifications Conduits & Web Push
export {
  WebPushConduit,
  generateVapidKeys,
  getOrCreateVapidKeys,
  createVapidJwt,
  encryptWebPushPayload,
  decryptWebPushPayload
} from './notifications/web-push.js';

export {
  NtfyConduit
} from './notifications/ntfy.js';

export {
  NotificationManager
} from './notifications/manager.js';


