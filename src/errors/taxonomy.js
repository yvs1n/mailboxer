/**
 * Error Taxonomy & Typed Error Classes
 *
 * Defines the 12 typed error codes and polymorphic error class hierarchy
 * for Mailboxer connection lifecycle and diagnostic engine.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module errors/taxonomy
 */

export const ERROR_CODES = Object.freeze({
  // Network & DNS
  DNS_RESOLUTION_FAILED: 'DNS_RESOLUTION_FAILED',
  CONNECTION_TIMEOUT: 'CONNECTION_TIMEOUT',
  CONNECTION_REFUSED: 'CONNECTION_REFUSED',
  CONNECTION_DROPPED: 'CONNECTION_DROPPED',

  // TLS & Cryptography
  TLS_HANDSHAKE_FAILED: 'TLS_HANDSHAKE_FAILED',

  // Authentication & Authorization
  AUTH_INVALID_CREDENTIALS: 'AUTH_INVALID_CREDENTIALS',
  AUTH_APP_PASSWORD_REQUIRED: 'AUTH_APP_PASSWORD_REQUIRED',
  AUTH_TENANT_POLICY_BLOCKED: 'AUTH_TENANT_POLICY_BLOCKED',
  AUTH_IMAP_DISABLED: 'AUTH_IMAP_DISABLED',

  // Protocol & Mailbox State
  PROTOCOL_VIOLATION: 'PROTOCOL_VIOLATION',
  SERVER_TEMPORARILY_UNAVAILABLE: 'SERVER_TEMPORARILY_UNAVAILABLE',
  MAILBOX_NOT_FOUND: 'MAILBOX_NOT_FOUND'
});

/**
 * Base error class for all Mailboxer errors.
 */
export class MailboxerError extends Error {
  /**
   * @param {string} code - One of the 12 ERROR_CODES
   * @param {string} message - Human-readable error description
   * @param {Object} [options={}] - Contextual details
   * @param {string} [options.provider='unknown'] - Provider identifier
   * @param {string} [options.remediation=''] - Actionable remediation guidance
   * @param {Object} [options.details={}] - Additional metadata
   * @param {Error} [options.cause] - Original underlying error
   */
  constructor(code, message, options = {}) {
    super(message, { cause: options.cause || options.originalError });
    this.name = this.constructor.name;
    this.code = code;
    this.provider = options.provider || 'unknown';
    this.remediation = options.remediation || '';
    this.details = options.details ? { ...options.details } : {};

    if (options.rawResponse) {
      this.details.rawResponse = options.rawResponse;
    }
    if (options.host) {
      this.details.host = options.host;
    }
    if (options.port) {
      this.details.port = options.port;
    }
    if (options.command) {
      this.details.command = options.command;
    }

    this.timestamp = options.timestamp || new Date().toISOString();
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      provider: this.provider,
      remediation: this.remediation,
      details: this.details,
      timestamp: this.timestamp
    };
  }
}

// Category Bases
export class NetworkError extends MailboxerError {}
export class TlsError extends MailboxerError {}
export class AuthenticationError extends MailboxerError {}
export class ProtocolError extends MailboxerError {}

// 12 Typed Subclasses
export class DnsResolutionError extends NetworkError {
  constructor(message, options = {}) {
    super(ERROR_CODES.DNS_RESOLUTION_FAILED, message, options);
  }
}

export class ConnectionTimeoutError extends NetworkError {
  constructor(message, options = {}) {
    super(ERROR_CODES.CONNECTION_TIMEOUT, message, options);
  }
}

export class ConnectionRefusedError extends NetworkError {
  constructor(message, options = {}) {
    super(ERROR_CODES.CONNECTION_REFUSED, message, options);
  }
}

export class ConnectionDroppedError extends NetworkError {
  constructor(message, options = {}) {
    super(ERROR_CODES.CONNECTION_DROPPED, message, options);
  }
}

export class TlsHandshakeError extends TlsError {
  constructor(message, options = {}) {
    super(ERROR_CODES.TLS_HANDSHAKE_FAILED, message, options);
  }
}

export class AuthInvalidCredentialsError extends AuthenticationError {
  constructor(message, options = {}) {
    super(ERROR_CODES.AUTH_INVALID_CREDENTIALS, message, options);
  }
}

export class AuthAppPasswordRequiredError extends AuthenticationError {
  constructor(message, options = {}) {
    super(ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED, message, options);
  }
}

export class AuthTenantPolicyBlockedError extends AuthenticationError {
  constructor(message, options = {}) {
    super(ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED, message, options);
  }
}

export class AuthImapDisabledError extends AuthenticationError {
  constructor(message, options = {}) {
    super(ERROR_CODES.AUTH_IMAP_DISABLED, message, options);
  }
}

export class ProtocolViolationError extends ProtocolError {
  constructor(message, options = {}) {
    super(ERROR_CODES.PROTOCOL_VIOLATION, message, options);
  }
}

export class ServerTemporarilyUnavailableError extends ProtocolError {
  constructor(message, options = {}) {
    super(ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE, message, options);
  }
}

export class MailboxNotFoundError extends ProtocolError {
  constructor(message, options = {}) {
    super(ERROR_CODES.MAILBOX_NOT_FOUND, message, options);
  }
}

/**
 * Mapping table from ERROR_CODES to concrete Class constructors.
 */
export const ERROR_CONSTRUCTORS = Object.freeze({
  [ERROR_CODES.DNS_RESOLUTION_FAILED]: DnsResolutionError,
  [ERROR_CODES.CONNECTION_TIMEOUT]: ConnectionTimeoutError,
  [ERROR_CODES.CONNECTION_REFUSED]: ConnectionRefusedError,
  [ERROR_CODES.CONNECTION_DROPPED]: ConnectionDroppedError,
  [ERROR_CODES.TLS_HANDSHAKE_FAILED]: TlsHandshakeError,
  [ERROR_CODES.AUTH_INVALID_CREDENTIALS]: AuthInvalidCredentialsError,
  [ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED]: AuthAppPasswordRequiredError,
  [ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED]: AuthTenantPolicyBlockedError,
  [ERROR_CODES.AUTH_IMAP_DISABLED]: AuthImapDisabledError,
  [ERROR_CODES.PROTOCOL_VIOLATION]: ProtocolViolationError,
  [ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE]: ServerTemporarilyUnavailableError,
  [ERROR_CODES.MAILBOX_NOT_FOUND]: MailboxNotFoundError
});

/**
 * Factory creating the corresponding MailboxerError subclass from a code.
 *
 * @param {string} code
 * @param {string} message
 * @param {Object} [options={}]
 * @returns {MailboxerError}
 */
export function createErrorByCode(code, message, options = {}) {
  const Constructor = ERROR_CONSTRUCTORS[code] || MailboxerError;
  if (Constructor === MailboxerError) {
    return new MailboxerError(code, message, options);
  }
  return new Constructor(message, options);
}

/**
 * Type predicate checking if an object is an instance of MailboxerError.
 *
 * @param {unknown} err
 * @returns {boolean}
 */
export function isMailboxerError(err) {
  return err instanceof MailboxerError;
}
