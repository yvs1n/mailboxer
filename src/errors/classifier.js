/**
 * Error Classifier & Remediation Engine
 *
 * Classifies wire responses, TLS alerts, and socket errors into Mailboxer's
 * 12 typed error codes, generating actionable provider-specific remediation guidance.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module errors/classifier
 */

import {
  ERROR_CODES,
  createErrorByCode,
  isMailboxerError,
  MailboxerError
} from './taxonomy.js';

/**
 * Sanitizes sensitive credentials (passwords, auth tokens) from wire lines and error messages.
 *
 * @param {string} text
 * @returns {string}
 */
export function maskSensitiveData(text) {
  if (typeof text !== 'string') return '';
  // Redact LOGIN / AUTHENTICATE command arguments: LOGIN "<user>" "<pass>"
  // Handles RFC 3501 escaped characters (\" and \\) inside quoted strings
  return text.replace(
    /((?:LOGIN|AUTHENTICATE)\s+(?:"(?:[^"\\]|\\.)*"|\S+)\s+)(?:"(?:[^"\\]|\\.)*"|\S+)/gi,
    '$1"[REDACTED]"'
  );
}

/**
 * Actionable remediation guidance catalog per error code and provider.
 */
export const REMEDIATION_CATALOG = Object.freeze({
  [ERROR_CODES.DNS_RESOLUTION_FAILED]: {
    default: 'Check your internet connection and verify that the mail server hostname is spelled correctly in your configuration.'
  },
  [ERROR_CODES.CONNECTION_TIMEOUT]: {
    default: 'Connection attempt timed out. Verify that the mail server host and port are reachable and that local firewalls, proxies, or VPNs are not blocking outgoing traffic.'
  },
  [ERROR_CODES.CONNECTION_REFUSED]: {
    default: 'Connection was refused by the target server. Verify that the host and port are correct and that the mail server is currently accepting connections.'
  },
  [ERROR_CODES.CONNECTION_DROPPED]: {
    default: 'The connection was abruptly terminated by the mail server or network. Check your network stability, or verify if the server closed the session due to rate limiting or inactivity.'
  },
  [ERROR_CODES.TLS_HANDSHAKE_FAILED]: {
    default: 'TLS/SSL handshake negotiation failed. Ensure the server certificate is valid, not expired, matches the hostname, and that the server supports TLS 1.2 or TLS 1.3.'
  },
  [ERROR_CODES.AUTH_INVALID_CREDENTIALS]: {
    default: 'Authentication failed. Check your username and password for typos. If two-factor authentication is active, use an app-specific password instead of your master password.',
    apple: 'Authentication failed. Verify your Apple ID email address. Ensure you are using a 16-character App-Specific Password.',
    gmail: 'Google rejected your credentials. Check your email and password for typos, or verify that your Google account is active.',
    outlook: 'Authentication failed. Check your Microsoft email and password for typos.'
  },
  [ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED]: {
    default: 'An App-Specific Password is required by your email provider. Generate one in your account security portal and update your configuration.',
    apple: 'Apple ID requires a 16-character App-Specific Password for third-party email clients. Sign in at https://appleid.apple.com, navigate to Sign-In and Security > App-Specific Passwords, generate a password, and update APPLE_APP_PASSWORD in .env.',
    gmail: 'Google requires an App Password when 2-Step Verification is active. Generate a 16-character App Password at https://myaccount.google.com/apppasswords and update GMAIL_APP_PASSWORD in your .env file.',
    outlook: 'Microsoft requires an App Password for accounts using multi-factor authentication. Generate an App Password in your Microsoft account security dashboard.'
  },
  [ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED]: {
    default: 'Basic password authentication has been disabled by your organization\'s tenant security policy. Modern authentication (OAuth2) or an administrator policy exemption is required.',
    outlook: 'Microsoft Office 365 / University tenant has disabled basic password authentication. Modern authentication (OAuth2) or an IT administrator exemption policy is required.'
  },
  [ERROR_CODES.AUTH_IMAP_DISABLED]: {
    default: 'IMAP protocol access is disabled for this account. Enable IMAP in your email account web settings.',
    gmail: 'IMAP access is disabled for this account. Enable IMAP in Gmail Settings > Forwarding and POP/IMAP, or contact your Google Workspace administrator.',
    outlook: 'IMAP access is disabled for this user by organizational policy. Contact your organization or university IT helpdesk to enable IMAP access.'
  },
  [ERROR_CODES.PROTOCOL_VIOLATION]: {
    default: 'The server returned an invalid or unrecognized protocol response violating IMAP specifications. Verify the server hostname and port.'
  },
  [ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE]: {
    default: 'The mail server is temporarily unavailable or rate-limiting connections. Wait a few moments before retrying.'
  },
  [ERROR_CODES.MAILBOX_NOT_FOUND]: {
    default: 'The requested mailbox folder was not found on the server. Verify that the mailbox name is correct (e.g. "INBOX").'
  }
});

/**
 * Normalizes context argument which may be a provider string or an object.
 *
 * @private
 * @param {string|Object} [contextOrProvider]
 * @param {Object} [extraContext={}]
 * @returns {Object} Normalized context object
 */
function normalizeContext(contextOrProvider, extraContext = {}) {
  if (typeof contextOrProvider === 'string') {
    return { provider: contextOrProvider, ...extraContext };
  }
  return { ...(contextOrProvider || {}), ...extraContext };
}

/**
 * Returns customized remediation advice for an error code and provider.
 *
 * @param {string} code
 * @param {Object|string} [context={}]
 * @returns {string}
 */
export function getRemediationAdvice(code, context = {}) {
  const norm = normalizeContext(context);
  const provider = (norm.provider || 'default').toLowerCase();
  const entry = REMEDIATION_CATALOG[code];
  if (!entry) return 'Check mail server configuration and account credentials.';
  return entry[provider] || entry.default || 'Check mail server configuration.';
}

/**
 * Classifies an IMAP protocol wire response line into a typed MailboxerError.
 *
 * @param {string} rawResponse
 * @param {Object|string} [contextOrProvider={}]
 * @param {Object} [extraContext={}]
 * @returns {MailboxerError}
 */
export function classifyProtocolResponse(rawResponse, contextOrProvider = {}, extraContext = {}) {
  const context = normalizeContext(contextOrProvider, extraContext);
  const rawStr = Buffer.isBuffer(rawResponse)
    ? rawResponse.toString('utf8')
    : String(rawResponse ?? '');
  const line = rawStr.trim();
  const provider = (context.provider || 'unknown').toLowerCase();
  const sanitizedLine = maskSensitiveData(line);
  const capabilities = Array.isArray(context.capabilities) ? context.capabilities : [];
  const loginDisabled = context.loginDisabled || capabilities.includes('LOGINDISABLED');

  // 1. Outlook / Tenant Basic Authentication Disabled
  if (
    /Basic authentication is disabled/i.test(line) ||
    (loginDisabled && /NO|BAD/i.test(line))
  ) {
    const code = ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED;
    return createErrorByCode(code, 'Basic password authentication is disabled by tenant security policy.', {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 2. Google App Password Required / Web Login Required
  // Matches all Google help URL variants including /mail/answer/78754 and /accounts/answer/78754
  if (
    /Application-specific password required/i.test(line) ||
    /support\.google\.com\/(?:mail\/)?(?:accounts\/)?answer\/(?:78754|185833)/i.test(line) ||
    /\[ALERT\]\s+Web login required/i.test(line) ||
    /Please log in via your web browser/i.test(line)
  ) {
    const code = ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED;
    return createErrorByCode(code, 'Google requires a 16-character App Password when 2-Step Verification is active.', {
      provider: 'gmail',
      remediation: getRemediationAdvice(code, { provider: 'gmail' }),
      details: { rawResponse: sanitizedLine, provider: 'gmail', ...context.details }
    });
  }

  // 3. Apple Mail App Password Required
  // Apple returns generic "[AUTHENTICATIONFAILED] Authentication Failed" when regular password is used
  if (provider === 'apple' && /\[AUTHENTICATIONFAILED\]/i.test(line)) {
    const code = ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED;
    return createErrorByCode(code, 'Apple Mail (iCloud) requires a 16-character App-Specific Password.', {
      provider: 'apple',
      remediation: getRemediationAdvice(code, { provider: 'apple' }),
      details: { rawResponse: sanitizedLine, provider: 'apple', ...context.details }
    });
  }

  // 4. IMAP Protocol Disabled
  if (/IMAP access is disabled|IMAP is not enabled|not permitted to use IMAP/i.test(line)) {
    const code = ERROR_CODES.AUTH_IMAP_DISABLED;
    return createErrorByCode(code, 'IMAP access is disabled for this mailbox.', {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 5. General Invalid Credentials
  if (
    /\[AUTHENTICATIONFAILED\]/i.test(line) ||
    /Invalid credentials/i.test(line) ||
    /Username and Password not accepted/i.test(line) ||
    /Invalid username or password/i.test(line) ||
    /535\s+5\.7/i.test(line)
  ) {
    const code = ERROR_CODES.AUTH_INVALID_CREDENTIALS;
    return createErrorByCode(code, 'Authentication rejected: invalid username or password.', {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 6. Mailbox Not Found
  if (
    /\[NONEXISTENT\]/i.test(line) ||
    /Mailbox doesn'?t exist/i.test(line) ||
    /Mailbox not found/i.test(line) ||
    /No such mailbox/i.test(line)
  ) {
    const code = ERROR_CODES.MAILBOX_NOT_FOUND;
    return createErrorByCode(code, `Mailbox folder not found on server: ${sanitizedLine}`, {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 7. Server Temporarily Unavailable / Throttled
  if (
    /UNAVAILABLE/i.test(line) ||
    /Too many concurrent connections/i.test(line) ||
    /System error/i.test(line) ||
    /temporarily unavailable/i.test(line) ||
    /\b(?:421|451)\b/i.test(line)
  ) {
    const code = ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE;
    return createErrorByCode(code, 'Mail server is temporarily unavailable or rate-limiting connections.', {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 8. Server Disconnect / Termination (* BYE)
  if (/^\*\s+BYE\b/i.test(line)) {
    const code = ERROR_CODES.CONNECTION_DROPPED;
    return createErrorByCode(code, `Mail server closed connection: ${sanitizedLine}`, {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // 9. Protocol Violation (Invalid greeting, unexpected HTTP header, or malformed syntax)
  if (
    /^HTTP\/\d/i.test(line) ||
    /^\s*<html/i.test(line) ||
    /^\*\s+BAD/i.test(line) ||
    /BAD\s+(?:Invalid|Unrecognized|Syntax|Command)/i.test(line)
  ) {
    const code = ERROR_CODES.PROTOCOL_VIOLATION;
    return createErrorByCode(code, `IMAP protocol violation: unexpected server response "${sanitizedLine}"`, {
      provider,
      remediation: getRemediationAdvice(code, { provider }),
      details: { rawResponse: sanitizedLine, provider, ...context.details }
    });
  }

  // Fallback Protocol Error
  const fallbackCode = ERROR_CODES.PROTOCOL_VIOLATION;
  return createErrorByCode(fallbackCode, `Mail server returned unexpected response: ${sanitizedLine}`, {
    provider,
    remediation: getRemediationAdvice(fallbackCode, { provider }),
    details: { rawResponse: sanitizedLine, provider, ...context.details }
  });
}

/**
 * Alias for classifyProtocolResponse matching alternative naming.
 */
export const classifyProtocolError = classifyProtocolResponse;

/**
 * Classifies a low-level Node.js socket, system, or TLS error.
 *
 * @param {Error} err
 * @param {Object|string} [contextOrProvider={}]
 * @param {Object} [extraContext={}]
 * @returns {MailboxerError}
 */
export function classifySocketError(err, contextOrProvider = {}, extraContext = {}) {
  const context = normalizeContext(contextOrProvider, extraContext);
  const provider = (context.provider || 'unknown').toLowerCase();
  const codeStr = String(err?.code || '').toUpperCase();
  const nameStr = String(err?.name || '');
  const rawMsgStr = String(err?.message || '');
  const msgStr = maskSensitiveData(rawMsgStr);

  // 1. DNS Resolution Failures
  if (
    codeStr === 'ENOTFOUND' ||
    codeStr === 'EAI_AGAIN' ||
    codeStr === 'EAI_FAIL' ||
    codeStr === 'EAI_NONAME' ||
    /getaddrinfo/i.test(rawMsgStr)
  ) {
    const code = ERROR_CODES.DNS_RESOLUTION_FAILED;
    return createErrorByCode(code, `DNS resolution failed for mail server (${msgStr}).`, {
      provider,
      cause: err,
      remediation: getRemediationAdvice(code, { provider }),
      details: { originalCode: codeStr, host: context.host, port: context.port, ...context.details }
    });
  }

  // 2. Connection Timeout
  if (
    nameStr === 'AbortError' ||
    codeStr === 'ABORT_ERR' ||
    codeStr === 'ETIMEDOUT' ||
    codeStr === 'ERR_SOCKET_TIMEOUT' ||
    codeStr === 'CONNECTION_TIMEOUT' ||
    /timed?\s*out/i.test(rawMsgStr)
  ) {
    const code = ERROR_CODES.CONNECTION_TIMEOUT;
    return createErrorByCode(code, `Connection to mail server timed out (${msgStr || 'operation timed out'}).`, {
      provider,
      cause: err,
      remediation: getRemediationAdvice(code, { provider }),
      details: { originalCode: codeStr, host: context.host, port: context.port, ...context.details }
    });
  }

  // 3. Connection Refused
  if (codeStr === 'ECONNREFUSED' || /connection refused/i.test(rawMsgStr)) {
    const code = ERROR_CODES.CONNECTION_REFUSED;
    return createErrorByCode(code, `Connection refused by mail server (${msgStr}).`, {
      provider,
      cause: err,
      remediation: getRemediationAdvice(code, { provider }),
      details: { originalCode: codeStr, host: context.host, port: context.port, ...context.details }
    });
  }

  // 4. Connection Dropped / Reset
  if (
    codeStr === 'ECONNRESET' ||
    codeStr === 'EPIPE' ||
    codeStr === 'CONNECTION_DROPPED' ||
    codeStr === 'ERR_STREAM_PREMATURE_CLOSE' ||
    /socket hang up|premature close|connection reset|Connection closed prematurely/i.test(rawMsgStr)
  ) {
    const code = ERROR_CODES.CONNECTION_DROPPED;
    return createErrorByCode(code, `Connection was abruptly closed by the mail server (${msgStr}).`, {
      provider,
      cause: err,
      remediation: getRemediationAdvice(code, { provider }),
      details: { originalCode: codeStr, host: context.host, port: context.port, ...context.details }
    });
  }

  // 5. TLS Handshake & Certificate Verification Errors
  if (
    /CERT_|UNABLE_TO_VERIFY|DEPTH_ZERO_SELF_SIGNED|ERR_TLS_|ERR_SSL_|HANDSHAKE/i.test(codeStr) ||
    /certificate|tls handshake|ssl alert|altname/i.test(rawMsgStr)
  ) {
    const code = ERROR_CODES.TLS_HANDSHAKE_FAILED;
    return createErrorByCode(code, `TLS handshake failed: ${msgStr}`, {
      provider,
      cause: err,
      remediation: getRemediationAdvice(code, { provider }),
      details: { originalCode: codeStr, host: context.host, port: context.port, ...context.details }
    });
  }

  // Fallback to Connection Dropped or Protocol Violation
  const fallbackCode = ERROR_CODES.CONNECTION_DROPPED;
  return createErrorByCode(fallbackCode, `Network error: ${msgStr}`, {
    provider,
    cause: err,
    remediation: getRemediationAdvice(fallbackCode, { provider }),
    details: { originalCode: codeStr, ...context.details }
  });
}

/**
 * Universal error classifier accepting an Error instance or string response.
 *
 * @param {unknown} errorOrResponse
 * @param {Object|string} [contextOrProvider={}]
 * @param {Object} [extraContext={}]
 * @returns {MailboxerError}
 */
export function classifyError(errorOrResponse, contextOrProvider = {}, extraContext = {}) {
  const context = normalizeContext(contextOrProvider, extraContext);

  if (isMailboxerError(errorOrResponse)) {
    if (context.provider && errorOrResponse.provider === 'unknown') {
      errorOrResponse.provider = context.provider;
    }
    return errorOrResponse;
  }

  if (typeof errorOrResponse === 'string') {
    return classifyProtocolResponse(errorOrResponse, context);
  }

  if (errorOrResponse instanceof Error) {
    return classifySocketError(errorOrResponse, context);
  }

  return createErrorByCode(
    ERROR_CODES.PROTOCOL_VIOLATION,
    `Unrecognized error format: ${maskSensitiveData(String(errorOrResponse))}`,
    context
  );
}
