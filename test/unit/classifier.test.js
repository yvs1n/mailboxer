/**
 * Error Taxonomy & Classifier Unit Test Suite (test/unit/classifier.test.js)
 *
 * Validates the 12 typed error codes, class inheritance, serialization,
 * provider-specific regex rules, system error classification, and secret masking.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
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
} from '../../src/errors/taxonomy.js';

import {
  classifyError,
  classifyProtocolResponse,
  classifySocketError,
  maskSensitiveData,
  getRemediationAdvice
} from '../../src/errors/classifier.js';

describe('Error Taxonomy & Classifier (src/errors/)', () => {
  describe('1. Error Codes & Taxonomy (src/errors/taxonomy.js)', () => {
    it('defines exactly 12 typed error codes in frozen ERROR_CODES dictionary', () => {
      assert.ok(Object.isFrozen(ERROR_CODES), 'ERROR_CODES must be frozen');
      const codes = Object.values(ERROR_CODES);
      assert.strictEqual(codes.length, 12, 'Must contain exactly 12 error codes');

      const expected = [
        'DNS_RESOLUTION_FAILED',
        'CONNECTION_TIMEOUT',
        'CONNECTION_REFUSED',
        'CONNECTION_DROPPED',
        'TLS_HANDSHAKE_FAILED',
        'AUTH_INVALID_CREDENTIALS',
        'AUTH_APP_PASSWORD_REQUIRED',
        'AUTH_TENANT_POLICY_BLOCKED',
        'AUTH_IMAP_DISABLED',
        'PROTOCOL_VIOLATION',
        'SERVER_TEMPORARILY_UNAVAILABLE',
        'MAILBOX_NOT_FOUND'
      ];
      assert.deepStrictEqual(codes.sort(), expected.sort());
    });

    it('MailboxerError inherits from standard Error and populates all required metadata', () => {
      const err = new MailboxerError(ERROR_CODES.CONNECTION_TIMEOUT, 'Timeout occurred', {
        provider: 'apple',
        remediation: 'Check firewall',
        host: 'imap.mail.me.com',
        port: 993
      });

      assert.ok(err instanceof Error);
      assert.ok(err instanceof MailboxerError);
      assert.strictEqual(err.code, 'CONNECTION_TIMEOUT');
      assert.strictEqual(err.provider, 'apple');
      assert.strictEqual(err.remediation, 'Check firewall');
      assert.strictEqual(err.details.host, 'imap.mail.me.com');
      assert.strictEqual(err.details.port, 993);
      assert.ok(typeof err.timestamp === 'string');
    });

    it('MailboxerError.prototype.toJSON returns structured serializable representation', () => {
      const err = new MailboxerError(ERROR_CODES.AUTH_INVALID_CREDENTIALS, 'Bad password', {
        provider: 'gmail',
        remediation: 'Check typos'
      });
      const json = err.toJSON();
      assert.strictEqual(json.code, 'AUTH_INVALID_CREDENTIALS');
      assert.strictEqual(json.provider, 'gmail');
      assert.strictEqual(json.remediation, 'Check typos');
      assert.strictEqual(json.message, 'Bad password');
    });

    it('all 12 specialized subclasses instantiate with correct code and category inheritance', () => {
      const dns = new DnsResolutionError('DNS failed');
      assert.ok(dns instanceof NetworkError);
      assert.strictEqual(dns.code, ERROR_CODES.DNS_RESOLUTION_FAILED);

      const timeout = new ConnectionTimeoutError('Timed out');
      assert.ok(timeout instanceof NetworkError);
      assert.strictEqual(timeout.code, ERROR_CODES.CONNECTION_TIMEOUT);

      const refused = new ConnectionRefusedError('Refused');
      assert.ok(refused instanceof NetworkError);
      assert.strictEqual(refused.code, ERROR_CODES.CONNECTION_REFUSED);

      const dropped = new ConnectionDroppedError('Dropped');
      assert.ok(dropped instanceof NetworkError);
      assert.strictEqual(dropped.code, ERROR_CODES.CONNECTION_DROPPED);

      const tls = new TlsHandshakeError('TLS alert');
      assert.ok(tls instanceof TlsError);
      assert.strictEqual(tls.code, ERROR_CODES.TLS_HANDSHAKE_FAILED);

      const badAuth = new AuthInvalidCredentialsError('Bad creds');
      assert.ok(badAuth instanceof AuthenticationError);
      assert.strictEqual(badAuth.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);

      const appPass = new AuthAppPasswordRequiredError('App password needed');
      assert.ok(appPass instanceof AuthenticationError);
      assert.strictEqual(appPass.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);

      const tenant = new AuthTenantPolicyBlockedError('Tenant block');
      assert.ok(tenant instanceof AuthenticationError);
      assert.strictEqual(tenant.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);

      const imapDis = new AuthImapDisabledError('IMAP disabled');
      assert.ok(imapDis instanceof AuthenticationError);
      assert.strictEqual(imapDis.code, ERROR_CODES.AUTH_IMAP_DISABLED);

      const proto = new ProtocolViolationError('Bad protocol');
      assert.ok(proto instanceof ProtocolError);
      assert.strictEqual(proto.code, ERROR_CODES.PROTOCOL_VIOLATION);

      const unavail = new ServerTemporarilyUnavailableError('Server down');
      assert.ok(unavail instanceof ProtocolError);
      assert.strictEqual(unavail.code, ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE);

      const notFound = new MailboxNotFoundError('No inbox');
      assert.ok(notFound instanceof ProtocolError);
      assert.strictEqual(notFound.code, ERROR_CODES.MAILBOX_NOT_FOUND);
    });

    it('createErrorByCode factory instantiates corresponding subclass for every code', () => {
      for (const [codeKey, codeVal] of Object.entries(ERROR_CODES)) {
        const err = createErrorByCode(codeVal, `Test ${codeKey}`);
        assert.strictEqual(err.code, codeVal);
        assert.ok(err instanceof MailboxerError);
      }
    });

    it('isMailboxerError identifies MailboxerError instances and rejects regular Errors', () => {
      assert.strictEqual(isMailboxerError(new MailboxerError('TEST', 'test')), true);
      assert.strictEqual(isMailboxerError(new ConnectionTimeoutError('timeout')), true);
      assert.strictEqual(isMailboxerError(new Error('regular error')), false);
      assert.strictEqual(isMailboxerError(null), false);
      assert.strictEqual(isMailboxerError({}), false);
    });
  });

  describe('2. Provider Classification Rules (src/errors/classifier.js)', () => {
    it('classifies Google App Password requirement with actionable remediation', () => {
      const line = 'NO [ALERT] Application-specific password required: https://support.google.com/mail/answer/78754';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
      assert.strictEqual(err.provider, 'gmail');
      assert.ok(err.remediation.includes('myaccount.google.com/apppasswords'));
    });

    it('classifies Google web login required as AUTH_APP_PASSWORD_REQUIRED', () => {
      const line = 'NO [ALERT] Please log in via your web browser: https://support.google.com/mail/answer/78754 (Failure)';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });
      assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
    });

    it('classifies Google invalid credentials', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });
      assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
    });

    it('classifies Apple Mail auth failure as AUTH_APP_PASSWORD_REQUIRED when provider is apple', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Authentication Failed';
      const err = classifyProtocolResponse(line, { provider: 'apple' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
      assert.strictEqual(err.provider, 'apple');
      assert.ok(err.remediation.includes('appleid.apple.com'));
    });

    it('classifies Apple Mail auth failure as AUTH_INVALID_CREDENTIALS when provider is generic', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Authentication Failed';
      const err = classifyProtocolResponse(line, { provider: 'custom' });
      assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
    });

    it('classifies Microsoft Outlook basic authentication disabled as AUTH_TENANT_POLICY_BLOCKED', () => {
      const line = 'NO Basic authentication is disabled.';
      const err = classifyProtocolResponse(line, { provider: 'outlook' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
      assert.strictEqual(err.provider, 'outlook');
      assert.ok(err.remediation.includes('OAuth2'));
    });

    it('classifies Microsoft Outlook pre-auth LOGINDISABLED capability as AUTH_TENANT_POLICY_BLOCKED', () => {
      const line = 'NO Command not allowed';
      const err = classifyProtocolResponse(line, {
        provider: 'outlook',
        capabilities: ['IMAP4rev1', 'LOGINDISABLED']
      });
      assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
    });

    it('classifies IMAP disabled by administrator', () => {
      const line = 'NO [ALERT] IMAP access is disabled for your domain.';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });
      assert.strictEqual(err.code, ERROR_CODES.AUTH_IMAP_DISABLED);
    });

    it('classifies non-existent mailbox as MAILBOX_NOT_FOUND', () => {
      const line = 'NO [NONEXISTENT] Mailbox does not exist: ARCHIVE_2020';
      const err = classifyProtocolResponse(line);
      assert.strictEqual(err.code, ERROR_CODES.MAILBOX_NOT_FOUND);
    });

    it('classifies server temporarily unavailable as SERVER_TEMPORARILY_UNAVAILABLE', () => {
      const line = '* BYE [UNAVAILABLE] System error';
      const err = classifyProtocolResponse(line);
      assert.strictEqual(err.code, ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE);
    });

    it('classifies HTTP web response on IMAP port as PROTOCOL_VIOLATION', () => {
      const line = 'HTTP/1.1 400 Bad Request';
      const err = classifyProtocolResponse(line);
      assert.strictEqual(err.code, ERROR_CODES.PROTOCOL_VIOLATION);
    });

    it('classifies untagged * BYE disconnect lines as CONNECTION_DROPPED (Defect 10)', () => {
      const line = '* BYE Connection broken by server administrator';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.CONNECTION_DROPPED);
      assert.ok(err instanceof ConnectionDroppedError);
      assert.strictEqual(err.provider, 'gmail');

      // But * BYE [UNAVAILABLE] still classifies as SERVER_TEMPORARILY_UNAVAILABLE
      const unavailLine = '* BYE [UNAVAILABLE] Temporary maintenance';
      const unavailErr = classifyProtocolResponse(unavailLine, { provider: 'gmail' });
      assert.strictEqual(unavailErr.code, ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE);
    });

    it('classifies Google help URL variant with /accounts/ without English alert as AUTH_APP_PASSWORD_REQUIRED (Defect 11)', () => {
      const line = 'NO [ALERT] Check https://support.google.com/mail/accounts/answer/78754';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
      assert.strictEqual(err.provider, 'gmail');
      assert.ok(err.remediation.includes('myaccount.google.com/apppasswords'));
    });

    it('classifyProtocolResponse safely coerces non-string inputs (Buffer, number, object, null) without TypeError (Defect 12)', () => {
      const bufferInput = Buffer.from('NO [ALERT] Service unavailable');
      const errBuffer = classifyProtocolResponse(bufferInput);
      assert.ok(isMailboxerError(errBuffer));

      const numInput = 503;
      const errNum = classifyProtocolResponse(numInput);
      assert.ok(isMailboxerError(errNum));

      const nullInput = null;
      const errNull = classifyProtocolResponse(nullInput);
      assert.ok(isMailboxerError(errNull));

      const objInput = { code: 'FAIL' };
      const errObj = classifyProtocolResponse(objInput);
      assert.ok(isMailboxerError(errObj));
    });
  });

  describe('3. Socket & System Error Classification', () => {
    it('classifies ENOTFOUND as DNS_RESOLUTION_FAILED', () => {
      const socketErr = Object.assign(new Error('getaddrinfo ENOTFOUND imap.invalid'), { code: 'ENOTFOUND' });
      const err = classifySocketError(socketErr, { host: 'imap.invalid', port: 993 });

      assert.strictEqual(err.code, ERROR_CODES.DNS_RESOLUTION_FAILED);
      assert.ok(err.cause === socketErr);
    });

    it('classifies ETIMEDOUT and AbortError as CONNECTION_TIMEOUT', () => {
      const timedOut = Object.assign(new Error('connect ETIMEDOUT'), { code: 'ETIMEDOUT' });
      assert.strictEqual(classifySocketError(timedOut).code, ERROR_CODES.CONNECTION_TIMEOUT);

      const abort = Object.assign(new Error('Operation aborted'), { name: 'AbortError' });
      assert.strictEqual(classifySocketError(abort).code, ERROR_CODES.CONNECTION_TIMEOUT);
    });

    it('classifies ECONNREFUSED as CONNECTION_REFUSED', () => {
      const refused = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:993'), { code: 'ECONNREFUSED' });
      assert.strictEqual(classifySocketError(refused).code, ERROR_CODES.CONNECTION_REFUSED);
    });

    it('classifies ECONNRESET and socket hang up as CONNECTION_DROPPED', () => {
      const reset = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
      assert.strictEqual(classifySocketError(reset).code, ERROR_CODES.CONNECTION_DROPPED);

      const hangUp = new Error('socket hang up');
      assert.strictEqual(classifySocketError(hangUp).code, ERROR_CODES.CONNECTION_DROPPED);
    });

    it('classifies certificate expiration and validation errors as TLS_HANDSHAKE_FAILED', () => {
      const certErr = Object.assign(new Error('certificate has expired'), { code: 'CERT_HAS_EXPIRED' });
      assert.strictEqual(classifySocketError(certErr).code, ERROR_CODES.TLS_HANDSHAKE_FAILED);

      const altName = Object.assign(new Error('Host name mismatch'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
      assert.strictEqual(classifySocketError(altName).code, ERROR_CODES.TLS_HANDSHAKE_FAILED);
    });

    it('universal classifyError dispatches properly across Error instances and strings', () => {
      const socketErr = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
      assert.strictEqual(classifyError(socketErr).code, ERROR_CODES.CONNECTION_REFUSED);

      const protoLine = 'NO [NONEXISTENT] Mailbox does not exist';
      assert.strictEqual(classifyError(protoLine).code, ERROR_CODES.MAILBOX_NOT_FOUND);

      const existingMailboxerErr = new DnsResolutionError('DNS fail');
      assert.strictEqual(classifyError(existingMailboxerErr), existingMailboxerErr);
    });

    it('classifySocketError sanitizes credentials embedded in error.message (Defect 8)', () => {
      const secret = 'SUPER_SECRET_APP_TOKEN_999!';
      const rawError = new Error(`Connection reset while executing A001 LOGIN "user@icloud.com" "${secret}"`);
      rawError.code = 'ECONNRESET';

      const classified = classifySocketError(rawError, { provider: 'apple' });

      assert.strictEqual(classified.code, ERROR_CODES.CONNECTION_DROPPED);
      assert.ok(!classified.message.includes(secret), 'Message must not contain cleartext secret');
      assert.ok(classified.message.includes('[REDACTED]'), 'Message must contain [REDACTED]');
      assert.ok(!JSON.stringify(classified.toJSON()).includes(secret), 'toJSON must not contain cleartext secret');
    });
  });

  describe('4. Secret Masking & Redaction', () => {
    it('redacts plaintext passwords in LOGIN commands', () => {
      const unmasked = 'A002 LOGIN "user@gmail.com" "super-secret-password-123"';
      const masked = maskSensitiveData(unmasked);

      assert.ok(!masked.includes('super-secret-password-123'), 'Plaintext password must be redacted');
      assert.ok(masked.includes('[REDACTED]'), 'Must replace with [REDACTED]');
      assert.ok(masked.includes('user@gmail.com'), 'Username should remain visible');
    });

    it('maskSensitiveData correctly masks passwords containing escaped quotes and complex usernames (Defect 9)', () => {
      // Escaped quote in password
      const escapedPassCmd = 'A001 LOGIN "user@mail.com" "p\\\"ass"';
      const maskedPass = maskSensitiveData(escapedPassCmd);
      assert.ok(!maskedPass.includes('ass"'), 'Escaped quote must not expose remaining password chars');
      assert.ok(maskedPass.includes('[REDACTED]'));

      // Escaped quote in username with spaces
      const escapedUserCmd = 'A001 LOGIN "user \\" name" "supersecret123"';
      const maskedUser = maskSensitiveData(escapedUserCmd);
      assert.ok(!maskedUser.includes('supersecret123'), 'Escaped quote in username must not leak password');
      assert.ok(maskedUser.includes('[REDACTED]'));
    });

    it('does not corrupt non-login protocol strings', () => {
      const line = '* STATUS INBOX (MESSAGES 42 UNSEEN 3)';
      assert.strictEqual(maskSensitiveData(line), line);
    });

    it('getRemediationAdvice returns fallback guidance for unknown errors', () => {
      const advice = getRemediationAdvice('NON_EXISTENT_CODE');
      assert.ok(advice.length > 0);
    });
  });
});
