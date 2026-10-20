/**
 * Adversarial Challenge Suite: Error Taxonomy & Classifier Engine
 *
 * Comprehensive stress-testing and empirical verification for:
 * 1. Regex Adversarial Strings & ReDoS Resilience (100k chars, catastrophic backtracking, unicode, buffers)
 * 2. Obscure Provider Error Variants (Google, Apple, Microsoft, RFC 3501 borderline messages)
 * 3. Credential Redaction & Secret Leak Audit (LOGIN, AUTHENTICATE, socket error leaks, DiagnosticResult)
 * 4. Error Subclass Polymorphism (12 subclasses, category inheritance, toJSON, prototype chains)
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
  ERROR_CONSTRUCTORS,
  createErrorByCode,
  isMailboxerError
} from '../../src/errors/taxonomy.js';

import {
  classifyError,
  classifyProtocolResponse,
  classifySocketError,
  maskSensitiveData,
  getRemediationAdvice,
  REMEDIATION_CATALOG
} from '../../src/errors/classifier.js';

describe('Adversarial Challenge: Error Taxonomy & Classifier Engine', () => {

  // ==========================================================================
  // VECTOR 1: Regex Adversarial Strings & ReDoS Resilience
  // ==========================================================================
  describe('Vector 1: Regex Adversarial Strings & ReDoS Resilience', () => {

    it('processes 100,000-character error strings in under 50ms without catastrophic backtracking', () => {
      const longA = 'A'.repeat(100000);
      const startA = performance.now();
      const resA = classifyProtocolResponse(longA);
      const elapsedA = performance.now() - startA;

      assert.ok(elapsedA < 50, `100k "A" took ${elapsedA}ms (expected < 50ms)`);
      assert.strictEqual(resA.code, ERROR_CODES.PROTOCOL_VIOLATION);

      const repeatingPatterns = 'NO [ALERT] ' + 'bad '.repeat(20000) + 'invalid credentials';
      const startPattern = performance.now();
      const resPattern = classifyProtocolResponse(repeatingPatterns);
      const elapsedPattern = performance.now() - startPattern;

      assert.ok(elapsedPattern < 50, `Pattern took ${elapsedPattern}ms (expected < 50ms)`);
      assert.strictEqual(resPattern.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
    });

    it('stress-tests maskSensitiveData against pathological ReDoS string combinations', () => {
      // Unclosed quote with alternating spaces
      const unclosedQuotes = 'LOGIN "' + ' a'.repeat(30000);
      const startUnclosed = performance.now();
      const resUnclosed = maskSensitiveData(unclosedQuotes);
      const elapsedUnclosed = performance.now() - startUnclosed;

      assert.ok(elapsedUnclosed < 50, `Unclosed quote took ${elapsedUnclosed}ms (expected < 50ms)`);
      assert.ok(typeof resUnclosed === 'string');

      // Massive whitespace sequences
      const massiveSpaces = 'LOGIN ' + ' '.repeat(50000) + '"user" ' + ' '.repeat(50000) + '"secret"';
      const startSpaces = performance.now();
      const resSpaces = maskSensitiveData(massiveSpaces);
      const elapsedSpaces = performance.now() - startSpaces;

      assert.ok(elapsedSpaces < 50, `Massive spaces took ${elapsedSpaces}ms (expected < 50ms)`);
      assert.ok(resSpaces.includes('[REDACTED]'));
      assert.ok(!resSpaces.includes('secret'));

      // 100k character unquoted argument
      const longArg = 'LOGIN user ' + 'X'.repeat(100000);
      const startLong = performance.now();
      const resLong = maskSensitiveData(longArg);
      const elapsedLong = performance.now() - startLong;

      assert.ok(elapsedLong < 50, `Long arg took ${elapsedLong}ms (expected < 50ms)`);
      assert.ok(resLong.includes('[REDACTED]'));
    });

    it('handles unicode, multi-byte UTF-8, RTL overrides, and null characters gracefully', () => {
      const unicodeString = 'NO [AUTHENTICATIONFAILED] \u202E\u200D🔥 用户验证失败 密码不正确 \0 null byte';
      const err = classifyProtocolResponse(unicodeString, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
      assert.ok(err.details.rawResponse.includes('🔥'));
      assert.ok(err.details.rawResponse.includes('\0'));
    });

    it('survives non-string and binary buffer inputs passed to classifyError', () => {
      const buf = Buffer.from('NO [AUTHENTICATIONFAILED] Invalid credentials');
      const err = classifyError(buf);
      assert.ok(isMailboxerError(err));
      assert.strictEqual(err.code, ERROR_CODES.PROTOCOL_VIOLATION);

      assert.ok(isMailboxerError(classifyError(null)));
      assert.ok(isMailboxerError(classifyError(undefined)));
      assert.ok(isMailboxerError(classifyError(404)));
      assert.ok(isMailboxerError(classifyError({ error: 'failed' })));
      assert.ok(isMailboxerError(classifyError(Symbol('test'))));
    });

    it('audits classifyProtocolResponse behavior when passed non-string types directly', () => {
      // Testing if classifyProtocolResponse is resilient or throws on non-string
      const nonStringInputs = [null, undefined, 500, Buffer.from('NO [ALERT]'), { msg: 'bad' }, true];

      for (const input of nonStringInputs) {
        try {
          const result = classifyProtocolResponse(input);
          assert.ok(isMailboxerError(result), `Should return MailboxerError for ${typeof input}`);
        } catch (thrown) {
          // Record finding: classifyProtocolResponse throws TypeError on non-string inputs
          assert.fail(`classifyProtocolResponse threw ${thrown.name}: ${thrown.message} on input type ${typeof input}`);
        }
      }
    });
  });

  // ==========================================================================
  // VECTOR 2: Obscure Provider Error Variants
  // ==========================================================================
  describe('Vector 2: Obscure Provider Error Variants', () => {

    it('classifies: NO [ALERT] Please log in via your web browser: https://support.google.com/mail/accounts/answer/78754', () => {
      const line = 'NO [ALERT] Please log in via your web browser: https://support.google.com/mail/accounts/answer/78754';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
      assert.strictEqual(err.provider, 'gmail');
      assert.ok(err.remediation.includes('myaccount.google.com/apppasswords'));
    });

    it('classifies: NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
      assert.strictEqual(err.provider, 'gmail');
    });

    it('classifies: NO [AUTHENTICATIONFAILED] Authentication failed for user@icloud.com (Apple vs Generic)', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Authentication failed for user@icloud.com';

      // With provider = 'apple'
      const errApple = classifyProtocolResponse(line, { provider: 'apple' });
      assert.strictEqual(errApple.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
      assert.strictEqual(errApple.provider, 'apple');
      assert.ok(errApple.remediation.includes('appleid.apple.com'));

      // Case insensitivity check for provider name
      const errAppleUpper = classifyProtocolResponse(line, { provider: 'APPLE' });
      assert.strictEqual(errAppleUpper.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);

      // With generic provider (e.g. 'custom' or 'unknown')
      const errGeneric = classifyProtocolResponse(line, { provider: 'custom' });
      assert.strictEqual(errGeneric.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
    });

    it('classifies: NO [AUTHENTICATIONFAILED] Basic authentication is disabled for this tenant.', () => {
      const line = 'NO [AUTHENTICATIONFAILED] Basic authentication is disabled for this tenant.';
      const err = classifyProtocolResponse(line, { provider: 'outlook' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
      assert.strictEqual(err.provider, 'outlook');
      assert.ok(err.remediation.includes('OAuth2'));
    });

    it('classifies: * BYE Connection broken by server administrator', () => {
      const line = '* BYE Connection broken by server administrator';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      // An untagged BYE indicating server disconnection should classify as CONNECTION_DROPPED
      // or SERVER_TEMPORARILY_UNAVAILABLE, NOT PROTOCOL_VIOLATION.
      assert.strictEqual(
        err.code,
        ERROR_CODES.CONNECTION_DROPPED,
        `Expected CONNECTION_DROPPED for server termination BYE, got ${err.code}`
      );
    });

    it('classifies: * NO [UNAVAILABLE] Service temporarily down', () => {
      const line = '* NO [UNAVAILABLE] Service temporarily down';
      const err = classifyProtocolResponse(line);

      assert.strictEqual(err.code, ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE);
    });

    it('classifies: A0001 NO [NONEXISTENT] Unknown mailbox', () => {
      const line = 'A0001 NO [NONEXISTENT] Unknown mailbox';
      const err = classifyProtocolResponse(line);

      assert.strictEqual(err.code, ERROR_CODES.MAILBOX_NOT_FOUND);
    });

    it('tests Google obscure URL variant without "Please log in": NO [ALERT] https://support.google.com/mail/accounts/answer/78754', () => {
      const line = 'NO [ALERT] Check https://support.google.com/mail/accounts/answer/78754';
      const err = classifyProtocolResponse(line, { provider: 'gmail' });

      // Google help URL variant with /accounts/ must trigger AUTH_APP_PASSWORD_REQUIRED
      assert.strictEqual(
        err.code,
        ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED,
        `Expected AUTH_APP_PASSWORD_REQUIRED for Google accounts help URL, got ${err.code}`
      );
    });

    it('tests Microsoft Exchange login failure with LOGINDISABLED capability', () => {
      const line = 'NO LOGIN failed.';
      const err = classifyProtocolResponse(line, {
        provider: 'outlook',
        capabilities: ['IMAP4rev1', 'LOGINDISABLED']
      });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
    });

    it('tests Microsoft IMAP disabled response variant', () => {
      const line = 'NO [AUTHENTICATIONFAILED] User is not permitted to use IMAP';
      const err = classifyProtocolResponse(line, { provider: 'outlook' });

      assert.strictEqual(err.code, ERROR_CODES.AUTH_IMAP_DISABLED);
    });
  });

  // ==========================================================================
  // VECTOR 3: Credential Redaction & Secret Leak Audit
  // ==========================================================================
  describe('Vector 3: Credential Redaction & Secret Leak Audit', () => {

    it('masks passwords in all IMAP LOGIN command syntaxes', () => {
      const pass = 'Sup3r$ecr3t!P@ss';

      // 1. Quoted user and pass
      assert.strictEqual(
        maskSensitiveData(`A001 LOGIN "user@mail.com" "${pass}"`),
        'A001 LOGIN "user@mail.com" "[REDACTED]"'
      );

      // 2. Unquoted user and pass
      assert.strictEqual(
        maskSensitiveData(`A001 LOGIN user@mail.com ${pass}`),
        'A001 LOGIN user@mail.com "[REDACTED]"'
      );

      // 3. Password containing whitespace inside quotes
      assert.strictEqual(
        maskSensitiveData(`A001 LOGIN "user@mail.com" "word1 word2 word3"`),
        'A001 LOGIN "user@mail.com" "[REDACTED]"'
      );

      // 4. Empty password
      assert.strictEqual(
        maskSensitiveData('A001 LOGIN "user@mail.com" ""'),
        'A001 LOGIN "user@mail.com" "[REDACTED]"'
      );

      // 5. AUTHENTICATE PLAIN
      assert.strictEqual(
        maskSensitiveData('A001 AUTHENTICATE PLAIN AGZvb2Jhcg=='),
        'A001 AUTHENTICATE PLAIN "[REDACTED]"'
      );

      // 6. AUTHENTICATE XOAUTH2
      assert.strictEqual(
        maskSensitiveData('A001 AUTHENTICATE XOAUTH2 dXNlcj11c2Vy...'),
        'A001 AUTHENTICATE XOAUTH2 "[REDACTED]"'
      );
    });

    it('audits maskSensitiveData on non-string inputs', () => {
      assert.strictEqual(maskSensitiveData(null), '');
      assert.strictEqual(maskSensitiveData(undefined), '');
      assert.strictEqual(maskSensitiveData(12345), '');
      assert.strictEqual(maskSensitiveData({}), '');
    });

    it('audits maskSensitiveData with escaped quotes and complex usernames', () => {
      // Escaped quotes in password
      const escapedPass = 'A001 LOGIN "user@mail.com" "p\\\"ass"';
      const maskedPass = maskSensitiveData(escapedPass);
      // In "p\"ass", [^"]* stops at the first quote right after backslash:
      // "p\" gets redacted, leaving ass" exposed!
      assert.ok(
        !maskedPass.includes('ass"'),
        `maskSensitiveData leaked partial password with escaped quote: "${maskedPass}"`
      );

      // Escaped quotes in username with spaces
      const escapedUser = 'A001 LOGIN "user \\" name" "supersecret123"';
      const maskedUser = maskSensitiveData(escapedUser);
      assert.ok(
        !maskedUser.includes('supersecret123'),
        `maskSensitiveData leaked secret when username contains escaped quotes: "${maskedUser}"`
      );
    });

    it('verifies classifySocketError does not leak credentials present in error.message', () => {
      const rawSecret = 'SUPER_SENSITIVE_APP_KEY_999!';
      const err = new Error(`Connection reset while sending A001 LOGIN "user@me.com" "${rawSecret}"`);
      err.code = 'ECONNRESET';

      const classified = classifySocketError(err, { provider: 'apple' });

      assert.ok(
        !classified.message.includes(rawSecret),
        `classifySocketError leaked raw password in message: "${classified.message}"`
      );
      assert.ok(
        !JSON.stringify(classified.toJSON()).includes(rawSecret),
        `classifySocketError leaked raw password in toJSON: ${JSON.stringify(classified.toJSON())}`
      );
    });

    it('verifies DiagnosticResult.error does not leak credentials from socket errors', () => {
      const rawSecret = 'DIAGNOSTIC_SECRET_KEY!';
      const socketErr = new Error(`AbortError: timeout waiting for A001 LOGIN "user" "${rawSecret}"`);
      socketErr.name = 'AbortError';

      // Simulating what imap-client.verify does:
      const classified = classifySocketError(socketErr, { provider: 'gmail' });
      const diagnosticError = {
        code: classified.code,
        message: classified.message,
        remediationAdvice: classified.remediation || ''
      };

      assert.ok(
        !diagnosticError.message.includes(rawSecret),
        `DiagnosticResult.error.message leaked secret: "${diagnosticError.message}"`
      );
    });

    it('verifies classifyProtocolResponse sanitizes rawResponse details and message', () => {
      const rawSecret = 'CLEARTEXT_PASSWORD_ABC';
      const line = `NO [ALERT] Failed command: A001 LOGIN "alice" "${rawSecret}"`;

      const classified = classifyProtocolResponse(line, { provider: 'custom' });

      assert.ok(
        !classified.message.includes(rawSecret),
        `classifyProtocolResponse leaked password in message: "${classified.message}"`
      );
      assert.ok(
        !classified.details.rawResponse.includes(rawSecret),
        `classifyProtocolResponse leaked password in rawResponse: "${classified.details.rawResponse}"`
      );
    });

    it('verifies classifyError does not leak credentials in fallback message', () => {
      const rawSecret = 'SECRET_TOKEN_XYZ';
      const hostileInput = `LOGIN "admin" "${rawSecret}"`;

      // Pass hostile string through classifyError
      const classified = classifyError(hostileInput);

      assert.ok(
        !classified.message.includes(rawSecret),
        `classifyError leaked secret in fallback message: "${classified.message}"`
      );
    });
  });

  // ==========================================================================
  // VECTOR 4: Error Subclass Polymorphism
  // ==========================================================================
  describe('Vector 4: Error Subclass Polymorphism', () => {

    const ERROR_CLASS_MAP = [
      { code: ERROR_CODES.DNS_RESOLUTION_FAILED, Class: DnsResolutionError, Category: NetworkError },
      { code: ERROR_CODES.CONNECTION_TIMEOUT, Class: ConnectionTimeoutError, Category: NetworkError },
      { code: ERROR_CODES.CONNECTION_REFUSED, Class: ConnectionRefusedError, Category: NetworkError },
      { code: ERROR_CODES.CONNECTION_DROPPED, Class: ConnectionDroppedError, Category: NetworkError },
      { code: ERROR_CODES.TLS_HANDSHAKE_FAILED, Class: TlsHandshakeError, Category: TlsError },
      { code: ERROR_CODES.AUTH_INVALID_CREDENTIALS, Class: AuthInvalidCredentialsError, Category: AuthenticationError },
      { code: ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED, Class: AuthAppPasswordRequiredError, Category: AuthenticationError },
      { code: ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED, Class: AuthTenantPolicyBlockedError, Category: AuthenticationError },
      { code: ERROR_CODES.AUTH_IMAP_DISABLED, Class: AuthImapDisabledError, Category: AuthenticationError },
      { code: ERROR_CODES.PROTOCOL_VIOLATION, Class: ProtocolViolationError, Category: ProtocolError },
      { code: ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE, Class: ServerTemporarilyUnavailableError, Category: ProtocolError },
      { code: ERROR_CODES.MAILBOX_NOT_FOUND, Class: MailboxNotFoundError, Category: ProtocolError }
    ];

    it('verifies all 12 classes exhibit complete 3-tier prototype inheritance', () => {
      assert.strictEqual(ERROR_CLASS_MAP.length, 12, 'Must test exactly 12 subclasses');

      for (const { code, Class, Category } of ERROR_CLASS_MAP) {
        const instance = new Class(`Test message for ${code}`, {
          provider: 'apple',
          remediation: 'Custom fix',
          host: 'imap.mail.me.com',
          port: 993
        });

        // Tier 1: Concrete class
        assert.ok(instance instanceof Class, `${Class.name} should be instance of ${Class.name}`);
        // Tier 2: Category base
        assert.ok(instance instanceof Category, `${Class.name} should be instance of ${Category.name}`);
        // Tier 3: Root MailboxerError
        assert.ok(instance instanceof MailboxerError, `${Class.name} should be instance of MailboxerError`);
        // Tier 4: Native Error
        assert.ok(instance instanceof Error, `${Class.name} should be instance of Error`);

        // Name and Code consistency
        assert.strictEqual(instance.name, Class.name, `instance.name should match constructor name`);
        assert.strictEqual(instance.code, code, `instance.code should match ${code}`);
        assert.strictEqual(instance.provider, 'apple');
        assert.strictEqual(instance.remediation, 'Custom fix');
        assert.strictEqual(instance.details.host, 'imap.mail.me.com');
        assert.strictEqual(instance.details.port, 993);

        // isMailboxerError predicate
        assert.strictEqual(isMailboxerError(instance), true);
      }
    });

    it('verifies toJSON() and JSON.stringify serialization consistency across all 12 classes', () => {
      for (const { code, Class } of ERROR_CLASS_MAP) {
        const instance = new Class(`Serialization test for ${code}`, {
          provider: 'gmail',
          remediation: 'Fix config'
        });

        const json = instance.toJSON();
        assert.strictEqual(typeof json, 'object');
        assert.strictEqual(json.name, Class.name);
        assert.strictEqual(json.code, code);
        assert.strictEqual(json.provider, 'gmail');
        assert.strictEqual(json.remediation, 'Fix config');
        assert.strictEqual(json.message, `Serialization test for ${code}`);
        assert.ok(typeof json.timestamp === 'string');

        // JSON.stringify round-trip
        const stringified = JSON.stringify(instance);
        const parsed = JSON.parse(stringified);
        assert.strictEqual(parsed.name, Class.name);
        assert.strictEqual(parsed.code, code);
        assert.strictEqual(parsed.provider, 'gmail');
      }
    });

    it('verifies createErrorByCode factory instantiates precise subclass for all 12 codes', () => {
      for (const { code, Class } of ERROR_CLASS_MAP) {
        const created = createErrorByCode(code, `Created via factory: ${code}`, { provider: 'outlook' });
        assert.ok(created instanceof Class, `createErrorByCode(${code}) must return instance of ${Class.name}`);
        assert.strictEqual(created.code, code);
        assert.strictEqual(created.name, Class.name);
        assert.strictEqual(created.provider, 'outlook');
      }
    });

    it('verifies createErrorByCode fallback for unknown error code', () => {
      const unknown = createErrorByCode('NON_EXISTENT_CODE', 'Unknown failure', { provider: 'custom' });
      assert.ok(unknown instanceof MailboxerError);
      assert.strictEqual(unknown.code, 'NON_EXISTENT_CODE');
      assert.strictEqual(unknown.name, 'MailboxerError');
      assert.strictEqual(unknown.provider, 'custom');
    });

    it('verifies ERROR_CONSTRUCTORS dictionary is frozen and maps all 12 codes', () => {
      assert.ok(Object.isFrozen(ERROR_CONSTRUCTORS), 'ERROR_CONSTRUCTORS must be frozen');
      assert.strictEqual(Object.keys(ERROR_CONSTRUCTORS).length, 12);
      for (const { code, Class } of ERROR_CLASS_MAP) {
        assert.strictEqual(ERROR_CONSTRUCTORS[code], Class);
      }
    });
  });
});
