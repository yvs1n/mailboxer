/**
 * Schema Unit Test Suite
 * Validates strict configuration schema, RFC 5322 emails, port boundaries,
 * TLS parameters, and App Password sanitization.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateAccountConfig,
  resolveAccountConfig,
  validateServerConfig,
  isValidHostname,
  normalizeSecret,
  isValidEmail,
  isValidPort,
  ValidationError
} from '../../src/config/schema.js';

describe('Schema Validator (src/config/schema.js)', () => {
  const createValidConfig = (overrides = {}) => ({
    id: 'test-account',
    label: 'Test Account',
    provider: 'apple',
    email: 'user@icloud.com',
    enabled: true,
    auth: {
      type: 'app_password',
      user: 'user@icloud.com',
      pass: 'abcdefghijklmnop'
    },
    imap: {
      host: 'imap.mail.me.com',
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    smtp: {
      host: 'smtp.mail.me.com',
      port: 587,
      secure: false,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    ...overrides
  });

  describe('Valid Account Configurations', () => {
    it('accepts valid Apple Mail configuration', () => {
      const config = createValidConfig();
      const validated = validateAccountConfig(config);
      assert.strictEqual(validated.id, 'test-account');
      assert.strictEqual(validated.provider, 'apple');
      assert.strictEqual(validated.imap.port, 993);
    });

    it('accepts valid Google Mail configuration', () => {
      const config = createValidConfig({
        id: 'gmail-test',
        provider: 'gmail',
        email: 'user@gmail.com',
        imap: {
          host: 'imap.gmail.com',
          port: 993,
          secure: true,
          connectionTimeoutMs: 10000,
          authTimeoutMs: 10000,
          tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
        }
      });
      const validated = validateAccountConfig(config);
      assert.strictEqual(validated.provider, 'gmail');
    });

    it('accepts valid Outlook configuration', () => {
      const config = createValidConfig({
        id: 'outlook-test',
        provider: 'outlook',
        email: 'user@university.edu',
        imap: {
          host: 'outlook.office365.com',
          port: 993,
          secure: true,
          connectionTimeoutMs: 10000,
          authTimeoutMs: 10000,
          tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
        }
      });
      const validated = validateAccountConfig(config);
      assert.strictEqual(validated.provider, 'outlook');
    });

    it('accepts valid Custom configuration with custom host and port', () => {
      const config = createValidConfig({
        id: 'custom-test',
        provider: 'custom',
        email: 'user@mailserver.local',
        imap: {
          host: 'mail.customserver.internal',
          port: 1993,
          secure: true,
          connectionTimeoutMs: 5000,
          authTimeoutMs: 5000,
          tls: { rejectUnauthorized: false, minVersion: 'TLSv1.3' }
        }
      });
      const validated = validateAccountConfig(config);
      assert.strictEqual(validated.provider, 'custom');
      assert.strictEqual(validated.imap.port, 1993);
      assert.strictEqual(validated.imap.tls.rejectUnauthorized, false);
    });
  });

  describe('Configuration Resolution & Preset Merging', () => {
    it('resolves minimal Apple input into fully populated AccountConfig', () => {
      const resolved = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        password: 'abcd-efgh-ijkl-mnop'
      });
      assert.strictEqual(resolved.provider, 'apple');
      assert.strictEqual(resolved.email, 'user@icloud.com');
      assert.strictEqual(resolved.imap.host, 'imap.mail.me.com');
      assert.strictEqual(resolved.imap.port, 993);
      assert.strictEqual(resolved.imap.secure, true);
      assert.strictEqual(resolved.auth.pass, 'abcdefghijklmnop');
      assert.ok(resolved.id, 'ID must be auto-generated');
      assert.ok(resolved.label, 'Label must be auto-generated');
    });

    it('resolves minimal Gmail input with preset defaults', () => {
      const resolved = resolveAccountConfig({
        provider: 'gmail',
        email: 'user@gmail.com',
        password: 'abcd efgh ijkl mnop'
      });
      assert.strictEqual(resolved.provider, 'gmail');
      assert.strictEqual(resolved.imap.host, 'imap.gmail.com');
      assert.strictEqual(resolved.auth.pass, 'abcdefghijklmnop');
    });

    it('resolves minimal Outlook input with preset defaults', () => {
      const resolved = resolveAccountConfig({
        provider: 'outlook',
        email: 'student@university.edu',
        password: 'MyUniPassword123'
      });
      assert.strictEqual(resolved.provider, 'outlook');
      assert.strictEqual(resolved.imap.host, 'outlook.office365.com');
    });

    it('preserves user overrides when resolving with presets', () => {
      const resolved = resolveAccountConfig({
        provider: 'gmail',
        email: 'user@gmail.com',
        password: 'app-password',
        label: 'My Custom Gmail',
        imap: { port: 1993, connectionTimeoutMs: 15000 }
      });
      assert.strictEqual(resolved.label, 'My Custom Gmail');
      assert.strictEqual(resolved.imap.port, 1993);
      assert.strictEqual(resolved.imap.connectionTimeoutMs, 15000);
      assert.strictEqual(resolved.imap.host, 'imap.gmail.com');
    });

    it('infers provider from email domain when provider is omitted', () => {
      const gmailResolved = resolveAccountConfig({
        email: 'user@gmail.com',
        password: 'secretpassword'
      });
      assert.strictEqual(gmailResolved.provider, 'gmail');

      const appleResolved = resolveAccountConfig({
        email: 'user@icloud.com',
        password: 'secretpassword'
      });
      assert.strictEqual(appleResolved.provider, 'apple');
    });

    it('throws ValidationError for custom provider without explicit IMAP host', () => {
      assert.throws(
        () => resolveAccountConfig({ provider: 'custom', email: 'user@custom.com', password: 'pw' }),
        ValidationError
      );
    });

    it('resolves custom provider without SMTP block when only IMAP is configured (Defect 1 regression)', () => {
      const resolved = resolveAccountConfig({
        provider: 'custom',
        email: 'user@customserver.com',
        auth: { pass: 'password123' },
        imap: { host: 'mail.customserver.com' }
      });

      assert.strictEqual(resolved.provider, 'custom');
      assert.strictEqual(resolved.email, 'user@customserver.com');
      assert.strictEqual(resolved.imap.host, 'mail.customserver.com');
      assert.strictEqual(resolved.imap.port, 993);
      assert.strictEqual(resolved.imap.secure, true);
      assert.strictEqual(resolved.smtp, undefined, 'SMTP block must be omitted when not provided for custom provider');
      assert.ok(resolved.id, 'ID must be generated');
      assert.ok(resolved.label, 'Label must be generated');
    });

    it('resolves custom provider with explicit smtp: null or smtp: false without validation error', () => {
      const resolvedNull = resolveAccountConfig({
        provider: 'custom',
        email: 'user@customserver.com',
        password: 'password123',
        imap: { host: 'mail.customserver.com' },
        smtp: null
      });
      assert.strictEqual(resolvedNull.smtp, undefined);

      const resolvedFalse = resolveAccountConfig({
        provider: 'custom',
        email: 'user@customserver.com',
        password: 'password123',
        imap: { host: 'mail.customserver.com' },
        smtp: false
      });
      assert.strictEqual(resolvedFalse.smtp, undefined);
    });

    it('resolves custom provider with both IMAP and explicit SMTP configuration', () => {
      const resolved = resolveAccountConfig({
        provider: 'custom',
        email: 'user@customserver.com',
        password: 'password123',
        imap: { host: 'mail.customserver.com' },
        smtp: { host: 'smtp.customserver.com' }
      });

      assert.strictEqual(resolved.provider, 'custom');
      assert.strictEqual(resolved.imap.host, 'mail.customserver.com');
      assert.ok(resolved.smtp, 'SMTP block must exist when explicitly configured');
      assert.strictEqual(resolved.smtp.host, 'smtp.customserver.com');
      assert.strictEqual(resolved.smtp.port, 587);
      assert.strictEqual(resolved.smtp.tls.servername, 'smtp.customserver.com');
    });

    it('sets IMAP SNI servername to connection host for custom provider when servername is omitted', () => {
      const resolved = resolveAccountConfig({
        provider: 'custom',
        email: 'user@customserver.com',
        password: 'password123',
        imap: { host: 'mail.customserver.com' }
      });
      assert.strictEqual(resolved.imap.tls.servername, 'mail.customserver.com');
    });

    it('resolves string enabled: "false" and enabled: "0" to boolean false (Defect 2 regression)', () => {
      const resFalseStr = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: 'false'
      });
      assert.strictEqual(resFalseStr.enabled, false, 'String "false" must resolve to boolean false');

      const resZeroStr = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: '0'
      });
      assert.strictEqual(resZeroStr.enabled, false, 'String "0" must resolve to boolean false');

      const resNoStr = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: 'no'
      });
      assert.strictEqual(resNoStr.enabled, false, 'String "no" must resolve to boolean false');

      const resBoolFalse = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: false
      });
      assert.strictEqual(resBoolFalse.enabled, false, 'Boolean false must resolve to boolean false');
    });

    it('resolves enabled: true and enabled: "true" to boolean true, and defaults to true when omitted', () => {
      const resOmitted = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' }
      });
      assert.strictEqual(resOmitted.enabled, true, 'Omitted enabled must default to true');

      const resBoolTrue = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: true
      });
      assert.strictEqual(resBoolTrue.enabled, true);

      const resStrTrue = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: 'true'
      });
      assert.strictEqual(resStrTrue.enabled, true);

      const resOneStr = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        enabled: '1'
      });
      assert.strictEqual(resOneStr.enabled, true);
    });

    it('rejects invalid non-boolean enabled values during validation', () => {
      assert.throws(
        () =>
          resolveAccountConfig({
            provider: 'apple',
            email: 'user@icloud.com',
            auth: { pass: 'abcdefghijklmnop' },
            enabled: 'not_a_boolean'
          }),
        ValidationError,
        'Should reject invalid string enabled value'
      );

      assert.throws(
        () =>
          resolveAccountConfig({
            provider: 'apple',
            email: 'user@icloud.com',
            auth: { pass: 'abcdefghijklmnop' },
            enabled: 42
          }),
        ValidationError,
        'Should reject invalid numeric enabled value'
      );
    });
  });

  describe('App Password Normalization', () => {
    it('strips all whitespace from app passwords', () => {
      assert.strictEqual(normalizeSecret('abcd efgh ijkl mnop'), 'abcdefghijklmnop');
      assert.strictEqual(normalizeSecret('ab cd ef gh ij kl mn op'), 'abcdefghijklmnop');
      assert.strictEqual(normalizeSecret('\tabcd\t \tefgh\t'), 'abcdefgh');
    });

    it('strips hyphens from app passwords', () => {
      assert.strictEqual(normalizeSecret('abcd-efgh-ijkl-mnop'), 'abcdefghijklmnop');
      assert.strictEqual(normalizeSecret('a-b-c-d-e-f-g-h'), 'abcdefgh');
    });

    it('strips mixed whitespace, hyphens, and leading/trailing padding', () => {
      assert.strictEqual(
        normalizeSecret('   abcd - efgh - ijkl - mnop   '),
        'abcdefghijklmnop'
      );
    });

    it('leaves standard non-spaced alphanumeric passwords unchanged', () => {
      assert.strictEqual(normalizeSecret('ComplexP@ssw0rd!'), 'ComplexP@ssw0rd!');
    });

    it('handles null, undefined, and non-strings safely', () => {
      assert.strictEqual(normalizeSecret(''), '');
      assert.strictEqual(normalizeSecret(null), '');
      assert.strictEqual(normalizeSecret(undefined), '');
    });
  });

  describe('Email Format Validation (RFC 5322)', () => {
    it('validates helper isValidEmail for standard and complex emails', () => {
      assert.strictEqual(isValidEmail('user@gmail.com'), true);
      assert.strictEqual(isValidEmail('user.name+tag@sub.domain.co.uk'), true);
      assert.strictEqual(isValidEmail('student_123@university.edu'), true);
    });

    it('rejects invalid email formats', () => {
      assert.strictEqual(isValidEmail('not-an-email'), false);
      assert.strictEqual(isValidEmail('@missinguser.com'), false);
      assert.strictEqual(isValidEmail('user@'), false);
      assert.strictEqual(isValidEmail('user name@gmail.com'), false);
      assert.strictEqual(isValidEmail(''), false);
      assert.strictEqual(isValidEmail(null), false);
    });

    it('throws ValidationError when config email is invalid', () => {
      const invalidEmails = [
        '',
        '   ',
        'invalidemail',
        '@nodomain.com',
        'user@',
        'user@.com',
        12345,
        null,
        undefined
      ];

      for (const email of invalidEmails) {
        assert.throws(
          () => validateAccountConfig(createValidConfig({ email })),
          ValidationError,
          `Expected ValidationError for email: ${email}`
        );
      }
    });

    it('rejects email addresses with numeric top-level domains', () => {
      assert.strictEqual(isValidEmail('user@domain.123'), false, 'Numeric TLD should be rejected');
      assert.strictEqual(isValidEmail('user@domain.c0m'), false, 'Mixed alphanumeric TLD should be rejected');
    });
  });

  describe('Port Number Validation', () => {
    it('validates helper isValidPort on boundary and standard ports', () => {
      assert.strictEqual(isValidPort(1), true);
      assert.strictEqual(isValidPort(993), true);
      assert.strictEqual(isValidPort(587), true);
      assert.strictEqual(isValidPort(465), true);
      assert.strictEqual(isValidPort(65535), true);
    });

    it('rejects out-of-range, negative, and non-integer ports', () => {
      assert.strictEqual(isValidPort(0), false);
      assert.strictEqual(isValidPort(-1), false);
      assert.strictEqual(isValidPort(65536), false);
      assert.strictEqual(isValidPort(99999), false);
      assert.strictEqual(isValidPort(993.5), false);
      assert.strictEqual(isValidPort('993'), false);
      assert.strictEqual(isValidPort(NaN), false);
      assert.strictEqual(isValidPort(null), false);
    });

    it('throws ValidationError when IMAP port is out of bounds', () => {
      const invalidPorts = [0, -1, -993, 65536, 100000, 993.4, '993', NaN, null];

      for (const port of invalidPorts) {
        assert.throws(
          () =>
            validateAccountConfig(
              createValidConfig({
                imap: {
                  host: 'imap.mail.me.com',
                  port,
                  secure: true,
                  connectionTimeoutMs: 10000,
                  authTimeoutMs: 10000,
                  tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
                }
              })
            ),
          ValidationError,
          `Expected ValidationError for port: ${port}`
        );
      }
    });
  });

  describe('Hostname & Network Target Validation', () => {
    it('throws ValidationError when host is empty, whitespace, or invalid type', () => {
      const invalidHosts = ['', '   ', null, undefined, 127001, 'imap. gmail.com'];

      for (const host of invalidHosts) {
        assert.throws(
          () =>
            validateAccountConfig(
              createValidConfig({
                imap: {
                  host,
                  port: 993,
                  secure: true,
                  connectionTimeoutMs: 10000,
                  authTimeoutMs: 10000,
                  tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
                }
              })
            ),
          ValidationError,
          `Expected ValidationError for host: ${host}`
        );
      }
    });

    it('validateServerConfig rejects hostnames containing unstripped CRLF or carriage return (Defect 4 regression)', () => {
      const errorsCRLF = validateServerConfig(
        { host: 'imap.mail.me.com\r\n', port: 993, secure: true },
        'imap'
      );
      assert.ok(errorsCRLF.length > 0, 'Must produce validation error for hostname with trailing CRLF');
      assert.ok(errorsCRLF.some((e) => e.field === 'imap.host'));

      const errorsLF = validateServerConfig(
        { host: 'imap.mail.me.com\n', port: 993, secure: true },
        'imap'
      );
      assert.ok(errorsLF.some((e) => e.field === 'imap.host'));

      const errorsCR = validateServerConfig(
        { host: 'imap.mail.me.com\r', port: 993, secure: true },
        'imap'
      );
      assert.ok(errorsCR.some((e) => e.field === 'imap.host'));
    });

    it('isValidHostname rejects hostnames containing unstripped CRLF, newlines, or whitespace', () => {
      assert.strictEqual(isValidHostname('imap.mail.me.com\r\n'), false);
      assert.strictEqual(isValidHostname('imap.mail.me.com\n'), false);
      assert.strictEqual(isValidHostname('imap.mail.me.com\r'), false);
      assert.strictEqual(isValidHostname(' imap.mail.me.com '), false);
      assert.strictEqual(isValidHostname('imap. mail.me.com'), false);
      assert.strictEqual(isValidHostname('imap.mail.me.com\t'), false);
    });

    it('resolveAccountConfig trims and sanitizes hostname containing surrounding whitespace or CRLF', () => {
      const resolved = resolveAccountConfig({
        provider: 'apple',
        email: 'user@icloud.com',
        auth: { pass: 'abcdefghijklmnop' },
        imap: { host: '  imap.mail.me.com\r\n  ', port: 993, secure: true }
      });
      assert.strictEqual(resolved.imap.host, 'imap.mail.me.com', 'Hostname must be trimmed of CRLF and spaces');
      assert.strictEqual(resolved.imap.host.includes('\r'), false);
      assert.strictEqual(resolved.imap.host.includes('\n'), false);
    });
  });

  describe('TLS & Security Flag Validation', () => {
    it('throws ValidationError when secure is non-boolean', () => {
      assert.throws(
        () =>
          validateAccountConfig(
            createValidConfig({
              imap: {
                host: 'imap.gmail.com',
                port: 993,
                secure: 'true',
                connectionTimeoutMs: 10000,
                authTimeoutMs: 10000,
                tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
              }
            })
          ),
        ValidationError
      );
    });

    it('throws ValidationError when tls.rejectUnauthorized is non-boolean', () => {
      assert.throws(
        () =>
          validateAccountConfig(
            createValidConfig({
              imap: {
                host: 'imap.gmail.com',
                port: 993,
                secure: true,
                connectionTimeoutMs: 10000,
                authTimeoutMs: 10000,
                tls: { rejectUnauthorized: 'yes', minVersion: 'TLSv1.2' }
              }
            })
          ),
        ValidationError
      );
    });

    it('throws ValidationError for unsupported tls.minVersion', () => {
      assert.throws(
        () =>
          validateAccountConfig(
            createValidConfig({
              imap: {
                host: 'imap.gmail.com',
                port: 993,
                secure: true,
                connectionTimeoutMs: 10000,
                authTimeoutMs: 10000,
                tls: { rejectUnauthorized: true, minVersion: 'SSLv3' }
              }
            })
          ),
        ValidationError
      );
    });
  });

  describe('Authentication Block Validation', () => {
    it('throws ValidationError when auth password is missing for app_password type', () => {
      assert.throws(
        () =>
          validateAccountConfig(
            createValidConfig({
              auth: {
                type: 'app_password',
                user: 'user@icloud.com',
                pass: ''
              }
            })
          ),
        ValidationError
      );
    });

    it('throws ValidationError for unsupported auth type', () => {
      assert.throws(
        () =>
          validateAccountConfig(
            createValidConfig({
              auth: {
                type: 'ntlm_unsupported',
                user: 'user@icloud.com',
                pass: 'password'
              }
            })
          ),
        ValidationError
      );
    });
  });

  describe('Aggregated Error Reporting', () => {
    it('aggregates multiple validation failures into errors property', () => {
      try {
        validateAccountConfig({
          id: '',
          email: 'bad-email',
          imap: {
            host: '',
            port: -1,
            secure: 'not-bool'
          }
        });
        assert.fail('Should have thrown ValidationError');
      } catch (err) {
        assert.ok(err instanceof ValidationError, 'Should throw ValidationError');
        assert.ok(Array.isArray(err.errors), 'Should include errors array');
        assert.ok(err.errors.length >= 3, 'Should aggregate multiple errors');
      }
    });
  });
});
