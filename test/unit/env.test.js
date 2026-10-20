/**
 * Environment Loader Unit Test Suite
 * Validates environment variable parsing, placeholder detection,
 * credential masking, and unconfigured account classification.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadEnvironmentAccounts,
  detectPlaceholders,
  maskSecret,
  maskEmail,
  parseEnvContent,
  isAccountConfigured
} from '../../src/config/env.js';

describe('Environment Loader (src/config/env.js)', () => {
  const createMockEnv = (overrides = {}) => ({
    GMAIL_ENABLED: 'true',
    GMAIL_EMAIL: 'real.user@gmail.com',
    GMAIL_APP_PASSWORD: 'abcd efgh ijkl mnop',

    APPLE_ENABLED: 'true',
    APPLE_EMAIL: 'real.user@icloud.com',
    APPLE_APP_PASSWORD: 'abcd-efgh-ijkl-mnop',

    OUTLOOK_ENABLED: 'true',
    OUTLOOK_EMAIL: 'student@university.edu',
    OUTLOOK_PASSWORD: 'RealStudentPassword123!',
    ...overrides
  });

  describe('Multi-Account Configuration Loading', () => {
    it('parses and validates all 3 accounts when valid credentials provided', () => {
      const mockEnv = createMockEnv();
      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 3, 'Should load 3 active accounts');
      assert.strictEqual(result.unconfigured.length, 0, 'Should have 0 unconfigured accounts');

      const providers = result.accounts.map((a) => a.provider);
      assert.ok(providers.includes('gmail'), 'Gmail account present');
      assert.ok(providers.includes('apple'), 'Apple account present');
      assert.ok(providers.includes('outlook'), 'Outlook account present');
    });

    it('resolves Gmail account with accurate preset defaults and normalized app password', () => {
      const mockEnv = createMockEnv();
      const result = loadEnvironmentAccounts({ env: mockEnv });
      const gmail = result.accounts.find((a) => a.provider === 'gmail');

      assert.ok(gmail, 'Gmail account must be resolved');
      assert.strictEqual(gmail.email, 'real.user@gmail.com');
      assert.strictEqual(gmail.auth.pass, 'abcdefghijklmnop', 'Spaces stripped from app password');
      assert.strictEqual(gmail.imap.host, 'imap.gmail.com');
      assert.strictEqual(gmail.imap.port, 993);
    });

    it('resolves Apple account with accurate preset defaults and normalized app password', () => {
      const mockEnv = createMockEnv();
      const result = loadEnvironmentAccounts({ env: mockEnv });
      const apple = result.accounts.find((a) => a.provider === 'apple');

      assert.ok(apple, 'Apple account must be resolved');
      assert.strictEqual(apple.email, 'real.user@icloud.com');
      assert.strictEqual(apple.auth.pass, 'abcdefghijklmnop', 'Dashes stripped from app password');
      assert.strictEqual(apple.imap.host, 'imap.mail.me.com');
      assert.strictEqual(apple.imap.port, 993);
      assert.strictEqual(apple.smtp.port, 587);
    });

    it('resolves Outlook account with accurate preset defaults', () => {
      const mockEnv = createMockEnv();
      const result = loadEnvironmentAccounts({ env: mockEnv });
      const outlook = result.accounts.find((a) => a.provider === 'outlook');

      assert.ok(outlook, 'Outlook account must be resolved');
      assert.strictEqual(outlook.email, 'student@university.edu');
      assert.strictEqual(outlook.auth.pass, 'RealStudentPassword123!');
      assert.strictEqual(outlook.imap.host, 'outlook.office365.com');
    });

    it('respects optional environment variable overrides for ports and labels', () => {
      const mockEnv = createMockEnv({
        GMAIL_LABEL: 'Custom Workspace Gmail',
        GMAIL_IMAP_PORT: '1993',
        GMAIL_CONNECTION_TIMEOUT_MS: '20000'
      });
      const result = loadEnvironmentAccounts({ env: mockEnv });
      const gmail = result.accounts.find((a) => a.provider === 'gmail');

      assert.strictEqual(gmail.label, 'Custom Workspace Gmail');
      assert.strictEqual(gmail.imap.port, 1993);
      assert.strictEqual(gmail.imap.connectionTimeoutMs, 20000);
    });

    it('respects _ENABLED=false and excludes account from active list', () => {
      const mockEnv = createMockEnv({
        GMAIL_ENABLED: 'false'
      });
      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 2);
      assert.strictEqual(
        result.accounts.some((a) => a.provider === 'gmail'),
        false
      );
    });

    it('treats accounts as disabled case-insensitively (FALSE, False, NO, no, 0, " false ") (Defect 7 regression)', () => {
      const mockEnv = {
        GMAIL_ENABLED: 'FALSE',
        APPLE_ENABLED: 'no',
        OUTLOOK_ENABLED: 'False'
      };

      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 0, 'No accounts should be loaded when all are disabled');
      assert.strictEqual(
        result.unconfigured.length,
        0,
        'Disabled accounts must NOT be listed in unconfigured diagnostic checklist'
      );
    });

    it('handles mixed case and whitespace-padded disable flags', () => {
      const mockEnv = {
        GMAIL_ENABLED: ' false ',
        APPLE_ENABLED: 'NO',
        OUTLOOK_ENABLED: '0'
      };

      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 0);
      assert.strictEqual(result.unconfigured.length, 0);
    });

    it('correctly isolates active accounts when companion accounts are disabled with uppercase flags', () => {
      const mockEnv = {
        GMAIL_ENABLED: 'TRUE',
        GMAIL_EMAIL: 'user@gmail.com',
        GMAIL_APP_PASSWORD: 'abcd efgh ijkl mnop',

        APPLE_ENABLED: 'FALSE',
        APPLE_EMAIL: '', // Missing credentials, but disabled!
        APPLE_APP_PASSWORD: '',

        OUTLOOK_ENABLED: 'No',
        OUTLOOK_EMAIL: '',
        OUTLOOK_PASSWORD: ''
      };

      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 1, 'Only Gmail should be active');
      assert.strictEqual(result.accounts[0].provider, 'gmail');
      assert.strictEqual(
        result.unconfigured.length,
        0,
        'Disabled Apple and Outlook accounts must not appear in unconfigured list'
      );
    });

    it('respects CUSTOM_ENABLED case-insensitive disablement', () => {
      const mockEnv = {
        GMAIL_ENABLED: 'false',
        APPLE_ENABLED: 'false',
        OUTLOOK_ENABLED: 'false',
        CUSTOM_ENABLED: 'FALSE',
        CUSTOM_EMAIL: 'user@customserver.com',
        CUSTOM_PASSWORD: 'password123'
      };

      const result = loadEnvironmentAccounts({ env: mockEnv });
      assert.strictEqual(result.accounts.length, 0, 'Custom account must be disabled');
      assert.strictEqual(result.unconfigured.length, 0);
    });
  });

  describe('Missing & Incomplete Credentials Handling', () => {
    it('returns empty accounts list and populated unconfigured list for empty env', () => {
      const result = loadEnvironmentAccounts({ env: {} });

      assert.strictEqual(result.accounts.length, 0);
      assert.strictEqual(result.unconfigured.length, 3);

      const unconfiguredProviders = result.unconfigured.map((u) => u.provider);
      assert.ok(unconfiguredProviders.includes('gmail'));
      assert.ok(unconfiguredProviders.includes('apple'));
      assert.ok(unconfiguredProviders.includes('outlook'));
    });

    it('flags account as unconfigured when email is provided without password', () => {
      const mockEnv = {
        GMAIL_ENABLED: 'true',
        GMAIL_EMAIL: 'user@gmail.com'
        // GMAIL_APP_PASSWORD missing
      };
      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 0);
      const gmailUnconfigured = result.unconfigured.find((u) => u.provider === 'gmail');
      assert.ok(gmailUnconfigured, 'Gmail should be in unconfigured list');
      assert.strictEqual(gmailUnconfigured.reason, 'MISSING_CREDENTIALS');
      assert.ok(gmailUnconfigured.advice, 'Remediation advice should be provided');
    });

    it('flags account as unconfigured when password is provided without email', () => {
      const mockEnv = {
        APPLE_ENABLED: 'true',
        APPLE_APP_PASSWORD: 'abcdefghijklmnop'
        // APPLE_EMAIL missing
      };
      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 0);
      const appleUnconfigured = result.unconfigured.find((u) => u.provider === 'apple');
      assert.ok(appleUnconfigured);
      assert.strictEqual(appleUnconfigured.reason, 'MISSING_CREDENTIALS');
    });
  });

  describe('Placeholder Detection (detectPlaceholders)', () => {
    it('detects standard email placeholder values from .env.example', () => {
      assert.strictEqual(detectPlaceholders('your.account@gmail.com'), true);
      assert.strictEqual(detectPlaceholders('your.account@icloud.com'), true);
      assert.strictEqual(detectPlaceholders('your.id@university.edu'), true);
      assert.strictEqual(detectPlaceholders('user@example.com'), true);
      assert.strictEqual(detectPlaceholders('username@domain.com'), true);
    });

    it('detects standard password placeholder values from .env.example', () => {
      assert.strictEqual(detectPlaceholders('your-16-char-app-password'), true);
      assert.strictEqual(detectPlaceholders('your_app_password'), true);
      assert.strictEqual(detectPlaceholders('xxxx-xxxx-xxxx-xxxx'), true);
      assert.strictEqual(detectPlaceholders('YOUR_PASSWORD_HERE'), true);
    });

    it('returns false for realistic, actual credentials', () => {
      assert.strictEqual(detectPlaceholders('sarah.connor@gmail.com'), false);
      assert.strictEqual(detectPlaceholders('abcd efgh ijkl mnop'), false);
      assert.strictEqual(detectPlaceholders('student9876@cambridge.ac.uk'), false);
      assert.strictEqual(detectPlaceholders('MySecurePassword2026!'), false);
    });

    it('handles null, undefined, empty strings, and non-strings safely', () => {
      assert.strictEqual(detectPlaceholders(''), false);
      assert.strictEqual(detectPlaceholders(null), false);
      assert.strictEqual(detectPlaceholders(undefined), false);
      assert.strictEqual(detectPlaceholders(12345), false);
    });

    it('categorizes accounts with placeholder credentials as unconfigured', () => {
      const mockEnv = {
        GMAIL_ENABLED: 'true',
        GMAIL_EMAIL: 'your.account@gmail.com', // placeholder
        GMAIL_APP_PASSWORD: 'your-16-char-app-password' // placeholder
      };
      const result = loadEnvironmentAccounts({ env: mockEnv });

      assert.strictEqual(result.accounts.length, 0);
      const gmailUnconfigured = result.unconfigured.find((u) => u.provider === 'gmail');
      assert.ok(gmailUnconfigured);
      assert.strictEqual(gmailUnconfigured.reason, 'PLACEHOLDER_CREDENTIALS');
      assert.ok(gmailUnconfigured.advice.includes('.env.example'));
    });
  });

  describe('Defensive Credential & Email Masking (maskSecret, maskEmail)', () => {
    it('masks 16-character app passwords while showing minimal boundary hints', () => {
      const masked = maskSecret('abcdefghijklmnop');
      assert.strictEqual(masked.length >= 10, true);
      assert.ok(masked.includes('*'), 'Must contain mask characters');
      assert.ok(masked.startsWith('abcd'), 'Preserves prefix hint');
      assert.ok(!masked.includes('efghijkl'), 'Conceals middle secret');
    });

    it('masks arbitrary passwords securely', () => {
      const masked = maskSecret('VerySecretPass123!');
      assert.ok(masked.includes('***'));
      assert.ok(!masked.includes('SecretPass'));
    });

    it('handles very short secrets (< 5 characters) without exposing characters', () => {
      const masked1 = maskSecret('abc');
      const masked2 = maskSecret('a');
      assert.strictEqual(masked1, '***');
      assert.strictEqual(masked2, '***');
    });

    it('handles empty, null, and undefined safely without throwing', () => {
      assert.strictEqual(maskSecret(''), '');
      assert.strictEqual(maskSecret(null), '');
      assert.strictEqual(maskSecret(undefined), '');
    });

    it('masks email addresses defensively and never returns literal "undefined" for missing localparts (Defect 6 regression)', () => {
      // Empty localpart with domain
      const maskedAtDomain = maskEmail('@domain.com');
      assert.strictEqual(typeof maskedAtDomain, 'string');
      assert.ok(!maskedAtDomain.includes('undefined'), 'Must never interpolate "undefined" for empty localpart');
      assert.strictEqual(maskedAtDomain, '***@domain.com');

      // Bare '@'
      const maskedBareAt = maskEmail('@');
      assert.strictEqual(typeof maskedBareAt, 'string');
      assert.ok(!maskedBareAt.includes('undefined'), 'Must never interpolate "undefined" for bare @');
      assert.strictEqual(maskedBareAt, '***@***');

      // Double '@'
      assert.strictEqual(maskEmail('@@domain.com'), '****');
      assert.strictEqual(maskEmail('user@@domain.com'), '****');
      assert.strictEqual(maskEmail('not-an-email'), '****');

      // Empty, null, undefined, and non-strings
      assert.strictEqual(maskEmail(''), '');
      assert.strictEqual(maskEmail(null), '');
      assert.strictEqual(maskEmail(undefined), '');
      assert.strictEqual(maskEmail(12345), '');

      // Standard emails retain expected masking
      assert.strictEqual(maskEmail('user@gmail.com'), 'u***r@gmail.com');
      assert.strictEqual(maskEmail('a@icloud.com'), 'a***@icloud.com');
      assert.strictEqual(maskEmail('ab@icloud.com'), 'a***@icloud.com');
      assert.strictEqual(maskEmail('sarah.connor@gmail.com'), 's***r@gmail.com');
      assert.strictEqual(maskEmail('student@university.edu'), 's***t@university.edu');
    });
  });

  describe('Filesystem & Environment Edge Cases', () => {
    it('handles non-existent .env file path gracefully without uncaught exceptions', () => {
      const result = loadEnvironmentAccounts({ envPath: './non-existent-env-file.tmp' });
      assert.ok(result, 'Must return a result object');
      assert.ok(Array.isArray(result.accounts), 'accounts must be array');
      assert.ok(Array.isArray(result.unconfigured), 'unconfigured must be array');
    });

    it('ensures in-memory env parameter does not mutate process.env', () => {
      const originalEnvValue = process.env.MAILBOXER_ISOLATION_TEST_KEY;
      loadEnvironmentAccounts({
        env: {
          GMAIL_ENABLED: 'true',
          GMAIL_EMAIL: 'test@gmail.com',
          GMAIL_APP_PASSWORD: 'pass',
          MAILBOXER_ISOLATION_TEST_KEY: 'test_value'
        }
      });
      assert.strictEqual(process.env.MAILBOXER_ISOLATION_TEST_KEY, originalEnvValue);
    });

    it('validates helper isAccountConfigured for valid vs invalid accounts', () => {
      assert.strictEqual(
        isAccountConfigured({
          email: 'user@gmail.com',
          password: 'valid-password'
        }),
        true
      );
      assert.strictEqual(
        isAccountConfigured({
          email: 'your.account@gmail.com',
          password: 'valid-password'
        }),
        false
      );
      assert.strictEqual(
        isAccountConfigured({
          email: 'user@gmail.com',
          password: ''
        }),
        false
      );
    });
  });

  describe('Standalone .env Content Parser (parseEnvContent) (Defect 5 regression)', () => {
    it('preserves quoted values containing hash symbols when followed by inline comment', () => {
      const content = 'GMAIL_APP_PASSWORD="secret#123" # primary gmail token';
      const parsed = parseEnvContent(content);
      assert.strictEqual(
        parsed.GMAIL_APP_PASSWORD,
        'secret#123',
        'Should preserve # inside quotes and strip trailing comment and outer quotes'
      );
    });

    it('strips outer quotes from values containing spaces when followed by inline comment', () => {
      const content = 'APPLE_APP_PASSWORD="abcd efgh ijkl mnop" # iCloud app password';
      const parsed = parseEnvContent(content);
      assert.strictEqual(
        parsed.APPLE_APP_PASSWORD,
        'abcd efgh ijkl mnop',
        'Should preserve spaces, strip trailing comment, and strip outer quotes'
      );
    });

    it('handles single-quoted values with hash symbols and trailing comments', () => {
      const content = "OUTLOOK_PASSWORD='secret#token#456' # University portal credential";
      const parsed = parseEnvContent(content);
      assert.strictEqual(
        parsed.OUTLOOK_PASSWORD,
        'secret#token#456',
        'Single quotes and comments must be stripped while preserving internal #'
      );
    });

    it('handles escaped quotes and newlines inside quoted values followed by comments', () => {
      const content = 'MULTI_LINE="hello\\nworld\\\"quoted\\\"" # comment with # symbols';
      const parsed = parseEnvContent(content);
      assert.strictEqual(parsed.MULTI_LINE, 'hello\nworld"quoted"');
    });

    it('strips comments from unquoted values without corrupting value', () => {
      const parsed = parseEnvContent('UNQUOTED=my_val # trailing comment');
      assert.strictEqual(parsed.UNQUOTED, 'my_val');
    });

    it('handles unterminated quotes gracefully without throwing', () => {
      const parsed = parseEnvContent('UNTERMINATED="foo # comment');
      assert.strictEqual(parsed.UNTERMINATED, '"foo');
    });

    it('correctly parses multi-line .env content containing varied quotes, hashes, and comments', () => {
      const content = [
        '# Mailboxer Configuration',
        'GMAIL_ENABLED=true',
        'GMAIL_EMAIL=user@gmail.com',
        'GMAIL_APP_PASSWORD="secret#123" # comment',
        'APPLE_ENABLED=true',
        'APPLE_EMAIL=user@icloud.com',
        'APPLE_APP_PASSWORD="abcd efgh ijkl mnop" # token',
        "OUTLOOK_PASSWORD='uni#secret' # comment",
        'UNQUOTED_VAR=simple_token # trailing comment'
      ].join('\n');

      const parsed = parseEnvContent(content);
      assert.strictEqual(parsed.GMAIL_ENABLED, 'true');
      assert.strictEqual(parsed.GMAIL_EMAIL, 'user@gmail.com');
      assert.strictEqual(parsed.GMAIL_APP_PASSWORD, 'secret#123');
      assert.strictEqual(parsed.APPLE_ENABLED, 'true');
      assert.strictEqual(parsed.APPLE_EMAIL, 'user@icloud.com');
      assert.strictEqual(parsed.APPLE_APP_PASSWORD, 'abcd efgh ijkl mnop');
      assert.strictEqual(parsed.OUTLOOK_PASSWORD, 'uni#secret');
      assert.strictEqual(parsed.UNQUOTED_VAR, 'simple_token');
    });
  });
});
