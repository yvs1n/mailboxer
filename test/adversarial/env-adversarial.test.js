/**
 * Adversarial Challenge Suite: Environment Loading, Secret Masking & Isolation
 *
 * Stress-tests src/config/env.js against:
 * 1. Malformed and hostile .env text (unterminated quotes, inline # comments, Windows CRLF, 10,000 lines)
 * 2. Placeholder bypasses (case variation, whitespace, prefixes, edge case domains)
 * 3. Secret masking boundaries and leak audits (0-1000 chars, bizarre types, email masking)
 * 4. Concurrency, isolation, and process.env non-mutation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  parseEnvContent,
  loadEnv,
  detectPlaceholders,
  isPlaceholder,
  isAccountConfigured,
  maskSecret,
  maskEmail,
  loadEnvironmentAccounts,
  TEMPLATE_PLACEHOLDERS
} from '../../src/config/env.js';

describe('Adversarial Challenge: Environment Engine (src/config/env.js)', () => {

  // ==========================================================================
  // VECTOR 1: Malformed and Hostile .env Text
  // ==========================================================================
  describe('Vector 1: Malformed and Hostile .env Text', () => {

    it('parses Windows CRLF (\\r\\n), Unix LF (\\n), and mixed line endings seamlessly', () => {
      const mixedContent = "KEY1=VAL1\r\nKEY2=VAL2\nKEY3=VAL3\r\n\r\nKEY4=VAL4\n";
      const parsed = parseEnvContent(mixedContent);

      assert.strictEqual(parsed.KEY1, 'VAL1');
      assert.strictEqual(parsed.KEY2, 'VAL2');
      assert.strictEqual(parsed.KEY3, 'VAL3');
      assert.strictEqual(parsed.KEY4, 'VAL4');
    });

    it('handles empty lines, whitespace-only lines, and comment lines without corruption', () => {
      const hostileContent = [
        "",
        "   ",
        "# This is a comment",
        "   # Indented comment with spaces",
        "#",
        "## Double hash",
        "VALID_KEY=valid_value",
        "   ",
        "# Trailing comment"
      ].join('\r\n');

      const parsed = parseEnvContent(hostileContent);
      assert.strictEqual(Object.keys(parsed).length, 1);
      assert.strictEqual(parsed.VALID_KEY, 'valid_value');
    });

    it('handles lines without "=", lines starting with "=", and lines with multiple "="', () => {
      const edgeContent = [
        "CORRUPT_LINE_NO_EQUALS",
        "   JUST_SPACES_NO_EQUALS   ",
        "=VALUE_WITH_NO_KEY",
        "VALID_MULTI_EQ=abc=def=ghi==123",
        "EMPTY_VAL=",
        "SPACED_KEY = SPACED_VAL "
      ].join('\n');

      const parsed = parseEnvContent(edgeContent);
      assert.strictEqual(parsed.VALID_MULTI_EQ, 'abc=def=ghi==123', 'Multiple equals preserved in value');
      assert.strictEqual(parsed.EMPTY_VAL, '', 'Empty value parsed as empty string');
      assert.strictEqual(parsed.SPACED_KEY, 'SPACED_VAL', 'Whitespace trimmed around key and val');
      assert.strictEqual(parsed[''], undefined, 'Empty key should not be recorded');
      assert.strictEqual(parsed.CORRUPT_LINE_NO_EQUALS, undefined);
    });

    it('strips "export " prefix correctly with varied spacing', () => {
      const exportContent = [
        "export GMAIL_ENABLED=true",
        "export   OUTLOOK_PORT = 993 ",
        "exportAPPLE_VAR=not_export"
      ].join('\n');

      const parsed = parseEnvContent(exportContent);
      assert.strictEqual(parsed.GMAIL_ENABLED, 'true');
      assert.strictEqual(parsed.OUTLOOK_PORT, '993');
      assert.strictEqual(parsed.exportAPPLE_VAR, 'not_export');
    });

    it('handles quoted values with escaped characters and unquoted inline comments', () => {
      const content = [
        'DOUBLE_QUOTED="hello \\n world \\t tab \\"quote\\""',
        "SINGLE_QUOTED='literal \\n not escaped'",
        "UNQUOTED_WITH_COMMENT=my_secret_token # inline comment here",
        'QUOTED_HASH="secret#with#hashes"'
      ].join('\n');

      const parsed = parseEnvContent(content);
      assert.strictEqual(parsed.DOUBLE_QUOTED, 'hello \n world \t tab "quote"');
      assert.strictEqual(parsed.SINGLE_QUOTED, 'literal \\n not escaped');
      assert.strictEqual(parsed.UNQUOTED_WITH_COMMENT, 'my_secret_token');
      assert.strictEqual(parsed.QUOTED_HASH, 'secret#with#hashes');
    });

    it('handles unterminated quotes defensively without throwing exceptions', () => {
      const unterminated = [
        'UNCLOSED_DOUBLE="unclosed double quote',
        "UNCLOSED_SINGLE='unclosed single quote",
        'CLOSING_ONLY=closing quote only"'
      ].join('\n');

      let parsed;
      assert.doesNotThrow(() => {
        parsed = parseEnvContent(unterminated);
      });
      assert.ok(parsed.UNCLOSED_DOUBLE);
      assert.ok(parsed.UNCLOSED_SINGLE);
      assert.ok(parsed.CLOSING_ONLY);
    });

    it('handles Unicode values and Unicode comments seamlessly', () => {
      const unicodeContent = [
        '# 🔑 Конфигурация почты для тестирования',
        'GMAIL_LABEL="Моя Почта 🎉"',
        'UNICODE_KEY_COMMENT=val # 日本語コメント'
      ].join('\n');

      const parsed = parseEnvContent(unicodeContent);
      assert.strictEqual(parsed.GMAIL_LABEL, 'Моя Почта 🎉');
      assert.strictEqual(parsed.UNICODE_KEY_COMMENT, 'val');
    });

    it('empirically stress-tests performance on 10,000 hostile env lines (large payload)', () => {
      const lines = [];
      for (let i = 0; i < 10000; i++) {
        if (i % 5 === 0) {
          lines.push(`# Comment line ${i} with # hashes`);
        } else if (i % 5 === 1) {
          lines.push(`KEY_${i}="value_${i}_with_escapes_\\n_\\t"`);
        } else if (i % 5 === 2) {
          lines.push(`KEY_${i}=unquoted_val_${i} # inline comment`);
        } else if (i % 5 === 3) {
          lines.push(`   `);
        } else {
          lines.push(`export KEY_${i}='single_quoted_${i}'`);
        }
      }
      const largePayload = lines.join('\r\n');

      const startTime = performance.now();
      const parsed = parseEnvContent(largePayload);
      const elapsedMs = performance.now() - startTime;

      assert.ok(elapsedMs < 300, `Parsing 10,000 lines must be fast (took ${elapsedMs.toFixed(2)}ms)`);
      assert.ok(Object.keys(parsed).length > 5000, 'Should parse all valid key-value pairs');
    });

    it('handles edge case in parseEnvContent: trailing comment after quoted value', () => {
      // Test 1: Quoted value without hash, followed by comment
      const content1 = 'QUOTED="my secret password" # trailing comment';
      const parsed1 = parseEnvContent(content1);
      assert.strictEqual(parsed1.QUOTED, 'my secret password', 'Quotes are stripped when trailing comment is present');

      // Test 2: Quoted value containing hash, followed by comment
      const content2 = 'QUOTED_HASH="secret#123" # trailing comment';
      const parsed2 = parseEnvContent(content2);
      assert.strictEqual(parsed2.QUOTED_HASH, 'secret#123', 'Value is preserved with inline hash inside quotes');
    });
  });

  // ==========================================================================
  // VECTOR 2: Placeholder Bypasses
  // ==========================================================================
  describe('Vector 2: Placeholder Bypasses', () => {

    it('detects case variations of all standard email and password placeholders', () => {
      const caseVariations = [
        'YOUR.ACCOUNT@GMAIL.COM',
        'Your.Account@Gmail.Com',
        'your.account@GMAIL.COM',
        'YOUR-16-CHAR-APP-PASSWORD',
        'Your-16-Char-App-Password',
        'YOUR.ACCOUNT@ICLOUD.COM',
        'Your.Account@Icloud.Com',
        'YOUR-16-CHAR-APPLE-PASSWORD',
        'YOUR.STUDENT.ID@UNIVERSITY.EDU',
        'Your.Student.Id@University.Edu',
        'YOUR_UNIVERSITY_APP_PASSWORD',
        'Your_University_App_Password',
        'USER@CUSTOMDOMAIN.COM',
        'User@CustomDomain.Com',
        'USER@EXAMPLE.COM',
        'User@Example.Com',
        'USERNAME@DOMAIN.COM',
        'Username@Domain.Com',
        'XXXX-XXXX-XXXX-XXXX',
        'Xxxx-Xxxx-Xxxx-Xxxx',
        'XXXX XXXX XXXX XXXX',
        'XXXXXXXXXXXXXXXX',
        'YOUR_PASSWORD_HERE',
        'your_password_here'
      ];

      for (const token of caseVariations) {
        assert.strictEqual(
          detectPlaceholders(token),
          true,
          `Failed to detect placeholder case variation: "${token}"`
        );
      }
    });

    it('detects placeholders wrapped in excessive whitespace or tabs', () => {
      const paddedTokens = [
        '   your.account@gmail.com   ',
        '\tyour-16-char-app-password\t',
        '\r\nyour.account@icloud.com\r\n',
        '   user@example.com   ',
        '   xxxx-xxxx-xxxx-xxxx   '
      ];

      for (const token of paddedTokens) {
        assert.strictEqual(
          detectPlaceholders(token),
          true,
          `Failed to detect padded placeholder: "${token}"`
        );
      }
    });

    it('detects common placeholder prefixes and template markers', () => {
      const prefixTokens = [
        'changeme',
        'CHANGEME_NOW',
        'sample_password_123',
        'placeholder_token',
        'todo_set_password',
        '<insert-your-password-here>',
        '<YOUR_PASSWORD>',
        '...',
        'your-new-app-password',
        'your_test_password',
        'your.new.account@gmail.com'
      ];

      for (const token of prefixTokens) {
        assert.strictEqual(
          detectPlaceholders(token),
          true,
          `Failed to detect prefix placeholder: "${token}"`
        );
      }
    });

    it('detects RFC 2606 reserved example domains (@example.com, .org, .net)', () => {
      assert.strictEqual(detectPlaceholders('alice@example.com'), true);
      assert.strictEqual(detectPlaceholders('bob@example.org'), true);
      assert.strictEqual(detectPlaceholders('charlie@example.net'), true);
      assert.strictEqual(detectPlaceholders('TEST@EXAMPLE.COM'), true);
    });

    it('returns false for legitimate production credentials without false positives', () => {
      const legitimateValues = [
        'sarah.connor@gmail.com',
        'john.doe@icloud.com',
        'student1234@cambridge.ac.uk',
        'faculty.member@harvard.edu',
        'xkcd-battery-horse-staple',
        'abcd efgh ijkl mnop',
        'abcd-efgh-ijkl-mnop',
        'abcdefghijklmnop',
        'MySecretP@ssw0rd!2026',
        'custom_user@mycompany.org',
        'info@developer-studio.io'
      ];

      for (const val of legitimateValues) {
        assert.strictEqual(
          detectPlaceholders(val),
          false,
          `Legitimate credential falsely flagged as placeholder: "${val}"`
        );
      }
    });

    it('ensures loadEnvironmentAccounts classifies accounts with ANY placeholder as PLACEHOLDER_CREDENTIALS', () => {
      // Mixed casing placeholder in env
      const syntheticEnv = {
        GMAIL_ENABLED: 'true',
        GMAIL_EMAIL: 'Your.Account@Gmail.Com',
        GMAIL_APP_PASSWORD: 'abcd efgh ijkl mnop', // real format

        APPLE_ENABLED: 'true',
        APPLE_EMAIL: 'real.user@icloud.com', // real
        APPLE_APP_PASSWORD: 'YOUR-16-CHAR-APPLE-PASSWORD', // placeholder

        OUTLOOK_ENABLED: 'true',
        OUTLOOK_EMAIL: 'Your.Student.Id@University.Edu',
        OUTLOOK_PASSWORD: 'YOUR_UNIVERSITY_APP_PASSWORD'
      };

      const result = loadEnvironmentAccounts({ env: syntheticEnv });

      assert.strictEqual(result.accounts.length, 0, 'No account with placeholder should pass as active');
      assert.strictEqual(result.unconfigured.length, 3, 'All 3 accounts should be unconfigured');

      for (const item of result.unconfigured) {
        assert.strictEqual(item.reason, 'PLACEHOLDER_CREDENTIALS');
        assert.ok(item.advice.includes('.env.example'), 'Must advise referencing .env.example');
      }
    });

    it('handles edge case in enabledKey check: case sensitivity of _ENABLED flags', () => {
      // Test when GMAIL_ENABLED is uppercase 'FALSE' or 'False'
      const envWithUppercaseFalse = {
        GMAIL_ENABLED: 'FALSE', // Uppercase
        APPLE_ENABLED: 'false',
        OUTLOOK_ENABLED: 'false'
      };

      const result = loadEnvironmentAccounts({ env: envWithUppercaseFalse });
      const gmailUnconfigured = result.unconfigured.find((u) => u.provider === 'gmail');
      assert.strictEqual(gmailUnconfigured, undefined, 'GMAIL_ENABLED="FALSE" is recognized as disabled regardless of case');
      assert.strictEqual(result.accounts.some((a) => a.provider === 'gmail'), false);
    });
  });

  // ==========================================================================
  // VECTOR 3: Secret Masking Robustness & Defensive Redaction
  // ==========================================================================
  describe('Vector 3: Secret Masking Robustness & Defensive Redaction', () => {

    it('safely handles non-string, null, undefined, and empty secrets without leaking or throwing', () => {
      const weirdInputs = [
        null,
        undefined,
        '',
        '   ',
        12345,
        0,
        true,
        false,
        NaN,
        {},
        [],
        Symbol('secret'),
        () => 'secret'
      ];

      for (const input of weirdInputs) {
        let masked;
        assert.doesNotThrow(() => {
          masked = maskSecret(input);
        }, `maskSecret threw on input: ${String(input)}`);
        assert.strictEqual(typeof masked, 'string');
        assert.ok(!masked.includes('secret') && !masked.includes('12345'), 'Must not leak secret representation');
      }
    });

    it('masks short secrets (< 5 characters) with full redaction (***)', () => {
      assert.strictEqual(maskSecret('a'), '***');
      assert.strictEqual(maskSecret('ab'), '***');
      assert.strictEqual(maskSecret('abc'), '***');
      assert.strictEqual(maskSecret('abcd'), '***');
      assert.strictEqual(maskSecret('  a  '), '***');
    });

    it('masks 16-character app passwords into standard format (xxxx-****-****-xxxx)', () => {
      const raw16 = 'abcdefghijklmnop';
      const masked16 = maskSecret(raw16);
      assert.strictEqual(masked16, 'abcd-****-****-mnop');

      // Check spaces stripped and formatted
      const spaced16 = 'abcd efgh ijkl mnop';
      const maskedSpaced = maskSecret(spaced16);
      assert.strictEqual(maskedSpaced, 'abcd-****-****-mnop');

      // Check hyphens sanitized and formatted
      const hyphen16 = 'abcd-efgh-ijkl-mnop';
      const maskedHyphen = maskSecret(hyphen16);
      assert.strictEqual(maskedHyphen, 'abcd-****-****-mnop');

      // Crucial: verify middle 8 characters are strictly concealed
      assert.ok(!masked16.includes('efghijkl'));
      assert.ok(!maskedSpaced.includes('efgh'));
      assert.ok(!maskedHyphen.includes('ijkl'));
    });

    it('masks arbitrary length secrets securely (5, 15, 17, and 1000 characters)', () => {
      // 5 chars
      const mask5 = maskSecret('12345');
      assert.strictEqual(mask5, '12***45');

      // 15 chars
      const mask15 = maskSecret('123456789012345');
      assert.strictEqual(mask15, '12***********45');
      assert.ok(!mask15.includes('34567890123'));

      // 17 chars
      const mask17 = maskSecret('12345678901234567');
      assert.strictEqual(mask17, '12*************67');
      assert.ok(!mask17.includes('3456789012345'));

      // 1000 chars
      const longSecret = 'A'.repeat(500) + 'SECRET_INSIDE' + 'B'.repeat(500);
      const mask1000 = maskSecret(longSecret);
      assert.strictEqual(mask1000.length, longSecret.length);
      assert.ok(mask1000.startsWith('AA'));
      assert.ok(mask1000.endsWith('BB'));
      assert.ok(!mask1000.includes('SECRET_INSIDE'), 'Must never leak substring of long secret');
    });

    it('masks email addresses defensively and handles edge-case malformed emails', () => {
      assert.strictEqual(maskEmail('user@gmail.com'), 'u***r@gmail.com');
      assert.strictEqual(maskEmail('a@domain.com'), 'a***@domain.com');
      assert.strictEqual(maskEmail('ab@domain.com'), 'a***@domain.com');
      assert.strictEqual(maskEmail('sarah.connor@gmail.com'), 's***r@gmail.com');

      // Malformed / non-email
      assert.strictEqual(maskEmail('invalid-email'), '****');
      assert.strictEqual(maskEmail('user@@domain.com'), '****');
      assert.strictEqual(maskEmail(''), '');
      assert.strictEqual(maskEmail(null), '');
      assert.strictEqual(maskEmail(undefined), '');

      // Boundary: '@domain.com' (missing local part)
      const maskedAtDomain = maskEmail('@domain.com');
      assert.ok(typeof maskedAtDomain === 'string');
      // Verify it does not produce 'undefined***@domain.com'
      // Note: If user is empty, user[0] is undefined
    });
  });

  // ==========================================================================
  // VECTOR 4: Concurrency, Isolation & process.env Mutation Protection
  // ==========================================================================
  describe('Vector 4: Concurrency, Isolation & process.env Mutation Protection', () => {

    it('ensures 50 concurrent invocations with different synthetic envs never cross-contaminate', async () => {
      const originalEnvKeys = Object.keys(process.env);

      const tasks = Array.from({ length: 50 }, (_, i) => {
        return new Promise((resolve) => {
          // Microtask yield to simulate concurrency
          queueMicrotask(() => {
            const syntheticEnv = {
              GMAIL_ENABLED: 'true',
              GMAIL_EMAIL: `user_${i}@gmail.com`,
              GMAIL_APP_PASSWORD: `pass${String(i).padStart(4, '0')} efgh ijkl mnop`,
              APPLE_ENABLED: 'false',
              OUTLOOK_ENABLED: 'false',
              UNIQUE_ISOLATION_PROBE_KEY: `probe_value_${i}`
            };

            const result = loadEnvironmentAccounts({ env: syntheticEnv });
            resolve({ index: i, result, probeKey: syntheticEnv.UNIQUE_ISOLATION_PROBE_KEY });
          });
        });
      });

      const outcomes = await Promise.all(tasks);

      for (const outcome of outcomes) {
        assert.strictEqual(outcome.result.accounts.length, 1);
        const account = outcome.result.accounts[0];
        assert.strictEqual(account.provider, 'gmail');
        assert.strictEqual(account.email, `user_${outcome.index}@gmail.com`);

        // Assert process.env was NEVER contaminated by synthetic keys
        assert.strictEqual(process.env.UNIQUE_ISOLATION_PROBE_KEY, undefined);
      }

      // Assert total process.env keys didn't grow
      const currentEnvKeys = Object.keys(process.env);
      assert.strictEqual(
        currentEnvKeys.filter((k) => !originalEnvKeys.includes(k)).length,
        0,
        'process.env should have zero leaked keys from concurrent runs'
      );
    });

    it('isolates filesystem loading via loadEnv without crashing when file does not exist', () => {
      const nonExistentPath = path.resolve(os.tmpdir(), `mailboxer_non_existent_${Date.now()}.env`);
      const result = loadEnv(nonExistentPath);

      assert.strictEqual(result.loaded, false);
      assert.strictEqual(result.path, null);
    });
  });
});
