/**
 * CLI Diagnostics Unit & Integration Test Suite (test/unit/verify-cli.test.js)
 *
 * Validates the standalone verify CLI runner:
 * - Graceful exit on missing credentials
 * - Flag handling (--help, --json, --env, --account)
 * - Safe error reporting without unhandled exceptions
 * - JSON output schema validation
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runDiagnostics } from '../../bin/verify.js';

describe('Diagnostic Runner CLI (bin/verify.js)', () => {
  it('exits cleanly with code 0 and unconfigured status when no accounts are set', async () => {
    // Pass non-existent env path so no accounts are loaded
    const { exitCode, results } = await runDiagnostics(['--env', '.env.nonexistent', '--json']);

    assert.strictEqual(exitCode, 0);
    assert.strictEqual(results.length, 0);
  });

  it('handles --help flag cleanly and exits with code 0', async () => {
    const { exitCode } = await runDiagnostics(['--help']);
    assert.strictEqual(exitCode, 0);
  });

  it('handles -h flag cleanly and exits with code 0', async () => {
    const { exitCode } = await runDiagnostics(['-h']);
    assert.strictEqual(exitCode, 0);
  });

  it('outputs valid JSON schema when --json flag is supplied with unconfigured env', async () => {
    let capturedOutput = '';
    const originalLog = console.log;
    try {
      console.log = (str) => {
        capturedOutput += str;
      };

      const { exitCode } = await runDiagnostics(['--env', '.env.nonexistent', '--json']);
      assert.strictEqual(exitCode, 0);

      const parsed = JSON.parse(capturedOutput);
      assert.strictEqual(parsed.status, 'unconfigured');
      assert.strictEqual(parsed.totalConfigured, 0);
      assert.ok(Array.isArray(parsed.unconfigured));
    } finally {
      console.log = originalLog;
    }
  });

  it('gracefully filters by non-existent account name without throwing', async () => {
    const { exitCode, results } = await runDiagnostics(['--account', 'nonexistent_account']);
    assert.strictEqual(exitCode, 0);
    assert.strictEqual(results.length, 0);
  });
});
