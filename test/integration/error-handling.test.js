/**
 * Error Handling Integration Test Suite (test/integration/error-handling.test.js)
 *
 * Validates error classification and recovery across timeouts, socket drops,
 * app-password alerts, tenant policy blocks, and invalid responses.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { getMockAccountConfig } from '../helpers/fixtures.js';
import { MockImapServer } from '../helpers/mock-socket.js';
import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';
import { SocketTransport } from '../../src/connection/transport.js';
import { ERROR_CODES, MailboxerError } from '../../src/errors/taxonomy.js';

describe('Error Handling Integration (src/connection/imap-client.js)', () => {
  it('catches and classifies Google App Password requirement with remediation', async () => {
    const config = getMockAccountConfig('gmail');
    const mockServer = new MockImapServer({ scenario: 'app_password_google' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
        assert.ok(err.remediation.includes('myaccount.google.com/apppasswords'));
        return true;
      }
    );
  });

  it('catches and classifies Apple Mail authentication failure as AUTH_APP_PASSWORD_REQUIRED', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'app_password_apple' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
        assert.ok(err.remediation.includes('appleid.apple.com'));
        return true;
      }
    );
  });

  it('catches and classifies Microsoft Outlook basic auth block as AUTH_TENANT_POLICY_BLOCKED', async () => {
    const config = getMockAccountConfig('outlook');
    const mockServer = new MockImapServer({ scenario: 'tenant_blocked_outlook' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.AUTH_TENANT_POLICY_BLOCKED);
        assert.ok(err.remediation.includes('OAuth2'));
        return true;
      }
    );
  });

  it('catches and classifies generic invalid credentials as AUTH_INVALID_CREDENTIALS', async () => {
    const config = getMockAccountConfig('gmail');
    const mockServer = new MockImapServer({ scenario: 'auth_fail' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.AUTH_INVALID_CREDENTIALS);
        return true;
      }
    );
  });

  it('catches and classifies abrupt socket drop mid-session as CONNECTION_DROPPED', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'socket_drop' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.CONNECTION_DROPPED);
        return true;
      }
    );
  });

  it('catches and classifies connection timeout as CONNECTION_TIMEOUT', async () => {
    const config = getMockAccountConfig('apple', {
      imap: { connectionTimeoutMs: 25, authTimeoutMs: 25 }
    });
    const mockServer = new MockImapServer({ scenario: 'connection_timeout' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket(),
      timeoutMs: 25
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.CONNECTION_TIMEOUT);
        return true;
      }
    );
  });

  it('catches and classifies HTTP/non-IMAP banner as PROTOCOL_VIOLATION', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'invalid_greeting' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.PROTOCOL_VIOLATION);
        return true;
      }
    );
  });

  it('catches and classifies server maintenance as SERVER_TEMPORARILY_UNAVAILABLE', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'server_unavailable' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.SERVER_TEMPORARILY_UNAVAILABLE);
        return true;
      }
    );
  });

  it('catches and classifies nonexistent mailbox as MAILBOX_NOT_FOUND', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'mailbox_not_found' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connectAndVerify();
      },
      (err) => {
        assert.ok(err instanceof MailboxerError);
        assert.strictEqual(err.code, ERROR_CODES.MAILBOX_NOT_FOUND);
        return true;
      }
    );
  });

  it('verify method catches errors gracefully and returns DiagnosticResult payload with error info', async () => {
    const config = getMockAccountConfig('gmail');
    const mockServer = new MockImapServer({ scenario: 'app_password_google' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const result = await client.verify();

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.accountId, config.id);
    assert.strictEqual(result.provider, 'gmail');
    assert.ok(result.error);
    assert.strictEqual(result.error.code, ERROR_CODES.AUTH_APP_PASSWORD_REQUIRED);
    assert.ok(result.error.remediationAdvice.includes('myaccount.google.com/apppasswords'));
  });

  it('clears greeting timeout timer on immediate connection failure, avoiding unhandledRejection (Defect 2)', async () => {
    let unhandledRejectionDetected = null;
    const handler = (reason) => { unhandledRejectionDetected = reason; };
    process.on('unhandledRejection', handler);

    class FailingSocketTransport extends SocketTransport {
      constructor() {
        super({ socket: null });
      }
      async connect() {
        throw new Error('Immediate connection refused');
      }
      destroy() {
        this._state = 'closed';
      }
    }

    const client = new ImapClient({
      transport: new FailingSocketTransport()
    });

    await assert.rejects(
      async () => {
        await client.connect({ connectionTimeoutMs: 60 });
      },
      /Immediate connection refused/
    );

    // Wait past the greeting timeout (60ms) to ensure timer does not fire
    await new Promise(r => setTimeout(r, 100));
    process.removeListener('unhandledRejection', handler);

    assert.strictEqual(unhandledRejectionDetected, null, 'Must not trigger unhandledRejection');
    assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
  });

  it('resets state to DISCONNECTED on greeting failure to permit subsequent reconnect (Defect 3)', async () => {
    const mockServer = new MockImapServer({ scenario: 'invalid_greeting' });
    const client = new ImapClient({
      transport: mockServer.getClientSocket()
    });

    await assert.rejects(
      async () => {
        await client.connect();
      },
      (err) => {
        assert.strictEqual(err.code, ERROR_CODES.PROTOCOL_VIOLATION);
        return true;
      }
    );

    // State MUST be reset to DISCONNECTED, not left stuck in CONNECTING
    assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED, 'State must reset to DISCONNECTED');

    // A subsequent connection attempt must not fail with "Cannot connect while in state CONNECTING"
    const server2 = new MockImapServer({ scenario: 'happy_path' });
    const greeting = await client.connect({ transport: server2.getClientSocket() });
    assert.ok(greeting.includes('Ready'));
    assert.strictEqual(client.state, IMAP_STATES.CONNECTED);
    await client.logout();
  });
});
