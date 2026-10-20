/**
 * Connection Lifecycle Integration Test Suite (test/integration/connection-lifecycle.test.js)
 *
 * Validates full IMAP connection lifecycle: Connect -> Greeting -> Capability ->
 * Login -> Status INBOX -> Logout across Apple, Google, and Outlook presets.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { getMockAccountConfig } from '../helpers/fixtures.js';
import { MockImapServer } from '../helpers/mock-socket.js';
import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';

describe('Connection Lifecycle Integration (src/connection/imap-client.js)', () => {
  it('executes full happy path for Apple Mail account preset', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({
      scenario: 'happy_path',
      messageCount: 50,
      unseenCount: 2
    });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const stateTransitions = [];
    client.on('stateChange', ({ from, to }) => stateTransitions.push(`${from}->${to}`));

    const result = await client.connectAndVerify();

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.provider, 'apple');
    assert.strictEqual(result.inboxStatus.totalMessages, 50);
    assert.strictEqual(result.inboxStatus.unseen, 2);
    assert.ok(result.capabilities.includes('IMAP4rev1'));

    // Check TLS details
    assert.strictEqual(result.tlsDetails.protocol, 'TLSv1.3');
    assert.strictEqual(result.tlsDetails.cipherName, 'TLS_AES_256_GCM_SHA384');

    // Verify monotonic state transitions
    assert.ok(stateTransitions.includes('DISCONNECTED->CONNECTING'));
    assert.ok(stateTransitions.includes('CONNECTING->CONNECTED'));
    assert.ok(stateTransitions.includes('CONNECTED->AUTHENTICATING'));
    assert.ok(stateTransitions.includes('AUTHENTICATING->AUTHENTICATED'));
    assert.ok(stateTransitions.includes('AUTHENTICATED->QUERYING'));
    assert.ok(stateTransitions.includes('QUERYING->CLOSING'));
    assert.ok(stateTransitions.includes('CLOSING->DISCONNECTED'));
  });

  it('executes full happy path for Google Mail account preset', async () => {
    const config = getMockAccountConfig('gmail');
    const mockServer = new MockImapServer({
      scenario: 'happy_path',
      messageCount: 300,
      unseenCount: 15
    });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const result = await client.connectAndVerify();

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.provider, 'gmail');
    assert.strictEqual(result.inboxStatus.totalMessages, 300);
    assert.strictEqual(result.inboxStatus.unseen, 15);
  });

  it('executes full happy path for Outlook account preset', async () => {
    const config = getMockAccountConfig('outlook');
    const mockServer = new MockImapServer({
      scenario: 'happy_path',
      messageCount: 12,
      unseenCount: 0
    });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const result = await client.connectAndVerify();

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.provider, 'outlook');
    assert.strictEqual(result.inboxStatus.totalMessages, 12);
    assert.strictEqual(result.inboxStatus.unseen, 0);
  });

  it('correctly tracks connect, auth, and total duration metrics', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({ scenario: 'happy_path' });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const result = await client.connectAndVerify();

    assert.ok(typeof result.metrics.connectDurationMs === 'number');
    assert.ok(typeof result.metrics.authDurationMs === 'number');
    assert.ok(typeof result.metrics.totalDurationMs === 'number');
    assert.ok(result.metrics.totalDurationMs >= 0);
  });

  it('handles fragmented line chunks across packet boundaries', async () => {
    const mockServer = new MockImapServer({ autoGreet: false });
    const client = new ImapClient({
      transport: mockServer.getClientSocket()
    });

    const connectPromise = client.connect({ host: 'mock.mail' });

    // Send greeting in fragments
    mockServer.serverSocket.write('* OK Gre');
    await new Promise(r => setTimeout(r, 10));
    mockServer.serverSocket.write('eting banner ready\r\n');

    const greeting = await connectPromise;
    assert.strictEqual(greeting, '* OK Greeting banner ready');

    await client.logout();
  });

  it('defends against CRLF injection in username or password', async () => {
    const client = new ImapClient();
    await assert.rejects(
      async () => {
        await client.login('user@test.com', 'pass\r\nA002 LOGOUT\r\n');
      },
      /CRLF injection prevented/
    );
  });

  it('enforces state transition rules when commands are executed out of order', async () => {
    const client = new ImapClient();
    assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);

    // Cannot send commands while disconnected
    await assert.rejects(
      async () => {
        await client.status('INBOX');
      },
      /unauthenticated state/
    );

    await assert.rejects(
      async () => {
        await client.capability();
      },
      /Cannot query capabilities in state DISCONNECTED/
    );
  });

  it('hasCapability returns true for advertised capabilities and false otherwise', async () => {
    const config = getMockAccountConfig('apple');
    const mockServer = new MockImapServer({
      scenario: 'happy_path',
      capabilities: ['IMAP4REV1', 'IDLE', 'NAMESPACE', 'UIDPLUS']
    });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    await client.connect();
    await client.capability();

    assert.strictEqual(client.hasCapability('IMAP4REV1'), true);
    assert.strictEqual(client.hasCapability('idle'), true); // case-insensitive
    assert.strictEqual(client.hasCapability('NON_EXISTENT'), false);

    await client.logout();
  });

  it('verify method returns DiagnosticResult object without throwing on happy path', async () => {
    const config = getMockAccountConfig('gmail');
    const mockServer = new MockImapServer({ scenario: 'happy_path', messageCount: 88 });

    const client = new ImapClient({
      accountConfig: config,
      transport: mockServer.getClientSocket()
    });

    const diag = await client.verify();
    assert.strictEqual(diag.success, true);
    assert.strictEqual(diag.inboxStatus.totalMessages, 88);
  });

  it('client.logout() transmits RFC 3501 LOGOUT command over wire and closes cleanly (Defect 1)', async () => {
    const mockServer = new MockImapServer({ scenario: 'happy_path' });
    const client = new ImapClient({ transport: mockServer.getClientSocket() });

    await client.connect();
    assert.strictEqual(client.state, IMAP_STATES.CONNECTED);

    const startTime = Date.now();
    await client.logout();
    const duration = Date.now() - startTime;

    // Verify LOGOUT was transmitted over wire
    const logoutReceived = mockServer.commandHistory.some(cmd => cmd.includes('LOGOUT'));
    assert.strictEqual(logoutReceived, true, 'LOGOUT command must be sent to server');

    // Verify state transitioned to DISCONNECTED
    assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);

    // Verify logout did not wait for the 1500ms fallback hang
    assert.ok(duration < 500, `Logout took ${duration}ms, expected fast execution (<500ms) without fallback hang`);
  });

  it('parseStatusResponse matches targetMailbox case-insensitively and returns correct counts (Defect 4)', async () => {
    const { parseStatusResponse } = await import('../../src/connection/imap-client.js');
    const responseLines = [
      '* STATUS "OtherFolder" (MESSAGES 100 UNSEEN 50)',
      '* STATUS "INBOX" (MESSAGES 42 UNSEEN 3 UIDNEXT 1000 UIDVALIDITY 123456)',
      '* STATUS "Archive" (MESSAGES 999 UNSEEN 0)'
    ];

    const inboxStatus = parseStatusResponse(responseLines, 'INBOX');
    assert.strictEqual(inboxStatus.mailbox, 'INBOX');
    assert.strictEqual(inboxStatus.totalMessages, 42);
    assert.strictEqual(inboxStatus.unseen, 3);

    // Case-insensitivity check for INBOX
    const inboxLower = parseStatusResponse(responseLines, 'inbox');
    assert.strictEqual(inboxLower.mailbox, 'INBOX');
    assert.strictEqual(inboxLower.totalMessages, 42);

    // Specific folder query
    const otherStatus = parseStatusResponse(responseLines, 'OtherFolder');
    assert.strictEqual(otherStatus.mailbox, 'OtherFolder');
    assert.strictEqual(otherStatus.totalMessages, 100);

    // Nonexistent folder
    const missing = parseStatusResponse(responseLines, 'NonExistentFolder');
    assert.strictEqual(missing, null);
  });

  it('cleans up prior transport listeners on reconnection preventing EventEmitter leaks (Defect 6)', async () => {
    const mockServer1 = new MockImapServer({ scenario: 'happy_path' });
    const transport1 = mockServer1.getClientSocket();
    const client = new ImapClient({ transport: transport1 });

    await client.connect();
    await client.logout();

    // Reconnect with a second transport instance to verify prior listeners cleaned up
    const mockServer2 = new MockImapServer({ scenario: 'happy_path' });
    const transport2 = mockServer2.getClientSocket();
    await client.connect({ transport: transport2 });
    await client.logout();

    // Transport listener counts should not multiply
    assert.ok(transport1.listenerCount('data') <= 1, 'Data listeners must not leak');
    assert.ok(transport1.listenerCount('error') <= 1, 'Error listeners must not leak');
    assert.ok(transport1.listenerCount('close') <= 1, 'Close listeners must not leak');
    assert.ok(transport2.listenerCount('data') <= 1, 'Data listeners must not leak');
    assert.ok(transport2.listenerCount('error') <= 1, 'Error listeners must not leak');
    assert.ok(transport2.listenerCount('close') <= 1, 'Close listeners must not leak');
  });
});
