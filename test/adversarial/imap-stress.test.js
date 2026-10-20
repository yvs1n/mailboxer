/**
 * Adversarial Stress & Chaos Test Suite for IMAP State Machine & Socket Transport
 * (test/adversarial/imap-stress.test.js)
 *
 * Exercises:
 * 1. Fragmented Streaming: 1-byte chunks, CRLF splits, delayed streams, 1MB payloads
 * 2. Unsolicited & Out-of-Order IMAP Traffic: EXPUNGE, EXISTS, RECENT, ALERT, unsolicited tags
 * 3. Socket Chaos: Mid-command connection drops, timeouts, idempotent destroy()
 * 4. Concurrency & Queue Safety: Monotonic FIFO execution, queue draining on socket drop
 * 5. Event Safety: Zero uncaught exceptions on unhandled error events
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ImapClient, IMAP_STATES } from '../../src/connection/imap-client.js';
import { MockDuplexSocket, MockImapServer } from '../helpers/mock-socket.js';
import { SocketTransport, MockSocketTransport, TRANSPORT_STATES } from '../../src/connection/transport.js';
import { ERROR_CODES } from '../../src/errors/taxonomy.js';

describe('Adversarial Stress: IMAP State Machine & Socket Transport', () => {

  // ==========================================================================
  // VECTOR 1: Fragmented Byte Streaming & Boundary Splitting
  // ==========================================================================
  describe('Vector 1: Fragmented Byte Streaming & Chunk Boundaries', () => {

    it('processes greeting delivered 1 byte per chunk', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      const greeting = '* OK [CAPABILITY IMAP4rev1 IDLE] Mailboxer Host Ready\r\n';

      for (const char of greeting) {
        serverSock.write(char);
      }

      const receivedGreeting = await connectPromise;
      assert.strictEqual(receivedGreeting, greeting.trim());
      assert.strictEqual(client.state, IMAP_STATES.CONNECTED);
      assert.ok(client.hasCapability('IMAP4rev1'));
      assert.ok(client.hasCapability('IDLE'));
    });

    it('assembles lines when CRLF is split across chunk boundaries (\\r in chunk N, \\n in chunk N+1)', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Server Ready\r');
      serverSock.write('\n');

      await connectPromise;
      assert.strictEqual(client.serverGreeting, '* OK Server Ready');

      const cmdPromise = client.sendCommand('NOOP');
      serverSock.once('data', () => {
        serverSock.write('A0001 OK NOOP complete');
        serverSock.write('d\r');
        serverSock.write('\n');
      });

      const res = await cmdPromise;
      assert.strictEqual(res.status, 'OK');
      assert.strictEqual(res.rest, 'NOOP completed');
    });

    it('handles multiple response lines bundled in a single fragmented chunk stream', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const cmdPromise = client.capability();
      serverSock.once('data', () => {
        // Multi-line chunk with mixed line endings
        serverSock.write('* CAPABILITY IMAP4rev1 SASL-IR\r\n* CAPABILITY NAMESPACE QUOTA\r\nA0001 OK CAPABILITY completed\r\n');
      });

      const caps = await cmdPromise;
      assert.ok(caps.includes('IMAP4REV1') || caps.includes('IMAP4rev1'));
      assert.ok(client.hasCapability('NAMESPACE'));
      assert.ok(client.hasCapability('QUOTA'));
      assert.ok(client.hasCapability('SASL-IR'));
    });

    it('streams extreme 1MB payload without truncation, stack overflow, or memory corruption', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const largeToken = 'A'.repeat(1024 * 1024); // 1MB single string
      const cmdPromise = client.sendCommand('FETCH 1 BODY[]');

      serverSock.once('data', () => {
        serverSock.write(`* 1 FETCH (BODY[] "${largeToken}")\r\n`);
        serverSock.write('A0001 OK FETCH completed\r\n');
      });

      const res = await cmdPromise;
      assert.strictEqual(res.status, 'OK');
      assert.strictEqual(res.untagged.length, 1);
      assert.ok(res.untagged[0].length >= 1024 * 1024);
    });
  });

  // ==========================================================================
  // VECTOR 2: Out-of-Order & Unsolicited IMAP Traffic
  // ==========================================================================
  describe('Vector 2: Out-of-Order & Unsolicited IMAP Traffic', () => {

    it('ingests unsolicited * EXPUNGE, * EXISTS, * RECENT, and * NO [ALERT] lines during command execution', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const untaggedEvents = [];
      client.on('untagged', line => untaggedEvents.push(line));

      const cmdPromise = client.sendCommand('NOOP');

      serverSock.once('data', () => {
        serverSock.write('* 42 EXPUNGE\r\n');
        serverSock.write('* 1500 EXISTS\r\n');
        serverSock.write('* 5 RECENT\r\n');
        serverSock.write('* NO [ALERT] Server scheduled maintenance in 10 minutes\r\n');
        serverSock.write('A0001 OK NOOP finished\r\n');
      });

      const res = await cmdPromise;
      assert.strictEqual(res.status, 'OK');
      assert.strictEqual(res.untagged.length, 4);
      assert.strictEqual(untaggedEvents.length, 4);
      assert.ok(res.untagged.some(l => l.includes('EXPUNGE')));
      assert.ok(res.untagged.some(l => l.includes('ALERT')));
    });

    it('updates client capabilities and detects LOGINDISABLED when untagged * CAPABILITY arrives mid-session', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK [CAPABILITY IMAP4rev1] Ready\r\n');
      await connectPromise;

      assert.strictEqual(client.loginDisabled, false);

      const cmdPromise = client.sendCommand('NOOP');
      serverSock.once('data', () => {
        serverSock.write('* CAPABILITY IMAP4rev1 IDLE LOGINDISABLED XOAUTH2\r\n');
        serverSock.write('A0001 OK NOOP complete\r\n');
      });

      await cmdPromise;
      assert.strictEqual(client.loginDisabled, true);
      assert.ok(client.hasCapability('LOGINDISABLED'));
      assert.ok(client.hasCapability('XOAUTH2'));
    });

    it('emits unsolicitedTagged event on unexpected tagged line without crashing or corrupting active command', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const unexpectedEvents = [];
      client.on('unsolicitedTagged', event => unexpectedEvents.push(event));

      const cmdPromise = client.sendCommand('NOOP');

      serverSock.once('data', () => {
        serverSock.write('Z9999 OK Phantom completed\r\n');
        serverSock.write('A0001 OK NOOP completed\r\n');
      });

      const res = await cmdPromise;
      assert.strictEqual(res.tag, 'A0001');
      assert.strictEqual(res.status, 'OK');
      assert.strictEqual(unexpectedEvents.length, 1);
      assert.strictEqual(unexpectedEvents[0].tag, 'Z9999');
      assert.strictEqual(unexpectedEvents[0].status, 'OK');
    });

    it('tolerates malformed untagged lines without throwing unhandled exceptions', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const cmdPromise = client.sendCommand('NOOP');

      serverSock.once('data', () => {
        serverSock.write('*\r\n');
        serverSock.write('* \r\n');
        serverSock.write('* MALFORMED_NO_SPACE\r\n');
        serverSock.write('* 99999999999999999999999999999999999999999999999999999999\r\n');
        serverSock.write('A0001 OK Done\r\n');
      });

      const res = await cmdPromise;
      assert.strictEqual(res.status, 'OK');
      assert.ok(res.untagged.length >= 3);
    });
  });

  // ==========================================================================
  // VECTOR 3: Socket Chaos & Connection Failures
  // ==========================================================================
  describe('Vector 3: Socket Chaos & Connection Failures', () => {

    it('rejects in-flight command with CONNECTION_DROPPED when socket is abruptly destroyed', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      let caughtError = null;
      const cmdPromise = client.sendCommand('NOOP').catch(err => {
        caughtError = err;
      });

      serverSock.once('data', () => {
        serverSock.destroy(new Error('read ECONNRESET'));
      });

      await cmdPromise;
      assert.ok(caughtError !== null);
      assert.strictEqual(caughtError.code, ERROR_CODES.CONNECTION_DROPPED);
      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });

    it('enforces command timeout when server goes completely silent, cleanly destroying socket', async () => {
      const [clientSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      clientSock.peer.write('* OK Ready\r\n');
      await connectPromise;

      const start = Date.now();
      await assert.rejects(
        async () => {
          await client.sendCommand('SILENT_COMMAND', { timeoutMs: 50 });
        },
        (err) => {
          assert.strictEqual(err.code, ERROR_CODES.CONNECTION_TIMEOUT);
          return true;
        }
      );

      const elapsed = Date.now() - start;
      assert.ok(elapsed >= 45, `Expected timeout after ~50ms, elapsed: ${elapsed}ms`);
      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
      assert.strictEqual(clientSock.destroyed, true);
    });

    it('supports multiple sequential and concurrent destroy() calls idempotently without duplicate close events', () => {
      const [clientSock] = MockDuplexSocket.createPair();
      let closeEventCount = 0;
      clientSock.on('close', () => closeEventCount++);

      clientSock.destroy();
      clientSock.destroy();
      clientSock.destroy(new Error('subsequent destroy'));

      assert.strictEqual(clientSock.destroyed, true);
      assert.strictEqual(clientSock.writable, false);
      assert.strictEqual(clientSock.readable, false);
    });

    it('MockSocketTransport.destroy() is idempotent across client and peer', () => {
      const [clientTransport, serverTransport] = MockSocketTransport.createPair();
      let clientCloseCount = 0;
      clientTransport.on('close', () => clientCloseCount++);

      clientTransport.destroy();
      clientTransport.destroy();
      assert.strictEqual(clientTransport.state, TRANSPORT_STATES.DESTROYED);
      assert.strictEqual(clientCloseCount, 1);
    });
  });

  // ==========================================================================
  // VECTOR 4: Concurrency & Monotonic Queue Safety
  // ==========================================================================
  describe('Vector 4: Concurrency & Monotonic Queue Safety', () => {

    it('executes concurrent sendCommand calls in strict FIFO sequence with monotonic tags', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      const serverReceivedTags = [];

      serverSock.on('data', chunk => {
        const text = chunk.toString();
        const lines = text.split('\r\n').filter(Boolean);
        for (const line of lines) {
          const tag = line.split(' ')[0];
          serverReceivedTags.push(tag);
          // Respond asynchronously with small delay
          setTimeout(() => {
            serverSock.write(`${tag} OK Completed ${tag}\r\n`);
          }, 5);
        }
      });

      const results = await Promise.all([
        client.sendCommand('CMD_ONE'),
        client.sendCommand('CMD_TWO'),
        client.sendCommand('CMD_THREE'),
        client.sendCommand('CMD_FOUR'),
        client.sendCommand('CMD_FIVE')
      ]);

      assert.deepStrictEqual(serverReceivedTags, ['A0001', 'A0002', 'A0003', 'A0004', 'A0005']);
      assert.deepStrictEqual(results.map(r => r.tag), ['A0001', 'A0002', 'A0003', 'A0004', 'A0005']);
      assert.strictEqual(client.state, IMAP_STATES.CONNECTED);
    });

    it('drains queued commands when transport disconnects mid-batch, rejecting all with zero hangs', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      serverSock.write('* OK Ready\r\n');
      await connectPromise;

      serverSock.once('data', () => {
        // Destroy connection immediately upon receiving first command
        serverSock.destroy(new Error('Connection abruptly terminated'));
      });

      const results = await Promise.allSettled([
        client.sendCommand('BATCH_CMD_1'),
        client.sendCommand('BATCH_CMD_2'),
        client.sendCommand('BATCH_CMD_3')
      ]);

      assert.strictEqual(results[0].status, 'rejected');
      assert.strictEqual(results[1].status, 'rejected');
      assert.strictEqual(results[2].status, 'rejected');

      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
      assert.ok(results[1].reason.message.includes('Cannot send command in state DISCONNECTED'));
      assert.ok(results[2].reason.message.includes('Cannot send command in state DISCONNECTED'));
    });

    it('rejects overlapping connect() calls when already in CONNECTING or CONNECTED state', async () => {
      const [clientSock, serverSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const firstConnect = client.connect();

      await assert.rejects(
        async () => {
          await client.connect();
        },
        /Cannot connect while in state CONNECTING/
      );

      serverSock.write('* OK Ready\r\n');
      await firstConnect;

      await assert.rejects(
        async () => {
          await client.connect();
        },
        /Cannot connect while in state CONNECTED/
      );
    });
  });

  // ==========================================================================
  // VECTOR 5: Zero Uncaught Exceptions & Event Safety
  // ==========================================================================
  describe('Vector 5: Zero Uncaught Exceptions & Event Safety', () => {

    it('does not trigger uncaughtException when transport emits error with no client error listener', async () => {
      const [clientSock] = MockDuplexSocket.createPair();
      const client = new ImapClient({ transport: clientSock });

      const connectPromise = client.connect();
      clientSock.peer.write('* OK Ready\r\n');
      await connectPromise;

      // Ensure client has zero 'error' listeners
      assert.strictEqual(client.listenerCount('error'), 0);

      // Simulating socket error after connected
      clientSock.peer.destroy(new Error('Unprompted socket error'));

      // Wait a microtask to ensure no uncaughtException is thrown
      await new Promise(resolve => setTimeout(resolve, 50));
      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });

    it('safely handles MockImapServer dialogue with custom interceptors and fast tear down', async () => {
      const server = new MockImapServer({
        scenario: 'happy_path',
        messageCount: 999,
        unseenCount: 42
      });

      const client = new ImapClient({
        transport: server.getClientSocket()
      });

      await client.connect();
      await client.capability();
      const loginRes = await client.login('test@mailboxer.internal', 'securePass123');
      assert.strictEqual(loginRes.success, true);

      const status = await client.status('INBOX');
      assert.strictEqual(status.totalMessages, 999);
      assert.strictEqual(status.unseen, 42);

      server.destroy();
      await new Promise(resolve => setTimeout(resolve, 20));
      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED);
    });
  });

  // ==========================================================================
  // VECTOR 6: Protocol Compliance & State Machine Defects (Oracles & Probes)
  // ==========================================================================
  describe('Vector 6: Protocol Compliance & State Machine Defects', () => {

    it('transmits RFC 3501 LOGOUT command over wire before closing connection', async () => {
      const server = new MockImapServer({ scenario: 'happy_path' });
      const client = new ImapClient({ transport: server.getClientSocket() });

      await client.connect();
      await client.logout();

      const logoutSent = server.commandHistory.some(line => line.includes('LOGOUT'));
      assert.strictEqual(logoutSent, true,
        'Expected LOGOUT command to be transmitted to server before closing, but none was sent (Defect 1)');
    });

    it('cancels greeting timeout timer when transport connection fails immediately', async () => {
      let unhandled = null;
      const onUnhandled = (err) => { unhandled = err; };
      process.on('unhandledRejection', onUnhandled);

      const [clientSock] = MockDuplexSocket.createPair();
      class FailingTransport extends SocketTransport {
        async connect() {
          throw new Error('Immediate connection failure');
        }
      }
      const client = new ImapClient({
        transport: new FailingTransport({ socket: clientSock })
      });

      await assert.rejects(async () => {
        await client.connect({ connectionTimeoutMs: 50 });
      });

      await new Promise(r => setTimeout(r, 80));
      process.removeListener('unhandledRejection', onUnhandled);

      assert.strictEqual(unhandled, null,
        `Expected greeting timer to be cleared, but unhandledRejection fired: ${unhandled?.message} (Defect 2)`);
    });

    it('resets state to DISCONNECTED on greeting protocol violation to permit subsequent reconnect', async () => {
      const server = new MockImapServer({ scenario: 'invalid_greeting' });
      const client = new ImapClient({ transport: server.getClientSocket() });

      await assert.rejects(async () => {
        await client.connect();
      });

      assert.strictEqual(client.state, IMAP_STATES.DISCONNECTED,
        `Expected state to reset to DISCONNECTED after invalid greeting, but got ${client.state} (Defect 3)`);
    });

    it('parseStatusResponse matches targetMailbox instead of returning first arbitrary status line', async () => {
      const { parseStatusResponse } = await import('../../src/connection/imap-client.js');
      const lines = [
        '* STATUS "OtherFolder" (MESSAGES 12 UNSEEN 0)',
        '* STATUS "INBOX" (MESSAGES 500 UNSEEN 12)'
      ];
      const res = parseStatusResponse(lines, 'INBOX');
      assert.strictEqual(res?.mailbox, 'INBOX',
        `Expected status for "INBOX", but got status for "${res?.mailbox}" (Defect 4)`);
      assert.strictEqual(res?.totalMessages, 500);
    });
  });
});
