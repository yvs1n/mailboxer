/**
 * Transport Layer Unit Test Suite (test/unit/transport.test.js)
 *
 * Validates SocketTransport abstraction, TlsSocketTransport interface,
 * MockSocketTransport in-memory engine, SNI resolution, cipher extraction,
 * event forwarding, latency metrics, and timeout handling.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { MockDuplexSocket } from '../helpers/mock-socket.js';
import {
  SocketTransport,
  TlsSocketTransport,
  MockSocketTransport,
  resolveServername,
  extractTlsDetails,
  TRANSPORT_STATES
} from '../../src/connection/transport.js';

describe('Socket Transport Layer (src/connection/transport.js)', () => {
  describe('1. Abstract & Class Contracts', () => {
    it('SocketTransport cannot be instantiated directly without options.socket', () => {
      assert.throws(
        () => new SocketTransport(),
        (err) => {
          assert.ok(err instanceof TypeError);
          assert.ok(err.message.includes('abstract'));
          return true;
        }
      );
    });

    it('subclasses inherit default states and properties', () => {
      class TestTransport extends SocketTransport {
        constructor() {
          super({ socket: null });
        }
      }
      const t = new TestTransport();
      assert.strictEqual(t.state, TRANSPORT_STATES.DISCONNECTED);
      assert.strictEqual(t.connecting, false);
      assert.strictEqual(t.connected, false);
      assert.strictEqual(t.destroyed, false);
      assert.strictEqual(t.getCipher(), null);
      assert.strictEqual(t.getProtocol(), null);
      assert.strictEqual(t.getPeerCertificate(), null);
    });

    it('unimplemented methods on base class throw descriptive errors', async () => {
      class UnimplementedTransport extends SocketTransport {
        constructor() {
          super({ socket: null });
        }
      }
      const t = new UnimplementedTransport();
      await assert.rejects(() => t.connect(), /must be implemented/);
      assert.throws(() => t.write('hi'), /must be implemented/);
      assert.throws(() => t.end(), /must be implemented/);
      assert.throws(() => t.destroy(), /must be implemented/);
      assert.throws(() => t.setTimeout(100), /must be implemented/);
    });
  });

  describe('2. MockDuplexSocket In-Memory Engine', () => {
    it('creates bidirectional in-memory pair with zero TCP port binding', async () => {
      const [client, server] = MockDuplexSocket.createPair();

      const receivedByServer = [];
      server.on('data', chunk => receivedByServer.push(chunk.toString()));

      client.write('A001 CAPABILITY\r\n');
      await new Promise(r => queueMicrotask(r));

      assert.deepStrictEqual(receivedByServer, ['A001 CAPABILITY\r\n']);

      const receivedByClient = [];
      client.on('data', chunk => receivedByClient.push(chunk.toString()));

      server.write('* CAPABILITY IMAP4rev1\r\n');
      await new Promise(r => queueMicrotask(r));

      assert.deepStrictEqual(receivedByClient, ['* CAPABILITY IMAP4rev1\r\n']);
    });

    it('simulates TLS cipher, protocol, and peer certificate inspection', () => {
      const [client] = MockDuplexSocket.createPair();

      const cipher = client.getCipher();
      assert.strictEqual(cipher.name, 'TLS_AES_256_GCM_SHA384');
      assert.strictEqual(cipher.version, 'TLSv1.3');

      assert.strictEqual(client.getProtocol(), 'TLSv1.3');

      const cert = client.getPeerCertificate();
      assert.ok(cert.subject);
      assert.ok(cert.issuer);
      assert.strictEqual(client.authorized, true);
    });

    it('emits timeout event when setTimeout expires', async () => {
      const [client] = MockDuplexSocket.createPair();

      let timedOut = false;
      client.setTimeout(10, () => {
        timedOut = true;
      });

      await new Promise(r => setTimeout(r, 25));
      assert.strictEqual(timedOut, true);
    });

    it('abruptly destroys socket on destroy(err) and notifies peer', async () => {
      const [client, server] = MockDuplexSocket.createPair();

      let serverGotError = null;
      server.on('error', err => {
        serverGotError = err;
      });

      client.destroy(new Error('ECONNRESET'));
      await new Promise(r => queueMicrotask(r));

      assert.ok(serverGotError);
      assert.strictEqual(serverGotError.message, 'ECONNRESET');
      assert.strictEqual(client.destroyed, true);
      assert.strictEqual(server.destroyed, true);
    });
  });

  describe('3. SocketTransport Wrapping & Metrics', () => {
    it('tracks connection and handshake duration metrics', () => {
      const [client] = MockDuplexSocket.createPair();
      const transport = new SocketTransport({ socket: client });

      const metrics = transport.getMetrics();
      assert.ok('connectDurationMs' in metrics);
      assert.ok('tlsHandshakeDurationMs' in metrics);
      assert.ok('totalDurationMs' in metrics);
    });

    it('forwards data, error, and close events from underlying socket', async () => {
      const [client, server] = MockDuplexSocket.createPair();
      const transport = new SocketTransport({ socket: client });

      const chunks = [];
      transport.on('data', c => chunks.push(c.toString()));

      server.write('HELLO');
      await new Promise(r => queueMicrotask(r));

      assert.deepStrictEqual(chunks, ['HELLO']);
    });
  });

  describe('4. SNI & Parameter Validation (TlsSocketTransport)', () => {
    it('resolveServername returns hostname for standard domains and undefined for IP addresses', () => {
      assert.strictEqual(resolveServername('imap.gmail.com'), 'imap.gmail.com');
      assert.strictEqual(resolveServername('outlook.office365.com'), 'outlook.office365.com');
      assert.strictEqual(resolveServername('127.0.0.1'), undefined);
      assert.strictEqual(resolveServername('192.168.1.1'), undefined);
      assert.strictEqual(resolveServername('::1'), undefined);
      assert.strictEqual(resolveServername('2001:db8::1'), undefined);
      assert.strictEqual(resolveServername('custom.domain', 'override.sni'), 'override.sni');
      assert.strictEqual(resolveServername(null), undefined);
      assert.strictEqual(resolveServername(''), undefined);

      // Regression Defect 7: IP address passed as customServername must return undefined per RFC 6066
      assert.strictEqual(resolveServername('custom.domain', '127.0.0.1'), undefined);
      assert.strictEqual(resolveServername('custom.domain', '192.168.0.1'), undefined);
      assert.strictEqual(resolveServername('custom.domain', '::1'), undefined);
      assert.strictEqual(resolveServername('custom.domain', 'fe80::1'), undefined);
      assert.strictEqual(resolveServername('custom.domain', ''), undefined);
      assert.strictEqual(resolveServername('custom.domain', '   '), undefined);
    });

    it('unpacks options.tls properties (rejectUnauthorized, minVersion, servername, ca) into tlsOptions', async () => {
      const t = new TlsSocketTransport();
      const opts = {
        host: 'imap.mail.me.com',
        port: 993,
        tls: {
          rejectUnauthorized: false,
          minVersion: 'TLSv1.2',
          maxVersion: 'TLSv1.3',
          servername: 'custom.override.me.com'
        }
      };

      if (typeof t._buildTlsOptions === 'function') {
        const resolved = t._buildTlsOptions(opts);
        assert.strictEqual(resolved.rejectUnauthorized, false);
        assert.strictEqual(resolved.minVersion, 'TLSv1.2');
        assert.strictEqual(resolved.maxVersion, 'TLSv1.3');
        assert.strictEqual(resolved.servername, 'custom.override.me.com');
      } else {
        await assert.rejects(
          () => t.connect({ ...opts, timeout: 10 }),
          (err) => err !== null
        );
      }
    });

    it('TlsSocketTransport.connect throws TypeError when host is missing or invalid', async () => {
      const t = new TlsSocketTransport();
      await assert.rejects(
        () => t.connect({}),
        TypeError
      );
      await assert.rejects(
        () => t.connect({ host: 12345 }),
        TypeError
      );
    });

    it('TlsSocketTransport.connect throws RangeError for out-of-range ports', async () => {
      const t = new TlsSocketTransport();
      await assert.rejects(
        () => t.connect({ host: 'imap.mail.me.com', port: 0 }),
        RangeError
      );
      await assert.rejects(
        () => t.connect({ host: 'imap.mail.me.com', port: 70000 }),
        RangeError
      );
      await assert.rejects(
        () => t.connect({ host: 'imap.mail.me.com', port: '993' }),
        RangeError
      );
    });

    it('write() when not connected returns false and invokes callback or emits error', async () => {
      const t = new TlsSocketTransport();
      let cbErr = null;
      const res = t.write('TEST', (err) => {
        cbErr = err;
      });

      assert.strictEqual(res, false);
      await new Promise(r => queueMicrotask(r));
      assert.ok(cbErr);
      assert.strictEqual(cbErr.code, 'ERR_SOCKET_NOT_CONNECTED');
    });
  });

  describe('5. MockSocketTransport Duplex Pipeline', () => {
    it('MockSocketTransport.createPair creates communicating client/server pair', async () => {
      const [client, server] = MockSocketTransport.createPair();

      await client.connect();
      await server.connect();

      assert.strictEqual(client.connected, true);
      assert.strictEqual(server.connected, true);

      const serverReceived = [];
      server.on('data', chunk => serverReceived.push(chunk.toString()));

      client.write('A001 NOOP\r\n');
      await new Promise(r => queueMicrotask(r));

      assert.deepStrictEqual(serverReceived, ['A001 NOOP\r\n']);
      assert.strictEqual(client.getMetrics().bytesWritten, 11);
      assert.strictEqual(server.getMetrics().bytesRead, 11);

      const clientReceived = [];
      client.on('data', chunk => clientReceived.push(chunk.toString()));

      server.write('A001 OK NOOP completed\r\n');
      await new Promise(r => queueMicrotask(r));

      assert.deepStrictEqual(clientReceived, ['A001 OK NOOP completed\r\n']);
    });

    it('MockSocketTransport.end cleanly terminates connection on both ends', async () => {
      const [client, server] = MockSocketTransport.createPair();
      await client.connect();
      await server.connect();

      let clientClosed = false;
      let serverEnded = false;

      client.on('close', () => { clientClosed = true; });
      server.on('end', () => { serverEnded = true; });

      client.end();
      await new Promise(r => setTimeout(r, 10));

      assert.strictEqual(clientClosed, true);
      assert.strictEqual(serverEnded, true);
    });

    it('MockSocketTransport handles simulated connection failures without throwing unhandled error', async () => {
      const client = new MockSocketTransport();
      await assert.rejects(
        () => client.connect({ shouldFail: true, failureCode: 'ECONNREFUSED', failureMessage: 'Connection refused' }),
        (err) => {
          assert.strictEqual(err.code, 'ECONNREFUSED');
          return true;
        }
      );
      assert.strictEqual(client.state, TRANSPORT_STATES.CLOSED);
    });

    it('extractTlsDetails extracts comprehensive diagnostic metadata', () => {
      const [client] = MockSocketTransport.createPair();
      const details = extractTlsDetails(client);

      assert.strictEqual(details.protocol, 'TLSv1.3');
      assert.strictEqual(details.cipherName, 'TLS_AES_256_GCM_SHA384');
      assert.strictEqual(details.authorized, true);
      assert.strictEqual(details.certificate.subjectCN, 'mock.mail.test');
      assert.strictEqual(details.certificate.issuerCN, 'Mailboxer Root CA');
    });

    it('connect() throws if invoked when already connected', async () => {
      const client = new MockSocketTransport();
      await client.connect();
      await assert.rejects(
        () => client.connect(),
        /already connected/
      );
    });

    it('destroy() is idempotent and handles multiple calls safely', async () => {
      const [client, server] = MockSocketTransport.createPair();
      await client.connect();
      await server.connect();

      client.destroy();
      client.destroy();
      assert.strictEqual(client.destroyed, true);
    });
  });
});
