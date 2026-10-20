/**
 * Socket Transport Abstraction & TLS Engine
 *
 * Provides abstract socket interface, live TlsSocketTransport with cipher/cert
 * introspection and latency metrics, and hermetic MockSocketTransport for tests.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module connection/transport
 */

import { EventEmitter } from 'node:events';
import tls from 'node:tls';
import net from 'node:net';
import { performance } from 'node:perf_hooks';

/**
 * Valid connection transport lifecycle states.
 */
export const TRANSPORT_STATES = Object.freeze({
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  CLOSING: 'closing',
  CLOSED: 'closed',
  DESTROYED: 'destroyed'
});

/**
 * Default TLS options enforcing modern security baselines.
 */
export const DEFAULT_TLS_OPTIONS = Object.freeze({
  port: 993,
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  rejectUnauthorized: true,
  timeout: 10000
});

/**
 * Resolves SNI servername complying with RFC 6066.
 * IP literals (IPv4/IPv6) must not be transmitted in SNI.
 *
 * @param {string} host Target hostname or IP
 * @param {string} [customServername] Explicit SNI override
 * @returns {string|undefined} Valid servername or undefined
 */
export function resolveServername(host, customServername) {
  if (customServername !== undefined) {
    if (typeof customServername !== 'string' || !customServername.trim()) {
      return undefined;
    }
    const trimmed = customServername.trim();
    if (net.isIP(trimmed) !== 0) {
      return undefined;
    }
    return trimmed;
  }
  if (!host || typeof host !== 'string') {
    return undefined;
  }
  const trimmedHost = host.trim();
  if (net.isIP(trimmedHost) !== 0) {
    return undefined;
  }
  return trimmedHost;
}

/**
 * Universal utility extracting standardized diagnostic TLS details
 * from a TLSSocket, SocketTransport, or mock object.
 *
 * @param {object} source Socket or transport instance
 * @returns {object} Standardized TLS diagnostic details
 */
export function extractTlsDetails(source) {
  if (!source) {
    return {
      protocol: 'Unknown',
      cipherName: 'Unknown',
      cipherVersion: 'Unknown',
      cipherStandardName: 'Unknown',
      authorized: false,
      authorizationError: null,
      alpnProtocol: null,
      certificate: null,
      ephemeralKey: null
    };
  }

  const cipher = typeof source.getCipher === 'function' ? source.getCipher() : (source.cipher || null);
  const protocol = typeof source.getProtocol === 'function' ? source.getProtocol() : (source.protocol || 'Unknown');
  const cert = typeof source.getPeerCertificate === 'function' ? source.getPeerCertificate() : (source.cert || source.certificate || null);
  const authorized = source.authorized === true;
  const authError = source.authorizationError ? String(source.authorizationError) : null;
  const alpnProtocol = source.alpnProtocol || null;
  const ephemeralKey = typeof source.getEphemeralKeyInfo === 'function' ? source.getEphemeralKeyInfo() : (source.ephemeralKey || null);

  return {
    protocol: protocol || 'Unknown',
    cipherName: cipher?.name || 'Unknown',
    cipherVersion: cipher?.version || protocol || 'Unknown',
    cipherStandardName: cipher?.standardName || cipher?.name || 'Unknown',
    authorized,
    authorizationError: authError,
    alpnProtocol,
    certificate: cert && Object.keys(cert).length > 0 ? {
      subjectCN: cert.subject?.CN || 'Unknown',
      subjectOrg: cert.subject?.O || 'Unknown',
      issuerCN: cert.issuer?.CN || 'Unknown',
      issuerOrg: cert.issuer?.O || 'Unknown',
      validFrom: cert.valid_from || '',
      validTo: cert.valid_to || '',
      fingerprint256: cert.fingerprint256 || '',
      serialNumber: cert.serialNumber || ''
    } : null,
    ephemeralKey: ephemeralKey ? {
      type: ephemeralKey.type || 'Unknown',
      name: ephemeralKey.name || 'Unknown',
      size: ephemeralKey.size ?? 0
    } : null
  };
}

/**
 * Abstract Socket Transport Base Class.
 * Extends EventEmitter to provide standard streaming lifecycle events.
 * Can also wrap an existing duplex stream/socket when passed in options.socket.
 */
export class SocketTransport extends EventEmitter {
  constructor(options = {}) {
    super();
    if (new.target === SocketTransport && !options?.socket) {
      throw new TypeError('SocketTransport is an abstract class and cannot be instantiated directly');
    }

    this._state = TRANSPORT_STATES.DISCONNECTED;
    this._socket = options.socket || null;
    this._metrics = {
      connectDurationMs: 0,
      tcpConnectDurationMs: 0,
      tlsHandshakeDurationMs: 0,
      totalDurationMs: 0,
      bytesRead: 0,
      bytesWritten: 0,
      connectedAt: null,
      closedAt: null
    };

    if (this._socket) {
      this._bindSocket(this._socket);
    }
  }

  _bindSocket(sock) {
    this._socket = sock;
    this._state = TRANSPORT_STATES.CONNECTED;
    this._metrics.connectedAt = new Date().toISOString();

    sock.on('data', (chunk) => {
      this._metrics.bytesRead += chunk.length;
      this.emit('data', chunk);
    });

    sock.on('error', (err) => {
      if (this.listenerCount('error') > 0) {
        this.emit('error', err);
      }
    });

    sock.on('close', (hadError) => {
      this._state = TRANSPORT_STATES.CLOSED;
      this._metrics.closedAt = new Date().toISOString();
      this.emit('close', hadError);
    });

    sock.on('timeout', () => {
      this.emit('timeout');
    });

    sock.on('end', () => {
      this.emit('end');
    });
  }

  get state() {
    return this._state;
  }

  get connecting() {
    return this._state === TRANSPORT_STATES.CONNECTING;
  }

  get connected() {
    return this._state === TRANSPORT_STATES.CONNECTED;
  }

  get destroyed() {
    return this._state === TRANSPORT_STATES.DESTROYED || this._state === TRANSPORT_STATES.CLOSED;
  }

  get authorized() {
    return this._socket ? this._socket.authorized === true : true;
  }

  get authorizationError() {
    return this._socket ? (this._socket.authorizationError || null) : null;
  }

  async connect(options = {}) { // eslint-disable-line no-unused-vars
    if (this._socket) {
      this._state = TRANSPORT_STATES.CONNECTED;
      this.emit('connect');
      return this;
    }
    throw new Error('SocketTransport.connect() must be implemented by subclass');
  }

  write(data, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (this._socket) {
      const len = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data, encoding || 'utf8');
      this._metrics.bytesWritten += len;
      return this._socket.write(data, encoding, callback);
    }

    throw new Error('SocketTransport.write() must be implemented by subclass');
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') {
      callback = data;
      data = null;
      encoding = undefined;
    } else if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (this._socket) {
      this._state = TRANSPORT_STATES.CLOSING;
      return this._socket.end(data, encoding, callback);
    }

    throw new Error('SocketTransport.end() must be implemented by subclass');
  }

  destroy(error) {
    if (this._socket) {
      this._state = TRANSPORT_STATES.DESTROYED;
      this._metrics.closedAt = new Date().toISOString();
      if (this._socket.destroy) this._socket.destroy(error);
      if (error && this.listenerCount('error') > 0) this.emit('error', error);
      return this;
    }
    throw new Error('SocketTransport.destroy() must be implemented by subclass');
  }

  setTimeout(ms, callback) {
    if (callback && typeof callback === 'function') {
      this.once('timeout', callback);
    }
    if (this._socket && typeof this._socket.setTimeout === 'function') {
      this._socket.setTimeout(ms);
      return this;
    }
    throw new Error('SocketTransport.setTimeout() must be implemented by subclass');
  }

  getCipher() {
    if (this._socket && typeof this._socket.getCipher === 'function') {
      return this._socket.getCipher();
    }
    return null;
  }

  getProtocol() {
    if (this._socket && typeof this._socket.getProtocol === 'function') {
      return this._socket.getProtocol();
    }
    return null;
  }

  getPeerCertificate(detailed = false) {
    if (this._socket && typeof this._socket.getPeerCertificate === 'function') {
      return this._socket.getPeerCertificate(detailed);
    }
    return null;
  }

  getMetrics() {
    return { ...this._metrics };
  }

  getTlsDetails() {
    return extractTlsDetails(this);
  }
}

/**
 * Production TLS Socket Transport.
 * Wraps node:tls.connect with SNI, TLSv1.2+ enforcement, cipher audit, and telemetry.
 */
export class TlsSocketTransport extends SocketTransport {
  constructor(options = {}) {
    super(options);
    const tlsSub = options.tls || {};
    this._defaultOptions = { ...DEFAULT_TLS_OPTIONS, ...options, ...tlsSub };
    this._socket = null;
    this._connectTimer = null;
    this._connectResolve = null;
    this._connectReject = null;
  }

  _cleanupConnectTimer() {
    if (this._connectTimer) {
      clearTimeout(this._connectTimer);
      this._connectTimer = null;
    }
  }

  _buildTlsOptions(options = {}) {
    const tlsConfig = options.tls || {};
    const customServername = options.servername ?? tlsConfig.servername ?? this._defaultOptions.servername;
    const servername = resolveServername(options.host, customServername);
    const tlsOpts = {
      host: options.host,
      port: options.port ?? tlsConfig.port ?? this._defaultOptions.port,
      servername,
      minVersion: options.minVersion ?? tlsConfig.minVersion ?? this._defaultOptions.minVersion,
      maxVersion: options.maxVersion ?? tlsConfig.maxVersion ?? this._defaultOptions.maxVersion,
      rejectUnauthorized: options.rejectUnauthorized ?? tlsConfig.rejectUnauthorized ?? this._defaultOptions.rejectUnauthorized
    };

    const ca = options.ca ?? tlsConfig.ca ?? this._defaultOptions.ca;
    if (ca !== undefined) {
      tlsOpts.ca = ca;
    }

    if (options.socket || tlsConfig.socket) {
      tlsOpts.socket = options.socket ?? tlsConfig.socket;
    }

    const checkServerIdentity = options.checkServerIdentity ?? tlsConfig.checkServerIdentity ?? this._defaultOptions.checkServerIdentity;
    if (typeof checkServerIdentity === 'function') {
      tlsOpts.checkServerIdentity = checkServerIdentity;
    }

    return tlsOpts;
  }

  async connect(options = {}) {
    if (this._state === TRANSPORT_STATES.CONNECTING || this._state === TRANSPORT_STATES.CONNECTED) {
      throw new Error(`Transport is already ${this._state}`);
    }

    if (!options.socket) {
      if (!options.host || typeof options.host !== 'string') {
        throw new TypeError('Transport connect options must specify a valid string host');
      }
    }

    if (options.port !== undefined) {
      if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
        throw new RangeError('Transport connect options port must be an integer between 1 and 65535');
      }
    }

    this._state = TRANSPORT_STATES.CONNECTING;
    this._metrics.bytesRead = 0;
    this._metrics.bytesWritten = 0;
    this._metrics.connectedAt = null;
    this._metrics.closedAt = null;
    this._metrics.connectDurationMs = 0;
    this._metrics.tcpConnectDurationMs = 0;
    this._metrics.tlsHandshakeDurationMs = 0;
    this._metrics.totalDurationMs = 0;

    const connectStartTime = performance.now();
    let tcpConnectedTime = null;

    return new Promise((resolve, reject) => {
      this._connectResolve = resolve;
      this._connectReject = reject;

      const tlsConfig = options.tls || {};
      const timeoutMs = options.timeout ?? tlsConfig.timeout ?? this._defaultOptions.timeout;

      if (timeoutMs > 0) {
        this._connectTimer = setTimeout(() => {
          const target = options.host ? `${options.host}:${options.port || tlsConfig.port || this._defaultOptions.port}` : 'remote server';
          const err = new Error(`TLS connection to ${target} timed out after ${timeoutMs}ms`);
          err.code = 'ETIMEDOUT';
          this._cleanupConnectTimer();
          this.destroy(err);
          if (this._connectReject) {
            const rej = this._connectReject;
            this._connectReject = null;
            this._connectResolve = null;
            rej(err);
          }
        }, timeoutMs);
        if (this._connectTimer.unref) this._connectTimer.unref();
      }

      const tlsOptions = this._buildTlsOptions(options);

      try {
        this._socket = tls.connect(tlsOptions);
      } catch (err) {
        this._cleanupConnectTimer();
        this._state = TRANSPORT_STATES.DISCONNECTED;
        this._connectResolve = null;
        this._connectReject = null;
        return reject(err);
      }

      this._socket.once('connect', () => {
        tcpConnectedTime = performance.now();
        this._metrics.tcpConnectDurationMs = Math.round((tcpConnectedTime - connectStartTime) * 100) / 100;
      });

      this._socket.once('secureConnect', () => {
        this._cleanupConnectTimer();
        const secureTime = performance.now();
        this._metrics.connectDurationMs = Math.round((secureTime - connectStartTime) * 100) / 100;

        if (tcpConnectedTime !== null) {
          this._metrics.tlsHandshakeDurationMs = Math.round((secureTime - tcpConnectedTime) * 100) / 100;
        } else {
          this._metrics.tlsHandshakeDurationMs = this._metrics.connectDurationMs;
        }
        this._metrics.totalDurationMs = this._metrics.connectDurationMs;

        this._metrics.connectedAt = new Date().toISOString();
        this._state = TRANSPORT_STATES.CONNECTED;

        const res = this._connectResolve;
        this._connectResolve = null;
        this._connectReject = null;

        this.emit('connect');
        if (res) res(this);
      });

      this._socket.on('data', (chunk) => {
        this._metrics.bytesRead += chunk.length;
        this.emit('data', chunk);
      });

      this._socket.on('error', (err) => {
        this._cleanupConnectTimer();
        const wasConnecting = (this._state === TRANSPORT_STATES.CONNECTING);
        if (wasConnecting && this._connectReject) {
          const rej = this._connectReject;
          this._connectReject = null;
          this._connectResolve = null;
          rej(err);
        }
        if (this.listenerCount('error') > 0) {
          this.emit('error', err);
        }
      });

      this._socket.on('close', (hadError) => {
        this._cleanupConnectTimer();
        const wasConnecting = (this._state === TRANSPORT_STATES.CONNECTING);
        this._state = TRANSPORT_STATES.CLOSED;
        this._metrics.closedAt = new Date().toISOString();

        if (wasConnecting && this._connectReject) {
          const rej = this._connectReject;
          this._connectReject = null;
          this._connectResolve = null;
          const err = new Error('Connection closed before TLS handshake completed');
          err.code = 'ECONNRESET';
          rej(err);
        }

        this.emit('close', hadError);
      });

      this._socket.on('timeout', () => {
        this.emit('timeout');
      });

      this._socket.on('end', () => {
        this.emit('end');
      });
    });
  }

  write(data, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (this._state !== TRANSPORT_STATES.CONNECTED || !this._socket) {
      const err = new Error(`Cannot write data: transport is in '${this._state}' state`);
      err.code = 'ERR_SOCKET_NOT_CONNECTED';
      if (callback) {
        queueMicrotask(() => callback(err));
      } else if (this.listenerCount('error') > 0) {
        this.emit('error', err);
      }
      return false;
    }

    const len = Buffer.isBuffer(data)
      ? data.length
      : Buffer.byteLength(data, encoding || 'utf8');
    this._metrics.bytesWritten += len;

    return this._socket.write(data, encoding, callback);
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') {
      callback = data;
      data = null;
      encoding = undefined;
    } else if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (this._state === TRANSPORT_STATES.CLOSED || this._state === TRANSPORT_STATES.DESTROYED) {
      if (callback) queueMicrotask(callback);
      return this;
    }

    this._state = TRANSPORT_STATES.CLOSING;
    if (this._socket && !this._socket.destroyed) {
      this._socket.end(data, encoding, callback);
    } else if (callback) {
      queueMicrotask(callback);
    }
    return this;
  }

  destroy(error) {
    this._cleanupConnectTimer();
    if (this._state === TRANSPORT_STATES.DESTROYED || this._state === TRANSPORT_STATES.CLOSED) {
      return this;
    }

    this._state = TRANSPORT_STATES.DESTROYED;
    this._metrics.closedAt = new Date().toISOString();

    if (this._socket && !this._socket.destroyed) {
      this._socket.destroy(error);
    }

    if (error && this.listenerCount('error') > 0) {
      this.emit('error', error);
    }
    return this;
  }

  setTimeout(ms, callback) {
    if (callback && typeof callback === 'function') {
      this.once('timeout', callback);
    }
    if (this._socket && typeof this._socket.setTimeout === 'function') {
      this._socket.setTimeout(ms);
    }
    return this;
  }

  getCipher() {
    if (!this._socket || typeof this._socket.getCipher !== 'function') {
      return null;
    }
    const cipher = this._socket.getCipher();
    if (!cipher) return null;
    return {
      name: cipher.name || 'Unknown',
      version: cipher.version || 'Unknown',
      standardName: cipher.standardName || cipher.name || 'Unknown'
    };
  }

  getProtocol() {
    if (!this._socket || typeof this._socket.getProtocol !== 'function') {
      return null;
    }
    return this._socket.getProtocol() || null;
  }

  getPeerCertificate(detailed = false) {
    if (!this._socket || typeof this._socket.getPeerCertificate !== 'function') {
      return null;
    }
    try {
      const cert = this._socket.getPeerCertificate(detailed);
      if (!cert || Object.keys(cert).length === 0) return null;
      return cert;
    } catch {
      return null;
    }
  }

  get authorized() {
    return this._socket ? this._socket.authorized === true : false;
  }

  get authorizationError() {
    return this._socket ? (this._socket.authorizationError || null) : null;
  }

  get alpnProtocol() {
    return this._socket ? (this._socket.alpnProtocol || null) : null;
  }
}

/**
 * In-memory Mock Socket Transport for 100% Hermetic Offline Testing.
 * Emulates duplex stream communication, TLS metadata, latency, and timeouts.
 */
export class MockSocketTransport extends SocketTransport {
  constructor(options = {}) {
    super(options);
    this.peer = options.peer || null;
    this._latencyMs = options.latencyMs ?? 0;
    this._mockCipher = options.cipher || {
      name: 'TLS_AES_256_GCM_SHA384',
      version: 'TLSv1.3',
      standardName: 'TLS_AES_256_GCM_SHA384'
    };
    this._mockProtocol = options.protocol || 'TLSv1.3';
    this._mockCert = options.certificate || {
      subject: { CN: 'mock.mail.test', O: 'Mailboxer Mock Authority' },
      issuer: { CN: 'Mailboxer Root CA', O: 'Mailboxer Test Infrastructure' },
      valid_from: 'Jan 01 00:00:00 2026 GMT',
      valid_to: 'Jan 01 00:00:00 2030 GMT',
      fingerprint256: '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
      serialNumber: '1000000000000001'
    };
    this._authorized = options.authorized ?? true;
    this._authorizationError = options.authorizationError ?? null;
    this._inactivityTimer = null;
    this._inactivityTimeoutMs = 0;
  }

  static createPair(options = {}) {
    const client = new MockSocketTransport(options.client || {});
    const server = new MockSocketTransport(options.server || {});
    client.peer = server;
    server.peer = client;
    return [client, server];
  }

  setPeer(peer) {
    this.peer = peer;
    if (peer && peer.peer !== this) {
      peer.peer = this;
    }
  }

  setMockCipher(cipher) {
    this._mockCipher = { ...this._mockCipher, ...cipher };
  }

  setMockProtocol(protocol) {
    this._mockProtocol = protocol;
  }

  setMockCertificate(cert) {
    this._mockCert = { ...this._mockCert, ...cert };
  }

  setMockAuthorized(authorized, error = null) {
    this._authorized = authorized;
    this._authorizationError = error;
  }

  async connect(options = {}) {
    if (this._state === TRANSPORT_STATES.CONNECTING || this._state === TRANSPORT_STATES.CONNECTED) {
      throw new Error(`Transport is already ${this._state}`);
    }

    this._state = TRANSPORT_STATES.CONNECTING;
    const startTime = performance.now();

    return new Promise((resolve, reject) => {
      const finalize = () => {
        if (options.shouldFail) {
          const err = options.failureError || new Error(options.failureMessage || 'Mock connection failed');
          if (options.failureCode) err.code = options.failureCode;
          this._state = TRANSPORT_STATES.CLOSED;
          if (this.listenerCount('error') > 0) this.emit('error', err);
          return reject(err);
        }

        const now = performance.now();
        const duration = Math.round((now - startTime) * 100) / 100;
        this._metrics.connectDurationMs = duration;
        this._metrics.tcpConnectDurationMs = Math.round(duration / 2 * 100) / 100;
        this._metrics.tlsHandshakeDurationMs = Math.round(duration / 2 * 100) / 100;
        this._metrics.totalDurationMs = duration;
        this._metrics.connectedAt = new Date().toISOString();
        this._state = TRANSPORT_STATES.CONNECTED;

        this.emit('connect');
        resolve(this);
      };

      const delay = options.latencyMs ?? this._latencyMs;
      if (delay > 0) {
        setTimeout(finalize, delay);
      } else {
        queueMicrotask(finalize);
      }
    });
  }

  write(data, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (this._state !== TRANSPORT_STATES.CONNECTED) {
      const err = new Error(`Cannot write data: mock transport is in '${this._state}' state`);
      err.code = 'ERR_SOCKET_NOT_CONNECTED';
      if (callback) queueMicrotask(() => callback(err));
      else if (this.listenerCount('error') > 0) this.emit('error', err);
      return false;
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding || 'utf8');
    this._metrics.bytesWritten += buf.length;
    this._resetInactivityTimer();

    if (this.peer && this.peer.state !== TRANSPORT_STATES.DESTROYED && this.peer.state !== TRANSPORT_STATES.CLOSED) {
      queueMicrotask(() => {
        if (this.peer && !this.peer.destroyed) {
          this.peer._receive(buf);
        }
      });
    }

    if (callback) queueMicrotask(callback);
    return true;
  }

  _receive(chunk) {
    this._metrics.bytesRead += chunk.length;
    this._resetInactivityTimer();
    this.emit('data', chunk);
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') {
      callback = data;
      data = null;
      encoding = undefined;
    } else if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    if (data) {
      this.write(data, encoding);
    }

    this._state = TRANSPORT_STATES.CLOSING;
    this._clearInactivityTimer();

    if (this.peer && !this.peer.destroyed) {
      queueMicrotask(() => {
        if (this.peer && !this.peer.destroyed) {
          this.peer.emit('end');
        }
      });
    }

    queueMicrotask(() => {
      this._state = TRANSPORT_STATES.CLOSED;
      this._metrics.closedAt = new Date().toISOString();
      this.emit('close', false);
      if (callback) callback();
    });

    return this;
  }

  destroy(error) {
    this._clearInactivityTimer();
    if (this._state === TRANSPORT_STATES.DESTROYED || this._state === TRANSPORT_STATES.CLOSED) {
      return this;
    }

    this._state = TRANSPORT_STATES.DESTROYED;
    this._metrics.closedAt = new Date().toISOString();

    if (this.peer && !this.peer.destroyed) {
      const peer = this.peer;
      queueMicrotask(() => {
        if (peer && !peer.destroyed) {
          peer.destroy(error);
        }
      });
    }

    if (error && this.listenerCount('error') > 0) {
      this.emit('error', error);
    }
    this.emit('close', !!error);
    return this;
  }

  setTimeout(ms, callback) {
    if (callback && typeof callback === 'function') {
      this.once('timeout', callback);
    }
    this._clearInactivityTimer();
    this._inactivityTimeoutMs = ms;
    if (ms > 0 && this._state === TRANSPORT_STATES.CONNECTED) {
      this._resetInactivityTimer();
    }
    return this;
  }

  emitTimeout() {
    this.emit('timeout');
    return this;
  }

  _clearInactivityTimer() {
    if (this._inactivityTimer) {
      clearTimeout(this._inactivityTimer);
      this._inactivityTimer = null;
    }
  }

  _resetInactivityTimer() {
    this._clearInactivityTimer();
    if (this._inactivityTimeoutMs > 0 && this._state === TRANSPORT_STATES.CONNECTED) {
      this._inactivityTimer = setTimeout(() => {
        this.emit('timeout');
      }, this._inactivityTimeoutMs);
      if (this._inactivityTimer.unref) this._inactivityTimer.unref();
    }
  }

  getCipher() {
    return this._mockCipher ? { ...this._mockCipher } : null;
  }

  getProtocol() {
    return this._mockProtocol;
  }

  getPeerCertificate() {
    return this._mockCert ? { ...this._mockCert } : null;
  }

  get authorized() {
    return this._authorized;
  }

  get authorizationError() {
    return this._authorizationError;
  }
}
