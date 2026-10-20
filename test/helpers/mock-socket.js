/**
 * In-Memory Duplex Socket Mock Engine (test/helpers/mock-socket.js)
 *
 * Zero-dependency, offline stream simulator for IMAP4rev1 dialogues.
 * Provides MockDuplexSocket and MockImapServer supporting scripted scenarios
 * and custom protocol interceptors.
 *
 * @module test/helpers/mock-socket
 */

import { EventEmitter } from 'node:events';

/**
 * In-memory duplex socket pair simulating a bidirectional TCP/TLS socket.
 */
export class MockDuplexSocket extends EventEmitter {
  constructor(options = {}) {
    super();
    this.peer = null;
    this.destroyed = false;
    this.writable = true;
    this.readable = true;

    // Mock TLS details
    this.cipher = options.cipher || {
      name: 'TLS_AES_256_GCM_SHA384',
      version: 'TLSv1.3',
      standardName: 'TLS_AES_256_GCM_SHA384'
    };
    this.protocol = options.protocol || 'TLSv1.3';
    this.cert = options.cert || {
      subject: { CN: options.host || 'imap.mock.internal', O: 'Mailboxer Mock Authority' },
      issuer: { CN: 'Mailboxer Test CA', O: 'Mailboxer Trust' },
      valid_from: 'Jan 1 00:00:00 2026 GMT',
      valid_to: 'Jan 1 00:00:00 2030 GMT',
      fingerprint256: '01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF'
    };
    this.authorized = options.authorized !== false;
    this.authorizationError = options.authorizationError || null;

    this._timer = null;
    this._timeoutMs = 0;
  }

  /**
   * Creates a connected pair of client and server mock sockets.
   *
   * @param {Object} [options={}]
   * @returns {[MockDuplexSocket, MockDuplexSocket]} [client, server]
   */
  static createPair(options = {}) {
    const client = new MockDuplexSocket(options);
    const server = new MockDuplexSocket(options);
    client.peer = server;
    server.peer = client;
    return [client, server];
  }

  /**
   * Writes data into the socket, delivering it to the peer via microtask.
   *
   * @param {string|Buffer} data
   * @param {string|Function} [encoding]
   * @param {Function} [cb]
   * @returns {boolean}
   */
  write(data, encoding, cb) {
    if (typeof encoding === 'function') {
      cb = encoding;
      encoding = undefined;
    }
    if (this.destroyed) {
      if (cb) queueMicrotask(() => cb(new Error('Cannot call write after socket destroyed')));
      return false;
    }

    const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding || 'utf8');

    if (this.peer && !this.peer.destroyed) {
      queueMicrotask(() => {
        if (!this.peer.destroyed) {
          this.peer.emit('data', chunk);
        }
      });
    }

    if (cb) queueMicrotask(cb);
    return true;
  }

  /**
   * Closes the socket gracefully.
   *
   * @param {string|Buffer} [chunk]
   * @param {string|Function} [encoding]
   * @param {Function} [cb]
   */
  end(chunk, encoding, cb) {
    if (typeof chunk === 'function') {
      cb = chunk;
      chunk = null;
    } else if (typeof encoding === 'function') {
      cb = encoding;
      encoding = undefined;
    }

    if (chunk) {
      this.write(chunk, encoding);
    }

    this.writable = false;
    this.clearTimeout();

    if (this.peer && !this.peer.destroyed) {
      queueMicrotask(() => {
        if (!this.peer.destroyed) {
          this.peer.readable = false;
          this.peer.emit('end');
        }
      });
    }

    queueMicrotask(() => {
      this.emit('close', false);
      if (cb) cb();
    });
  }

  /**
   * Abruptly terminates the socket.
   *
   * @param {Error} [err]
   * @returns {this}
   */
  destroy(err) {
    if (this.destroyed) return this;
    this.destroyed = true;
    this.writable = false;
    this.readable = false;
    this.clearTimeout();

    queueMicrotask(() => {
      if (err && this.listenerCount('error') > 0) this.emit('error', err);
      this.emit('close', Boolean(err));
    });

    if (this.peer && !this.peer.destroyed) {
      const peer = this.peer;
      peer.destroyed = true;
      peer.writable = false;
      peer.readable = false;
      peer.clearTimeout();

      queueMicrotask(() => {
        if (err && peer.listenerCount('error') > 0) peer.emit('error', err);
        peer.emit('close', Boolean(err));
      });
    }

    return this;
  }

  /**
   * Sets inactivity timeout in milliseconds.
   *
   * @param {number} ms
   * @param {Function} [callback]
   * @returns {this}
   */
  setTimeout(ms, callback) {
    this.clearTimeout();
    this._timeoutMs = ms;
    if (callback) this.once('timeout', callback);

    if (ms > 0) {
      this._timer = setTimeout(() => {
        if (!this.destroyed) {
          this.emit('timeout');
        }
      }, ms);
      if (this._timer.unref) this._timer.unref();
    }
    return this;
  }

  /**
   * Clears any active timeout timer.
   *
   * @returns {this}
   */
  clearTimeout() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    return this;
  }

  // TLS Inspection APIs
  getCipher() {
    return this.cipher;
  }

  getProtocol() {
    return this.protocol;
  }

  getPeerCertificate() {
    return this.cert;
  }

  getEphemeralKeyInfo() {
    return { type: 'ECDH', name: 'X25519', size: 253 };
  }
}

/**
 * High-level IMAP Dialogue Server Simulator
 */
export class MockImapServer extends EventEmitter {
  /**
   * @param {Object} [options={}]
   * @param {string} [options.scenario='happy_path']
   * @param {number} [options.messageCount=142]
   * @param {number} [options.unseenCount=7]
   * @param {number} [options.recentCount=0]
   * @param {number} [options.uidNext=200]
   * @param {number} [options.uidValidity=1]
   * @param {boolean} [options.autoGreet=true]
   * @param {string} [options.greeting]
   * @param {string[]} [options.capabilities]
   * @param {Error} [options.tlsError]
   */
  constructor(options = {}) {
    super();
    this.scenario = options.scenario || 'happy_path';
    this.messageCount = options.messageCount ?? 142;
    this.unseenCount = options.unseenCount ?? 7;
    this.recentCount = options.recentCount ?? 0;
    this.uidNext = options.uidNext ?? 200;
    this.uidValidity = options.uidValidity ?? 1;
    this.autoGreet = options.autoGreet !== false;
    this.customGreeting = options.greeting;
    this.customCapabilities = options.capabilities;
    this.tlsError = options.tlsError || null;

    this.commandHistory = [];
    this.customCommandHandler = null;

    const [clientSocket, serverSocket] = MockDuplexSocket.createPair({
      authorized: !this.tlsError,
      authorizationError: this.tlsError
    });

    this.clientSocket = clientSocket;
    this.serverSocket = serverSocket;

    this._setupDialogue();
  }

  _setupDialogue() {
    // 1. GREETING
    if (this.autoGreet) {
      queueMicrotask(() => {
        if (this.scenario === 'connection_timeout') {
          // Do not emit greeting; force client timeout
          return;
        }

        if (this.scenario === 'invalid_greeting') {
          this.serverSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
          return;
        }

        if (this.scenario === 'server_unavailable') {
          this.serverSocket.write('* BYE [UNAVAILABLE] Mailboxer mock server temporarily down for maintenance\r\n');
          this.serverSocket.end();
          return;
        }

        const greeting = this.customGreeting || '* OK [CAPABILITY IMAP4rev1 IDLE] Mailboxer Mock IMAP Server Ready\r\n';
        this.serverSocket.write(greeting);
      });
    }

    // 2. COMMAND LISTENER & BUFFER
    let buffer = '';
    this.serverSocket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\r\n');
      buffer = lines.pop(); // Keep uncompleted fragment

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        this.commandHistory.push(line);

        const parts = line.split(' ');
        const tag = parts[0];
        const cmd = (parts[1] || '').toUpperCase();
        const args = parts.slice(2);

        // Allow external custom handler override
        if (this.customCommandHandler) {
          const handled = this.customCommandHandler({ tag, cmd, args, rawLine: line, server: this });
          if (handled) continue;
        }

        this._handleCommand(tag, cmd, args, line);
      }
    });
  }

  _handleCommand(tag, cmd, args, rawLine) { // eslint-disable-line no-unused-vars
    if (cmd === 'CAPABILITY') {
      if (this.scenario === 'tenant_blocked_outlook') {
        this.serverSocket.write('* CAPABILITY IMAP4 IMAP4rev1 AUTH=XOAUTH2 LOGINDISABLED SASL-IR UIDPLUS\r\n');
        this.serverSocket.write(`${tag} OK CAPABILITY completed.\r\n`);
        return;
      }

      const caps = this.customCapabilities || [
        'IMAP4rev1',
        'UNSELECT',
        'IDLE',
        'NAMESPACE',
        'QUOTA',
        'MOVE',
        'SASL-IR'
      ];
      this.serverSocket.write(`* CAPABILITY ${caps.join(' ')}\r\n`);
      this.serverSocket.write(`${tag} OK CAPABILITY completed\r\n`);
      return;
    }

    if (cmd === 'LOGIN') {
      if (this.scenario === 'auth_fail') {
        this.serverSocket.write(`${tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n`);
        return;
      }
      if (this.scenario === 'app_password_google') {
        this.serverSocket.write(`${tag} NO [ALERT] Application-specific password required: https://support.google.com/mail/answer/78754\r\n`);
        return;
      }
      if (this.scenario === 'app_password_apple') {
        this.serverSocket.write(`${tag} NO [AUTHENTICATIONFAILED] Authentication Failed\r\n`);
        return;
      }
      if (this.scenario === 'tenant_blocked_outlook') {
        this.serverSocket.write(`${tag} NO Basic authentication is disabled.\r\n`);
        return;
      }
      if (this.scenario === 'imap_disabled') {
        this.serverSocket.write(`${tag} NO [ALERT] IMAP access is disabled for your domain.\r\n`);
        return;
      }
      if (this.scenario === 'socket_drop') {
        this.serverSocket.destroy(new Error('read ECONNRESET'));
        return;
      }

      // Default happy login
      this.serverSocket.write(`${tag} OK [CAPABILITY IMAP4rev1] Logged in successfully\r\n`);
      return;
    }

    if (cmd === 'AUTHENTICATE') {
      if (this.scenario === 'auth_fail') {
        this.serverSocket.write(`${tag} NO [AUTHENTICATIONFAILED] Authentication failed\r\n`);
        return;
      }
      this.serverSocket.write(`${tag} OK Success\r\n`);
      return;
    }

    if (cmd === 'STATUS') {
      const mailbox = args[0] ? args[0].replace(/"/g, '') : 'INBOX';

      if (this.scenario === 'mailbox_not_found' || mailbox.toUpperCase() === 'NONEXISTENT') {
        this.serverSocket.write(`${tag} NO [NONEXISTENT] Mailbox does not exist: ${mailbox}\r\n`);
        return;
      }

      this.serverSocket.write(
        `* STATUS "${mailbox}" (MESSAGES ${this.messageCount} UNSEEN ${this.unseenCount} RECENT ${this.recentCount} UIDNEXT ${this.uidNext} UIDVALIDITY ${this.uidValidity})\r\n`
      );
      this.serverSocket.write(`${tag} OK STATUS completed\r\n`);
      return;
    }

    if (cmd === 'SELECT') {
      const mailbox = args[0] ? args[0].replace(/"/g, '') : 'INBOX';
      this.serverSocket.write(`* ${this.messageCount} EXISTS\r\n`);
      this.serverSocket.write(`* ${this.recentCount} RECENT\r\n`);
      this.serverSocket.write(`* OK [UIDVALIDITY ${this.uidValidity}] UIDs valid\r\n`);
      this.serverSocket.write(`* OK [UIDNEXT ${this.uidNext}] Predicted next UID\r\n`);
      this.serverSocket.write(`* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n`);
      this.serverSocket.write(`* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited\r\n`);
      this.serverSocket.write(`${tag} OK [READ-WRITE] SELECT completed\r\n`);
      return;
    }

    if (cmd === 'IDLE') {
      this.lastIdleTag = tag;
      this.isIdling = true;
      this.serverSocket.write('+ idling\r\n');
      return;
    }

    if (tag.toUpperCase() === 'DONE' || cmd === 'DONE' || rawLine.trim().toUpperCase() === 'DONE') {
      this.isIdling = false;
      const respTag = this.lastIdleTag || 'A0001';
      this.serverSocket.write(`${respTag} OK IDLE completed\r\n`);
      return;
    }

    if (cmd === 'LOGOUT') {
      this.serverSocket.write('* BYE IMAP4rev1 Server logging out\r\n');
      this.serverSocket.write(`${tag} OK LOGOUT completed\r\n`);
      this.serverSocket.end();
      return;
    }

    // Default response for unhandled commands
    this.serverSocket.write(`${tag} BAD Command not implemented in mock server\r\n`);
  }

  /**
   * Pushes an untagged * <N> EXISTS notification to the client socket.
   *
   * @param {number} count
   */
  pushExists(count) {
    if (this.serverSocket && !this.serverSocket.destroyed) {
      this.messageCount = Number(count);
      this.serverSocket.write(`* ${count} EXISTS\r\n`);
    }
  }

  /**
   * Registers a custom command interception callback.
   *
   * @param {Function} handler - ({ tag, cmd, args, rawLine, server }) => boolean
   */
  onCommand(handler) {
    this.customCommandHandler = handler;
  }

  /**
   * Sends a raw line directly to the client.
   *
   * @param {string} line
   */
  pushLine(line) {
    const data = line.endsWith('\r\n') ? line : `${line}\r\n`;
    this.serverSocket.write(data);
  }

  /**
   * Returns the client-facing mock socket.
   *
   * @returns {MockDuplexSocket}
   */
  getClientSocket() {
    return this.clientSocket;
  }

  /**
   * Destroys the server socket.
   *
   * @param {Error} [err]
   */
  destroy(err) {
    this.serverSocket.destroy(err);
  }
}
