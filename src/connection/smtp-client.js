/**
 * Minimal zero-dependency SMTP submission client (RFC 5321 / 6409).
 *
 * Supports implicit TLS (port 465) and STARTTLS (port 587), AUTH PLAIN,
 * AUTH LOGIN and AUTH XOAUTH2, and dot-stuffed DATA transfer.
 *
 * @module connection/smtp-client
 */

import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';

export class SmtpError extends Error {
  constructor(message, code, stage) {
    super(message);
    this.name = 'SmtpError';
    this.smtpCode = code;
    this.stage = stage;
    // 5xx replies are permanent; 4xx and network errors may succeed on retry
    this.permanent = code >= 500 && code < 600;
  }
}

export class SmtpClient {
  /**
   * @param {object} options
   * @param {string} options.host
   * @param {number} [options.port=587]
   * @param {boolean} [options.secure] - Implicit TLS (default: port === 465)
   * @param {object} [options.tls] - Extra tls.connect options
   * @param {number} [options.timeoutMs=30000]
   * @param {boolean} [options.allowInsecure=false] - Allow AUTH without TLS (tests / local relays only)
   * @param {string} [options.clientName] - EHLO name
   */
  constructor(options = {}) {
    if (!options.host) throw new TypeError('SMTP host is required');
    this.host = options.host;
    this.port = Number(options.port || 587);
    this.secure = options.secure ?? this.port === 465;
    this.tlsOptions = options.tls || {};
    this.timeoutMs = options.timeoutMs || 30000;
    this.allowInsecure = Boolean(options.allowInsecure);
    this.clientName = options.clientName || os.hostname() || 'mailboxer.local';

    this.socket = null;
    this._buffer = '';
    this._lines = [];
    this._waiter = null;
    this._closedError = null;
    this.capabilities = new Map();
  }

  _attach(socket) {
    this.socket = socket;
    // No setEncoding(): the raw socket may later be handed to tls.connect for STARTTLS.
    socket.on('data', (chunk) => {
      this._buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let idx;
      while ((idx = this._buffer.indexOf('\n')) !== -1) {
        const line = this._buffer.slice(0, idx).replace(/\r$/, '');
        this._buffer = this._buffer.slice(idx + 1);
        this._lines.push(line);
      }
      this._deliver();
    });
    socket.on('error', (err) => {
      this._closedError = err;
      this._deliver();
    });
    socket.on('close', () => {
      this._closedError ||= new Error('SMTP connection closed unexpectedly');
      this._deliver();
    });
  }

  /** Resolves the pending reader once a full (possibly multi-line) reply is buffered. */
  _deliver() {
    if (!this._waiter) return;
    const endIdx = this._lines.findIndex(l => /^\d{3}(?: |$)/.test(l));
    if (endIdx !== -1) {
      const lines = this._lines.splice(0, endIdx + 1);
      const code = parseInt(lines[endIdx].slice(0, 3), 10);
      const { resolve, timer } = this._waiter;
      this._waiter = null;
      clearTimeout(timer);
      resolve({ code, lines: lines.map(l => l.slice(4)), text: lines.map(l => l.slice(4)).join(' ') });
    } else if (this._closedError) {
      const { reject, timer } = this._waiter;
      this._waiter = null;
      clearTimeout(timer);
      reject(this._closedError);
    }
  }

  _readReply(timeoutMs = this.timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._waiter = null;
        reject(new Error(`SMTP server did not respond within ${timeoutMs}ms`));
        this.socket?.destroy();
      }, timeoutMs);
      this._waiter = { resolve, reject, timer };
      this._deliver();
    });
  }

  async _command(line, expected, stage, timeoutMs) {
    this.socket.write(`${line}\r\n`);
    return this._expect(expected, stage, timeoutMs);
  }

  async _expect(expected, stage, timeoutMs) {
    const reply = await this._readReply(timeoutMs);
    const ok = Array.isArray(expected) ? expected.includes(reply.code) : reply.code === expected;
    if (!ok) {
      throw new SmtpError(`SMTP ${stage} failed: ${reply.code} ${reply.text}`.trim(), reply.code, stage);
    }
    return reply;
  }

  _parseCapabilities(reply) {
    this.capabilities = new Map();
    for (const line of reply.lines.slice(1)) {
      const [name, ...rest] = line.trim().split(/\s+/);
      if (name) this.capabilities.set(name.toUpperCase(), rest.map(r => r.toUpperCase()));
    }
  }

  async _connectSocket() {
    const timeout = this.timeoutMs;
    const socket = await new Promise((resolve, reject) => {
      const onError = (err) => reject(err);
      const opts = { host: this.host, port: this.port, timeout };
      const s = this.secure
        ? tls.connect({ ...opts, servername: net.isIP(this.host) ? undefined : this.host, minVersion: 'TLSv1.2', ...this.tlsOptions }, () => {
          s.removeListener('error', onError);
          resolve(s);
        })
        : net.connect(opts, () => {
          s.removeListener('error', onError);
          resolve(s);
        });
      s.once('error', onError);
      s.setTimeout(timeout, () => s.destroy(new Error(`SMTP connection to ${this.host}:${this.port} timed out`)));
    });
    // Per-reply timers take over once connected.
    socket.setTimeout(0);
    this._attach(socket);
  }

  async _startTls() {
    await this._command('STARTTLS', 220, 'STARTTLS');
    const plain = this.socket;
    plain.removeAllListeners('data');
    plain.removeAllListeners('close');
    plain.removeAllListeners('error');
    const secured = await new Promise((resolve, reject) => {
      const s = tls.connect({
        socket: plain,
        servername: net.isIP(this.host) ? undefined : this.host,
        minVersion: 'TLSv1.2',
        ...this.tlsOptions
      }, () => resolve(s));
      s.once('error', reject);
    });
    this._buffer = '';
    this._lines = [];
    this._closedError = null;
    this._attach(secured);
  }

  async _authenticate(auth) {
    const user = auth.user;
    if (auth.type === 'oauth2') {
      const token = Buffer.from(`user=${user}\x01auth=Bearer ${auth.accessToken}\x01\x01`).toString('base64');
      this.socket.write(`AUTH XOAUTH2 ${token}\r\n`);
      const reply = await this._readReply();
      if (reply.code === 334) {
        // Server sent an error challenge; an empty line makes it finish with the real error
        this.socket.write('\r\n');
        const final = await this._readReply();
        throw new SmtpError(`SMTP authentication failed: ${final.code} ${final.text}`, final.code, 'AUTH');
      }
      if (reply.code !== 235) throw new SmtpError(`SMTP authentication failed: ${reply.code} ${reply.text}`, reply.code, 'AUTH');
      return;
    }

    const mechanisms = this.capabilities.get('AUTH') || [];
    if (mechanisms.includes('PLAIN') || mechanisms.length === 0) {
      const token = Buffer.from(`\0${user}\0${auth.pass}`, 'utf8').toString('base64');
      this.socket.write(`AUTH PLAIN ${token}\r\n`);
      const reply = await this._readReply();
      if (reply.code !== 235) throw new SmtpError(`SMTP authentication failed: ${reply.code} ${reply.text}`, reply.code, 'AUTH');
      return;
    }
    if (mechanisms.includes('LOGIN')) {
      await this._command('AUTH LOGIN', 334, 'AUTH');
      await this._command(Buffer.from(user, 'utf8').toString('base64'), 334, 'AUTH');
      await this._command(Buffer.from(auth.pass, 'utf8').toString('base64'), 235, 'AUTH');
      return;
    }
    throw new SmtpError(`SMTP server supports no usable AUTH mechanism (${mechanisms.join(', ')})`, 0, 'AUTH');
  }

  /**
   * Connects, authenticates and submits one message.
   *
   * @param {object} params
   * @param {string} params.from - Envelope sender
   * @param {string[]} params.recipients - Envelope recipients (To + Cc + Bcc)
   * @param {string} params.raw - Complete RFC 5322 message (CRLF line endings)
   * @param {{type?: string, user: string, pass?: string, accessToken?: string}} params.auth
   * @returns {Promise<{accepted: string[], response: string}>}
   */
  async send({ from, recipients, raw, auth }) {
    if (!recipients || recipients.length === 0) throw new TypeError('At least one recipient is required');
    for (const addr of [from, ...recipients]) {
      if (/[\r\n<>]/.test(addr)) throw new TypeError(`Invalid email address: ${addr}`);
    }

    try {
      await this._connectSocket();
      await this._expect(220, 'greeting');
      let ehlo = await this._command(`EHLO ${this.clientName}`, 250, 'EHLO');
      this._parseCapabilities(ehlo);

      if (!this.secure) {
        if (this.capabilities.has('STARTTLS')) {
          await this._startTls();
          ehlo = await this._command(`EHLO ${this.clientName}`, 250, 'EHLO');
          this._parseCapabilities(ehlo);
        } else if (!this.allowInsecure) {
          throw new SmtpError('SMTP server does not offer STARTTLS; refusing to send credentials in plain text', 0, 'STARTTLS');
        }
      }

      if (auth) await this._authenticate(auth);

      await this._command(`MAIL FROM:<${from}>`, 250, 'MAIL FROM');
      const accepted = [];
      for (const rcpt of recipients) {
        await this._command(`RCPT TO:<${rcpt}>`, [250, 251], 'RCPT TO');
        accepted.push(rcpt);
      }
      await this._command('DATA', 354, 'DATA');

      // Dot-stuffing (RFC 5321 §4.5.2) and guaranteed CRLF endings
      const normalized = String(raw).replace(/\r?\n/g, '\r\n');
      const stuffed = normalized.replace(/^\./gm, '..');
      this.socket.write(stuffed.endsWith('\r\n') ? stuffed : `${stuffed}\r\n`);
      const done = await this._command('.', 250, 'DATA', 120000);

      try {
        this.socket.write('QUIT\r\n');
      } catch {}
      return { accepted, response: `${done.code} ${done.text}` };
    } finally {
      setTimeout(() => this.socket?.destroy(), 200).unref?.();
    }
  }
}
