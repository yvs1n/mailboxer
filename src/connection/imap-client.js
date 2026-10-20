/**
 * Mailboxer IMAP Protocol Client & Connection State Machine
 *
 * Implements RFC 3501 IMAP4rev1 wire protocol with zero external dependencies.
 * Provides deterministic 7-state monotonic transitions, streaming line parsing,
 * tagged command execution with timeouts, capability inspection, authentication,
 * STATUS INBOX querying, and clean LOGOUT teardown.
 *
 * Zero-dependency native Node.js 22 implementation.
 *
 * @module connection/imap-client
 */

import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';
import { SocketTransport, TlsSocketTransport } from './transport.js';
import {
  classifyProtocolResponse,
  classifySocketError
} from '../errors/classifier.js';
import {
  isMailboxerError,
  createErrorByCode,
  ERROR_CODES
} from '../errors/taxonomy.js';

/**
 * IMAP Client Lifecycle States
 * @readonly
 * @enum {string}
 */
export const IMAP_STATES = Object.freeze({
  DISCONNECTED: 'DISCONNECTED',
  CONNECTING: 'CONNECTING',
  CONNECTED: 'CONNECTED',
  AUTHENTICATING: 'AUTHENTICATING',
  AUTHENTICATED: 'AUTHENTICATED',
  QUERYING: 'QUERYING',
  IDLE: 'IDLE',
  CLOSING: 'CLOSING'
});

/**
 * Permitted state transitions enforcing monotonic progression.
 */
const ALLOWED_TRANSITIONS = {
  [IMAP_STATES.DISCONNECTED]: [IMAP_STATES.CONNECTING],
  [IMAP_STATES.CONNECTING]: [IMAP_STATES.CONNECTED, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.CONNECTED]: [IMAP_STATES.AUTHENTICATING, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.AUTHENTICATING]: [IMAP_STATES.AUTHENTICATED, IMAP_STATES.CONNECTED, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.AUTHENTICATED]: [IMAP_STATES.QUERYING, IMAP_STATES.IDLE, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.QUERYING]: [IMAP_STATES.QUERYING, IMAP_STATES.AUTHENTICATED, IMAP_STATES.IDLE, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.IDLE]: [IMAP_STATES.AUTHENTICATED, IMAP_STATES.QUERYING, IMAP_STATES.CLOSING, IMAP_STATES.DISCONNECTED],
  [IMAP_STATES.CLOSING]: [IMAP_STATES.DISCONNECTED]
};

/**
 * Escapes a string for use in an IMAP quoted string according to RFC 3501 §9.
 * Defends against CRLF injection.
 *
 * @param {*} str - String to escape
 * @returns {string} Quoted IMAP string
 */
export function escapeImapString(str) {
  if (str === null || str === undefined) return '""';
  const val = String(str);
  if (/[\r\n]/.test(val)) {
    throw new Error('IMAP string cannot contain newline characters (CRLF injection prevented)');
  }
  return '"' + val.replace(/[\\"]/g, '\\$&') + '"';
}

/**
 * Parses IMAP * STATUS response lines into structured status data.
 *
 * @param {string[]} lines - Response lines from STATUS command
 * @param {string} [targetMailbox='INBOX'] - Target mailbox name
 * @returns {object|null} Structured mailbox status or null
 */
export function parseStatusResponse(lines, targetMailbox = 'INBOX') {
  if (!Array.isArray(lines)) return null;

  const targetNorm = targetMailbox ? targetMailbox.trim() : 'INBOX';
  const isInbox = targetNorm.toUpperCase() === 'INBOX';

  for (const line of lines) {
    const match = line.match(/^\*\s+STATUS\s+(?:"([^"]+)"|(\S+))\s+\(([^)]*)\)/i);
    if (match) {
      const mailbox = match[1] || match[2];

      const matchesTarget = isInbox
        ? mailbox.toUpperCase() === 'INBOX'
        : (mailbox === targetNorm || mailbox.toLowerCase() === targetNorm.toLowerCase());

      if (!matchesTarget) {
        continue;
      }

      const body = match[3];

      const status = {
        mailbox,
        totalMessages: 0,
        unseen: 0,
        recent: 0,
        uidNext: null,
        uidValidity: null,
        raw: line
      };

      const tokens = body.trim().split(/\s+/);
      for (let i = 0; i < tokens.length; i += 2) {
        const key = (tokens[i] || '').toUpperCase();
        const val = parseInt(tokens[i + 1], 10);
        if (!Number.isNaN(val)) {
          if (key === 'MESSAGES') status.totalMessages = val;
          else if (key === 'UNSEEN') status.unseen = val;
          else if (key === 'RECENT') status.recent = val;
          else if (key === 'UIDNEXT') status.uidNext = val;
          else if (key === 'UIDVALIDITY') status.uidValidity = val;
        }
      }
      return status;
    }
  }
  return null;
}

/**
 * Extracts all capability tokens from untagged lines.
 *
 * @param {string[]} lines - Raw response lines
 * @returns {string[]} Uppercase capability tokens
 */
export function parseCapabilities(lines) {
  const caps = new Set();
  for (const line of lines) {
    if (/^\*\s+CAPABILITY\b/i.test(line)) {
      const tokens = line.replace(/^\*\s+CAPABILITY\s*/i, '').trim().split(/\s+/);
      for (const t of tokens) if (t) caps.add(t);
    }
    const bracketMatch = line.match(/\[CAPABILITY\s+([^\]]+)\]/i);
    if (bracketMatch) {
      const tokens = bracketMatch[1].trim().split(/\s+/);
      for (const t of tokens) if (t) caps.add(t);
    }
  }
  return Array.from(caps);
}

/**
 * Decodes MIME-encoded words in email headers (RFC 2047: =?charset?encoding?data?=).
 *
 * @param {string} str - Header value potentially containing encoded words
 * @returns {string} Decoded UTF-8 string
 */
export function decodeMimeHeader(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, charset, encoding, data) => {
    try {
      const enc = encoding.toUpperCase();
      if (enc === 'B') {
        const buf = Buffer.from(data, 'base64');
        return buf.toString(charset.toLowerCase().includes('utf') ? 'utf8' : 'latin1');
      } else if (enc === 'Q') {
        const decoded = data.replace(/_/g, ' ').replace(/=([A-Fa-f0-9]{2})/g, (__, hex) => {
          return String.fromCharCode(parseInt(hex, 16));
        });
        return decoded;
      }
    } catch {
      return data;
    }
    return data;
  });
}

/**
 * Extracts a normalized email address from a recipient or sender string.
 *
 * @param {string} str - E.g. 'Jane Doe <jane@uni.edu>' or 'jane@uni.edu'
 * @returns {string} Normalized lowercase email or empty string
 */
export function extractEmail(str) {
  if (!str || typeof str !== 'string') return '';
  const angleMatch = str.match(/<([^>]+)>/);
  if (angleMatch) return angleMatch[1].trim().toLowerCase();
  const directMatch = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  if (directMatch) return directMatch[0].trim().toLowerCase();
  return str.trim().toLowerCase();
}

/**
 * Parses multiple email recipients from a To / Cc / Bcc header.
 *
 * @param {string|string[]} val - Header string or array
 * @returns {string[]} Normalized email addresses
 */
export function extractEmailsList(val) {
  if (!val) return [];
  const list = Array.isArray(val) ? val : [val];
  const emails = [];
  for (const item of list) {
    if (typeof item === 'string') {
      const parts = item.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
      for (const p of parts) {
        const email = extractEmail(p);
        if (email) emails.push(email);
      }
    }
  }
  return emails;
}

/**
 * Parses RFC 822 / 2822 header blocks into an object of normalized key-value pairs.
 *
 * @param {string} raw - Raw header text
 * @returns {Record<string, string|string[]>}
 */
export function parseHeaders(raw) {
  if (!raw || typeof raw !== 'string') return {};
  const folded = raw.replace(/\r?\n[ \t]+/g, ' ');
  const lines = folded.split(/\r?\n/);
  const headers = {};

  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = decodeMimeHeader(line.slice(colon + 1).trim());
    if (headers[key] === undefined) {
      headers[key] = val;
    } else if (Array.isArray(headers[key])) {
      headers[key].push(val);
    } else {
      headers[key] = [headers[key], val];
    }
  }
  return headers;
}

/**
 * Parses IMAP LIST response lines into structured folder records.
 *
 * @param {string[]} lines - Raw untagged response lines
 * @returns {Array<{path: string, name: string, delimiter: string|null, flags: string[], selectable: boolean}>}
 */
export function parseListResponse(lines) {
  if (!Array.isArray(lines)) return [];
  const mailboxes = [];

  for (const line of lines) {
    if (!/^\*\s+LIST\b/i.test(line)) continue;

    const match = line.match(/^\*\s+LIST\s+\(([^)]*)\)\s+(?:"([^"]*)"|NIL|(\S+))\s+(?:"([^"]*)"|(\S+))/i);
    if (match) {
      const flagsRaw = match[1] || '';
      const flags = flagsRaw.trim().split(/\s+/).filter(Boolean);
      let delimiter = '/';
      if (match[2] !== undefined) {
        delimiter = match[2];
      } else if (match[3] === 'NIL') {
        delimiter = null;
      } else if (match[3]) {
        delimiter = match[3];
      }

      const path = match[4] !== undefined ? match[4] : (match[5] || '');
      const name = delimiter && path.includes(delimiter)
        ? path.split(delimiter).filter(Boolean).pop()
        : path;

      mailboxes.push({
        path,
        name: name || path,
        delimiter,
        flags,
        selectable: !flags.some(f => f.toLowerCase() === '\\noselect')
      });
    }
  }

  return mailboxes;
}

/**
 * Parses IMAP SELECT / EXAMINE response lines.
 *
 * @param {string[]} lines - Raw untagged lines
 * @param {string} [mailbox='INBOX'] - Mailbox name
 * @param {string} [taggedLine=''] - Optional completion tagged line (for READ-ONLY check)
 * @returns {object} MailboxSelectResult
 */
export function parseSelectResponse(lines, mailbox = 'INBOX', taggedLine = '') {
  const result = {
    mailbox,
    readOnly: false,
    exists: 0,
    totalMessages: 0,
    recent: 0,
    unseen: null,
    uidValidity: null,
    uidNext: null,
    highestModSeq: null,
    flags: [],
    permanentFlags: []
  };

  if (taggedLine && /\[READ-ONLY\]/i.test(taggedLine)) {
    result.readOnly = true;
  }

  if (!Array.isArray(lines)) return result;

  for (const line of lines) {
    let m = line.match(/^\*\s+(\d+)\s+EXISTS\b/i);
    if (m) {
      result.exists = parseInt(m[1], 10);
      result.totalMessages = result.exists;
      continue;
    }

    m = line.match(/^\*\s+(\d+)\s+RECENT\b/i);
    if (m) {
      result.recent = parseInt(m[1], 10);
      continue;
    }

    m = line.match(/^\*\s+FLAGS\s+\(([^)]*)\)/i);
    if (m) {
      result.flags = m[1].trim().split(/\s+/).filter(Boolean);
      continue;
    }

    m = line.match(/\[UIDVALIDITY\s+(\d+)\]/i);
    if (m) {
      result.uidValidity = parseInt(m[1], 10);
      continue;
    }

    m = line.match(/\[UIDNEXT\s+(\d+)\]/i);
    if (m) {
      result.uidNext = parseInt(m[1], 10);
      continue;
    }

    m = line.match(/\[HIGHESTMODSEQ\s+(\d+)\]/i);
    if (m) {
      result.highestModSeq = parseInt(m[1], 10);
      continue;
    }

    m = line.match(/\[UNSEEN\s+(\d+)\]/i);
    if (m) {
      result.unseen = parseInt(m[1], 10);
      continue;
    }

    m = line.match(/\[PERMANENTFLAGS\s+\(([^)]*)\)\]/i);
    if (m) {
      result.permanentFlags = m[1].trim().split(/\s+/).filter(Boolean);
      continue;
    }

    if (/\[READ-ONLY\]/i.test(line)) {
      result.readOnly = true;
    }
  }

  return result;
}

/**
 * Parses UID SEARCH response lines.
 *
 * @param {string[]} lines - Raw untagged lines
 * @returns {number[]} Array of numeric UIDs
 */
export function parseSearchResponse(lines) {
  if (!Array.isArray(lines)) return [];
  const uids = [];
  for (const line of lines) {
    if (/^\*\s+SEARCH\b/i.test(line)) {
      const rest = line.replace(/^\*\s+SEARCH\s*/i, '').trim();
      if (rest) {
        const tokens = rest.split(/\s+/);
        for (const t of tokens) {
          const num = parseInt(t, 10);
          if (!Number.isNaN(num) && num > 0) {
            uids.push(num);
          }
        }
      }
    }
  }
  return uids;
}

/**
 * Decodes quoted-printable encoded strings according to RFC 2045.
 *
 * @param {string} str
 * @returns {string}
 */
export function decodeQuotedPrintable(str) {
  if (!str || typeof str !== 'string') return '';
  const stripped = str.replace(/=(?:\r\n|\r|\n)/g, '');
  return stripped.replace(/((?:=[A-Fa-f0-9]{2})+)/g, (match) => {
    try {
      return decodeURIComponent(match.replace(/=/g, '%'));
    } catch {
      return match.replace(/=([A-Fa-f0-9]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    }
  });
}

/**
 * Converts simple HTML email fragments to clean plain text.
 *
 * @param {string} html
 * @returns {string}
 */
export function htmlToCleanText(html) {
  if (!html || typeof html !== 'string') return '';
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<\/p>|<\/div>|<br\s*\/?>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Extracts and cleans readable plain-text from raw MIME multipart bodies and quoted-printable text.
 *
 * @param {string} raw
 * @returns {string}
 */
export function cleanMimeBody(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let text = raw.trim();

  // 1. Detect multipart MIME boundary
  const boundaryMatch = text.match(/^--([a-zA-Z0-9_\-./=]+)/m);
  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const parts = text.split(new RegExp('--' + boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:--)?'));

    let chosenPart = '';
    let isHtml = false;
    for (const part of parts) {
      const p = part.trim();
      if (!p) continue;
      if (/Content-Type:\s*text\/plain/i.test(p)) {
        chosenPart = p;
        isHtml = false;
        break;
      }
    }
    if (!chosenPart) {
      for (const part of parts) {
        const p = part.trim();
        if (!p) continue;
        if (/Content-Type:\s*text\/html/i.test(p)) {
          chosenPart = p;
          isHtml = true;
          break;
        }
      }
    }
    if (!chosenPart) {
      for (const part of parts) {
        const p = part.trim();
        if (p) {
          chosenPart = p;
          isHtml = /<[a-z][\s\S]*>/i.test(p);
          break;
        }
      }
    }

    if (chosenPart) {
      const headerEnd = chosenPart.search(/\r?\n\r?\n/);
      let headers = '';
      let body = chosenPart;
      if (headerEnd !== -1) {
        headers = chosenPart.slice(0, headerEnd);
        body = chosenPart.slice(headerEnd).trim();
      }

      if (/Content-Transfer-Encoding:\s*base64/i.test(headers)) {
        try {
          if (typeof Buffer !== 'undefined') {
            body = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf-8');
          }
        } catch {}
      } else if (/Content-Transfer-Encoding:\s*quoted-printable/i.test(headers) || /=([0-9A-F]{2})/i.test(body)) {
        body = decodeQuotedPrintable(body);
      }
      if (isHtml || /<[a-z][\s\S]*>/i.test(body)) {
        body = htmlToCleanText(body);
      }
      text = body;
    }
  } else {
    if (/=([0-9A-F]{2})/i.test(text) || /=\r?\n/.test(text)) {
      text = decodeQuotedPrintable(text);
    }
    if (/<[a-z][\s\S]*>/i.test(text)) {
      text = htmlToCleanText(text);
    }
  }

  // Strip residual MIME headers
  text = text.replace(/^(?:(?:Content-Type|Content-Transfer-Encoding|Content-Disposition|Mime-Version|Content-Description):[^\n]*(?:\r?\n|\n))+/gi, '').trim();

  return text;
}

/**
 * Parses untagged FETCH responses containing message headers and body previews.
 *
 * @param {string[]} lines - Untagged lines from UID FETCH
 * @returns {object[]} Parsed message objects
 */
export function parseFetchResponses(lines) {
  if (!Array.isArray(lines)) return [];
  const results = [];

  for (const line of lines) {
    if (!/^\*\s+\d+\s+FETCH\b/i.test(line)) continue;

    const seqMatch = line.match(/^\*\s+(\d+)\s+FETCH\b/i);
    const seq = seqMatch ? parseInt(seqMatch[1], 10) : 1;

    // 1. UID
    const uidMatch = line.match(/\bUID\s+(\d+)\b/i);
    const uid = uidMatch ? parseInt(uidMatch[1], 10) : seq;

    // 2. FLAGS
    const flagsMatch = line.match(/\bFLAGS\s+\(([^)]*)\)/i);
    const flags = flagsMatch
      ? flagsMatch[1].trim().split(/\s+/).filter(Boolean)
      : [];
    const isSeen = flags.some(f => f.toLowerCase() === '\\seen');
    const isFlagged = flags.some(f => f.toLowerCase() === '\\flagged');

    // 3. RFC822.SIZE
    const sizeMatch = line.match(/\bRFC822\.SIZE\s+(\d+)\b/i);
    const size = sizeMatch ? parseInt(sizeMatch[1], 10) : 0;

    // 4. Headers extraction (literal or quoted)
    let rawHeaders = '';
    const headerLiteralIdx = line.search(/BODY(?:\.PEEK)?\[HEADER[^\]]*\]\s*\{(\d+)\}\r?\n/i);
    if (headerLiteralIdx !== -1) {
      const sub = line.slice(headerLiteralIdx);
      const m = sub.match(/^BODY(?:\.PEEK)?\[HEADER[^\]]*\]\s*\{(\d+)\}\r?\n/i);
      if (m) {
        const len = parseInt(m[1], 10);
        const start = headerLiteralIdx + m[0].length;
        rawHeaders = line.slice(start, start + len);
      }
    } else {
      const quotedMatch = line.match(/BODY(?:\.PEEK)?\[HEADER[^\]]*\]\s*"([^"]*)"/i);
      if (quotedMatch) {
        rawHeaders = quotedMatch[1];
      }
    }

    // 5. Body preview extraction
    let bodySnippet = '';
    const textLiteralIdx = line.search(/BODY(?:\.PEEK)?\[TEXT[^\]]*\](?:\<[0-9.]+\>)?\s*\{(\d+)\}\r?\n/i);
    if (textLiteralIdx !== -1) {
      const sub = line.slice(textLiteralIdx);
      const m = sub.match(/^BODY(?:\.PEEK)?\[TEXT[^\]]*\](?:\<[0-9.]+\>)?\s*\{(\d+)\}\r?\n/i);
      if (m) {
        const len = parseInt(m[1], 10);
        const start = textLiteralIdx + m[0].length;
        bodySnippet = line.slice(start, start + len);
      }
    } else {
      const quotedMatch = line.match(/BODY(?:\.PEEK)?\[TEXT[^\]]*\](?:\<[0-9.]+\>)?\s*"([^"]*)"/i);
      if (quotedMatch) {
        bodySnippet = quotedMatch[1];
      }
    }

    const headers = parseHeaders(rawHeaders);
    const sender = headers.from || '';
    const senderEmail = extractEmail(sender);
    const subject = headers.subject || '(no subject)';
    let date = headers.date || new Date().toISOString();
    try {
      const d = new Date(date);
      if (!Number.isNaN(d.getTime())) {
        date = d.toISOString();
      }
    } catch {
      date = new Date().toISOString();
    }

    const messageId = headers['message-id'] || null;
    const inReplyTo = headers['in-reply-to'] || null;
    const references = headers.references || null;

    let threadId = null;
    if (references) {
      const refMatch = references.match(/<[^>]+>/);
      if (refMatch) threadId = refMatch[0];
    }
    if (!threadId && inReplyTo) {
      const inReplyMatch = inReplyTo.match(/<[^>]+>/);
      if (inReplyMatch) threadId = inReplyMatch[0];
    }
    if (!threadId && messageId) {
      threadId = messageId;
    }
    if (!threadId) {
      threadId = `thread_${uid}`;
    }

    const recipients = [];
    if (headers.to) recipients.push(...extractEmailsList(headers.to));
    if (headers.cc) recipients.push(...extractEmailsList(headers.cc));

    const cleaned = cleanMimeBody(bodySnippet);
    const cleanBodySnippet = cleaned
      ? cleaned.replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 1000)
      : '';

    results.push({
      seq,
      uid,
      size,
      flags,
      isSeen,
      isFlagged,
      subject,
      sender,
      from: sender,
      senderEmail,
      recipients,
      date,
      bodySnippet: cleanBodySnippet,
      messageId,
      threadId,
      inReplyTo,
      references,
      listUnsubscribe: headers['list-unsubscribe'] || null,
      precedence: headers.precedence || null,
      rawHeaders
    });
  }

  return results;
}

/**
 * Sequential FIFO command queue ensuring non-interleaved IMAP transactions.
 */
class AsyncCommandQueue {
  constructor() {
    this._chain = Promise.resolve();
  }

  enqueue(fn) {
    const result = this._chain.then(() => fn());
    this._chain = result.catch(() => {});
    return result;
  }
}

/**
 * IMAP Protocol Client and State Machine
 */
export class ImapClient extends EventEmitter {
  /**
   * @param {object} [options={}] - Client configuration
   * @param {string} [options.host] - IMAP host
   * @param {number} [options.port=993] - IMAP port
   * @param {boolean} [options.secure=true] - TLS enabled
   * @param {number} [options.connectionTimeoutMs=10000] - Connection timeout in ms
   * @param {number} [options.authTimeoutMs=10000] - Authentication timeout in ms
   * @param {number} [options.commandTimeoutMs=10000] - Command execution timeout in ms
   * @param {number} [options.timeoutMs] - Fallback timeout in ms
   * @param {object} [options.tls={}] - TLS configuration options
   * @param {string} [options.provider='custom'] - Provider preset name
   * @param {object} [options.transport] - Optional injected transport (for testing)
   * @param {object} [options.accountConfig] - Optional complete account configuration
   */
  constructor(options = {}) {
    super();

    this.options = {
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      commandTimeoutMs: 10000,
      provider: 'custom',
      tls: {},
      ...options
    };

    if (options.timeoutMs) {
      this.options.connectionTimeoutMs = options.timeoutMs;
      this.options.authTimeoutMs = options.timeoutMs;
      this.options.commandTimeoutMs = options.timeoutMs;
    }

    this.accountConfig = options.accountConfig || null;
    if (this.accountConfig?.provider) {
      this.options.provider = this.accountConfig.provider;
    }

    this._injectedTransport = Boolean(options.transport);
    if (options.transport) {
      if (options.transport instanceof SocketTransport) {
        this.transport = options.transport;
      } else {
        this.transport = new SocketTransport({ socket: options.transport });
      }
    } else {
      this.transport = null;
    }

    this._boundTransport = null;
    this._boundOnData = null;
    this._boundOnError = null;
    this._boundOnClose = null;

    this._state = IMAP_STATES.DISCONNECTED;
    this._buffer = '';
    this._literalRemaining = 0;
    this._pendingLine = '';
    this._tagCounter = 1;
    this._currentCommand = null;
    this._commandQueue = new AsyncCommandQueue();
    this._greetingResolve = null;
    this._greetingReject = null;

    this.capabilities = [];
    this.serverGreeting = '';
    this.loginDisabled = false;
    this.tlsDetails = null;

    this.metrics = {
      connectDurationMs: 0,
      authDurationMs: 0,
      mailboxQueryDurationMs: 0,
      totalDurationMs: 0
    };
  }

  /**
   * Current lifecycle state.
   * @returns {string}
   */
  get state() {
    return this._state;
  }

  /**
   * Whether the client is connected to a transport.
   * @returns {boolean}
   */
  get isConnected() {
    return this._state !== IMAP_STATES.DISCONNECTED && this._state !== IMAP_STATES.CLOSING;
  }

  /**
   * Whether the client has successfully authenticated.
   * @returns {boolean}
   */
  get isAuthenticated() {
    return this._state === IMAP_STATES.AUTHENTICATED || this._state === IMAP_STATES.QUERYING || this._state === IMAP_STATES.IDLE;
  }

  /**
   * Checks whether the server advertises a specific capability.
   * @param {string} name - Capability name (case-insensitive)
   * @returns {boolean}
   */
  hasCapability(name) {
    if (!name) return false;
    const target = name.toUpperCase();
    return this.capabilities.some(c => c.toUpperCase() === target);
  }

  /**
   * Internal state transition guard.
   * @private
   */
  _setState(nextState) {
    const prevState = this._state;
    if (prevState === nextState) return;

    const allowed = ALLOWED_TRANSITIONS[prevState];
    if (!allowed || !allowed.includes(nextState)) {
      throw new Error(`Invalid IMAP state transition from ${prevState} to ${nextState}`);
    }

    this._state = nextState;
    this.emit('stateChange', {
      from: prevState,
      to: nextState,
      timestamp: Date.now()
    });
  }

  /**
   * Generates the next sequential IMAP command tag.
   * @private
   */
  _nextTag() {
    const tag = `A${String(this._tagCounter++).padStart(4, '0')}`;
    return tag;
  }

  /**
   * Handles incoming transport data chunks.
   * @private
   */
  _onData(chunk) {
    this._buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    this._drainLines();
  }

  /**
   * Splits buffer into complete lines and delegates to _handleLine.
   * Supports streaming literal octet tracking ({N}\r\n).
   * @private
   */
  _drainLines() {
    while (true) {
      if (this._literalRemaining > 0) {
        if (this._buffer.length < this._literalRemaining) {
          this._pendingLine += this._buffer;
          this._literalRemaining -= this._buffer.length;
          this._buffer = '';
          break;
        } else {
          const literal = this._buffer.slice(0, this._literalRemaining);
          this._pendingLine += literal;
          this._buffer = this._buffer.slice(this._literalRemaining);
          this._literalRemaining = 0;
          continue;
        }
      }

      const newlineIdx = this._buffer.indexOf('\n');
      if (newlineIdx === -1) break;

      let chunk = this._buffer.slice(0, newlineIdx);
      if (chunk.endsWith('\r')) {
        chunk = chunk.slice(0, -1);
      }
      this._buffer = this._buffer.slice(newlineIdx + 1);

      const fullLine = this._pendingLine ? this._pendingLine + chunk : chunk;
      this._pendingLine = '';

      const match = fullLine.match(/\{(\d+)\}\s*$/);
      if (match) {
        this._literalRemaining = parseInt(match[1], 10);
        this._pendingLine = fullLine + '\r\n';
        continue;
      }

      this._handleLine(fullLine);
    }
  }

  /**
   * Processes a single parsed line from the server.
   * @private
   */
  _handleLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;

    // 1. Untagged lines (* ...)
    if (line.startsWith('*')) {
      this._handleUntaggedLine(line);
      return;
    }

    // 2. Continuation lines (+ ...)
    if (line.startsWith('+')) {
      if (this._currentCommand?.onContinuation) {
        this._currentCommand.onContinuation(line);
      } else if (this._currentCommand) {
        this._currentCommand.untagged.push(line);
      }
      this.emit('continuation', line);
      return;
    }

    // 3. Tagged completion lines (A0001 OK/NO/BAD ...)
    const match = line.match(/^([A-Za-z0-9]+)\s+(OK|NO|BAD)\b(.*)$/i);
    if (match) {
      const [, tag, statusRaw, rest] = match;
      const status = statusRaw.toUpperCase();

      if (this._currentCommand && this._currentCommand.tag === tag) {
        const cmd = this._currentCommand;
        this._currentCommand = null;

        if (cmd.timer) {
          clearTimeout(cmd.timer);
        }

        if (status === 'OK') {
          const caps = parseCapabilities([line, ...cmd.untagged]);
          if (caps.length > 0) {
            this._mergeCapabilities(caps);
          }
          cmd.resolve({
            tag,
            status: 'OK',
            rest: rest.trim(),
            untagged: cmd.untagged,
            line
          });
        } else {
          const err = classifyProtocolResponse(line, this.options.provider, {
            loginDisabled: this.loginDisabled
          });
          err.rawResponse = line;
          err.tag = tag;
          err.status = status;
          cmd.reject(err);
        }
      } else {
        this.emit('unsolicitedTagged', { tag, status, line });
      }
      return;
    }

    // 4. Unexpected banner / non-IMAP response while awaiting greeting
    if (this._greetingReject) {
      const reject = this._greetingReject;
      this._greetingResolve = null;
      this._greetingReject = null;
      const err = classifyProtocolResponse(line, this.options.provider, {
        loginDisabled: this.loginDisabled
      });
      reject(err);
      return;
    }

    // Fallback: raw line
    if (this._currentCommand) {
      this._currentCommand.untagged.push(line);
    }
    this.emit('rawLine', line);
  }

  /**
   * Handles untagged lines (* ...)
   * @private
   */
  _handleUntaggedLine(line) {
    // Awaiting server greeting
    if (this._greetingResolve) {
      if (/^\*\s+OK\b/i.test(line) || /^\*\s+PREAUTH\b/i.test(line)) {
        this.serverGreeting = line;
        const caps = parseCapabilities([line]);
        if (caps.length > 0) {
          this._mergeCapabilities(caps);
        }
        const resolve = this._greetingResolve;
        this._greetingResolve = null;
        this._greetingReject = null;
        this._setState(IMAP_STATES.CONNECTED);
        resolve(line);
        this.emit('greeting', line);
        return;
      }

      if (/^\*\s+BYE\b/i.test(line)) {
        const reject = this._greetingReject;
        this._greetingResolve = null;
        this._greetingReject = null;
        const err = classifyProtocolResponse(line, this.options.provider, {
          loginDisabled: this.loginDisabled
        });
        reject(err);
        return;
      }
    }

    // Dynamic capability updates
    if (/^\*\s+CAPABILITY\b/i.test(line)) {
      const caps = parseCapabilities([line]);
      this._mergeCapabilities(caps);
    }

    // If a command is active, collect untagged output
    if (this._currentCommand) {
      this._currentCommand.untagged.push(line);
    }

    // Unsolicited untagged events parsing (EXISTS, EXPUNGE, FETCH, RECENT)
    const existsMatch = line.match(/^\*\s+(\d+)\s+EXISTS\b/i);
    if (existsMatch) {
      const count = parseInt(existsMatch[1], 10);
      this.emit('exists', count, line);
    }
    const expungeMatch = line.match(/^\*\s+(\d+)\s+EXPUNGE\b/i);
    if (expungeMatch) {
      const seq = parseInt(expungeMatch[1], 10);
      this.emit('expunge', seq, line);
    }
    const fetchMatch = line.match(/^\*\s+(\d+)\s+FETCH\b/i);
    if (fetchMatch) {
      const seq = parseInt(fetchMatch[1], 10);
      this.emit('fetch', seq, line);
    }
    const recentMatch = line.match(/^\*\s+(\d+)\s+RECENT\b/i);
    if (recentMatch) {
      const count = parseInt(recentMatch[1], 10);
      this.emit('recent', count, line);
    }

    this.emit('untagged', line);
  }

  /**
   * Merges newly discovered capabilities.
   * @private
   */
  _mergeCapabilities(newCaps) {
    const map = new Map();
    for (const c of this.capabilities) {
      map.set(c.toUpperCase(), c);
    }
    for (const c of newCaps) {
      if (!map.has(c.toUpperCase())) {
        map.set(c.toUpperCase(), c);
      }
    }
    this.capabilities = Array.from(map.values());
    if (this.hasCapability('LOGINDISABLED')) {
      this.loginDisabled = true;
    }
  }

  /**
   * Attaches listeners to transport.
   * @private
   */
  _attachTransportListeners(transport) {
    this._detachTransportListeners();
    if (!transport) return;

    this._boundTransport = transport;
    this._boundOnData = (chunk) => this._onData(chunk);
    this._boundOnError = (err) => this._onError(err);
    this._boundOnClose = () => this._onClose();

    transport.on('data', this._boundOnData);
    transport.on('error', this._boundOnError);
    transport.on('close', this._boundOnClose);
  }

  /**
   * Detaches listeners from the active transport to prevent memory leaks.
   * @private
   */
  _detachTransportListeners() {
    if (this._boundTransport) {
      if (this._boundOnData) this._boundTransport.removeListener('data', this._boundOnData);
      if (this._boundOnError) this._boundTransport.removeListener('error', this._boundOnError);
      if (this._boundOnClose) this._boundTransport.removeListener('close', this._boundOnClose);
      this._boundTransport = null;
      this._boundOnData = null;
      this._boundOnError = null;
      this._boundOnClose = null;
    }
  }

  /**
   * Handles transport error event.
   * @private
   */
  _onError(rawErr) {
    const classified = isMailboxerError(rawErr)
      ? rawErr
      : classifySocketError(rawErr, this.options.provider);

    if (this._greetingReject) {
      const reject = this._greetingReject;
      this._greetingResolve = null;
      this._greetingReject = null;
      reject(classified);
    }

    if (this._currentCommand) {
      if (this._currentCommand.timer) clearTimeout(this._currentCommand.timer);
      const cmd = this._currentCommand;
      this._currentCommand = null;
      cmd.reject(classified);
    }

    if (this._state !== IMAP_STATES.DISCONNECTED) {
      this._setState(IMAP_STATES.DISCONNECTED);
    }
    if (this.listenerCount('error') > 0) {
      this.emit('error', classified);
    }
  }

  /**
   * Handles transport close event.
   * @private
   */
  _onClose() {
    if (this._greetingReject) {
      const reject = this._greetingReject;
      this._greetingResolve = null;
      this._greetingReject = null;
      const dropErr = classifySocketError(new Error('Connection closed before greeting received'), this.options.provider);
      dropErr.code = ERROR_CODES.CONNECTION_DROPPED;
      reject(dropErr);
    }

    if (this._currentCommand) {
      if (this._currentCommand.timer) clearTimeout(this._currentCommand.timer);
      const cmd = this._currentCommand;
      this._currentCommand = null;
      const dropErr = classifySocketError(new Error('Connection closed prematurely by remote host'), this.options.provider);
      dropErr.code = ERROR_CODES.CONNECTION_DROPPED;
      cmd.reject(dropErr);
    }

    if (this._state !== IMAP_STATES.DISCONNECTED) {
      this._setState(IMAP_STATES.DISCONNECTED);
    }
    this.emit('close');
    this._detachTransportListeners();
  }

  /**
   * Sends an IMAP command sequentially with timeout management.
   *
   * @param {string} commandText - IMAP command (without tag or CRLF)
   * @param {object} [options={}] - Options
   * @param {number} [options.timeoutMs] - Timeout in ms
   * @param {boolean} [options.redact=false] - Whether to redact in logging/events
   * @returns {Promise<{tag: string, status: string, rest: string, untagged: string[], line: string}>}
   */
  async sendCommand(commandText, options = {}) {
    return this._commandQueue.enqueue(async () => {
      if (!this.transport) {
        throw new Error('Cannot send command: transport is not connected');
      }
      if (this._state === IMAP_STATES.DISCONNECTED || (this._state === IMAP_STATES.CLOSING && !/^LOGOUT\b/i.test(commandText.trim()))) {
        throw new Error(`Cannot send command in state ${this._state}`);
      }

      const tag = this._nextTag();
      const timeoutMs = options.timeoutMs ?? this.options.commandTimeoutMs ?? 10000;
      const redact = options.redact ?? false;
      const wireLine = `${tag} ${commandText}\r\n`;

      return new Promise((resolve, reject) => {
        let timer = null;
        if (timeoutMs > 0) {
          timer = setTimeout(() => {
            if (this._currentCommand && this._currentCommand.tag === tag) {
              this._currentCommand = null;
              const displayCmd = redact ? `${tag} [REDACTED]` : `${tag} ${commandText}`;
              const timeoutErr = createErrorByCode(
                ERROR_CODES.CONNECTION_TIMEOUT,
                `Command "${displayCmd}" timed out after ${timeoutMs}ms`,
                { provider: this.options.provider }
              );
              if (this.transport && !this.transport.destroyed) {
                this.transport.destroy();
              }
              reject(timeoutErr);
            }
          }, timeoutMs);
        }

        this._currentCommand = {
          tag,
          commandText: redact ? `${tag} [REDACTED]` : `${tag} ${commandText}`,
          untagged: [],
          timer,
          resolve,
          reject
        };

        this.transport.write(wireLine, (err) => {
          if (err) {
            if (timer) clearTimeout(timer);
            this._currentCommand = null;
            reject(err);
          }
        });
      });
    });
  }

  /**
   * Connects to IMAP server, performs TLS handshake, and waits for greeting banner.
   *
   * @param {object} [config={}] - Connection parameters (host, port, secure, tls, provider)
   * @returns {Promise<string>} Server greeting line
   */
  async connect(config = {}) {
    if (this._state !== IMAP_STATES.DISCONNECTED) {
      throw new Error(`Cannot connect while in state ${this._state}`);
    }

    this.options = { ...this.options, ...config };
    this._setState(IMAP_STATES.CONNECTING);
    this._buffer = '';
    this._literalRemaining = 0;
    this._pendingLine = '';
    this.capabilities = [];

    if (config.transport) {
      this._detachTransportListeners();
      if (config.transport instanceof SocketTransport) {
        this.transport = config.transport;
      } else {
        this.transport = new SocketTransport({ socket: config.transport });
      }
    } else if (!this.transport || (this.transport.destroyed && !this._injectedTransport)) {
      this._detachTransportListeners();
      this.transport = new TlsSocketTransport(this.options);
    }

    this._attachTransportListeners(this.transport);

    const greetingTimeoutMs = config.connectionTimeoutMs || config.timeoutMs || this.options.connectionTimeoutMs || this.options.timeoutMs || 10000;

    let greetingTimer = null;
    const greetingPromise = new Promise((resolve, reject) => {
      greetingTimer = setTimeout(() => {
        this._greetingResolve = null;
        this._greetingReject = null;
        const err = createErrorByCode(
          ERROR_CODES.CONNECTION_TIMEOUT,
          `Connection timed out waiting for server greeting after ${greetingTimeoutMs}ms`,
          { provider: this.options.provider }
        );
        if (this.transport && !this.transport.destroyed) {
          this.transport.destroy();
        }
        reject(err);
      }, greetingTimeoutMs);

      this._greetingResolve = (line) => {
        if (greetingTimer) {
          clearTimeout(greetingTimer);
          greetingTimer = null;
        }
        resolve(line);
      };
      this._greetingReject = (err) => {
        if (greetingTimer) {
          clearTimeout(greetingTimer);
          greetingTimer = null;
        }
        reject(err);
      };
    });

    // Suppress unhandledRejection on greetingPromise in case connect() aborts early
    greetingPromise.catch(() => {});

    try {
      await this.transport.connect({
        host: this.options.host,
        port: this.options.port,
        secure: this.options.secure,
        timeout: greetingTimeoutMs,
        tls: this.options.tls
      });

      if (typeof this.transport.getTlsDetails === 'function') {
        this.tlsDetails = this.transport.getTlsDetails();
      } else if (typeof this.transport.getCipher === 'function') {
        const cipher = this.transport.getCipher();
        const protocol = typeof this.transport.getProtocol === 'function' ? this.transport.getProtocol() : 'Unknown';
        const cert = typeof this.transport.getPeerCertificate === 'function' ? this.transport.getPeerCertificate() : null;
        this.tlsDetails = {
          protocol: protocol || 'Unknown',
          cipherName: cipher?.name || 'Unknown',
          cipherVersion: cipher?.version || protocol || 'Unknown',
          authorized: this.transport.authorized ?? true,
          peerCertificate: cert
        };
      }

      const greeting = await greetingPromise;
      return greeting;
    } catch (err) {
      if (greetingTimer) {
        clearTimeout(greetingTimer);
        greetingTimer = null;
      }
      this._greetingResolve = null;
      this._greetingReject = null;

      if (this.transport && !this.transport.destroyed) {
        this.transport.destroy();
      }
      this._detachTransportListeners();

      if (this._state !== IMAP_STATES.DISCONNECTED) {
        this._setState(IMAP_STATES.DISCONNECTED);
      }
      const classified = isMailboxerError(err) ? err : classifySocketError(err, this.options.provider);
      throw classified;
    }
  }

  /**
   * Queries server capabilities via CAPABILITY command.
   *
   * @returns {Promise<string[]>} List of capability tokens
   */
  async capability() {
    if (!this.isConnected) {
      throw new Error(`Cannot query capabilities in state ${this._state}`);
    }

    const res = await this.sendCommand('CAPABILITY');
    const caps = parseCapabilities([res.line, ...res.untagged]);
    this._mergeCapabilities(caps);
    return this.capabilities;
  }

  /**
   * Authenticates with the IMAP server using LOGIN or XOAUTH2.
   *
   * @param {string} user - Username or email
   * @param {string} [pass] - Password or app-specific password
   * @param {object} [authOptions={}] - Optional auth configuration (type, accessToken)
   * @returns {Promise<{success: boolean, text: string}>}
   */
  async login(user, pass, authOptions = {}) {
    // Validate inputs against CRLF injection up front
    escapeImapString(user);
    if (pass !== undefined) {
      escapeImapString(pass);
    }

    if (this._state !== IMAP_STATES.CONNECTED) {
      throw new Error(`Cannot authenticate while in state ${this._state}`);
    }

    this._setState(IMAP_STATES.AUTHENTICATING);
    const authType = authOptions.type || 'password';

    try {
      let res;
      if (authType === 'oauth2') {
        const token = authOptions.accessToken || pass;
        const authStr = Buffer.from(`user=${user}\x01auth=Bearer ${token}\x01\x01`).toString('base64');
        res = await this.sendCommand(`AUTHENTICATE XOAUTH2 ${authStr}`, {
          redact: true,
          timeoutMs: this.options.authTimeoutMs
        });
      } else {
        const cmd = `LOGIN ${escapeImapString(user)} ${escapeImapString(pass)}`;
        res = await this.sendCommand(cmd, {
          redact: true,
          timeoutMs: this.options.authTimeoutMs
        });
      }

      this._setState(IMAP_STATES.AUTHENTICATED);
      return { success: true, text: res.rest };
    } catch (err) {
      if (this._state === IMAP_STATES.AUTHENTICATING) {
        this._setState(IMAP_STATES.CONNECTED);
      }
      throw err;
    }
  }

  /**
   * Queries status of a mailbox (default: "INBOX").
   *
   * @param {string} [mailbox='INBOX'] - Mailbox name
   * @param {string[]} [items=['MESSAGES', 'UNSEEN', 'RECENT', 'UIDNEXT', 'UIDVALIDITY']] - Status items
   * @returns {Promise<object>} Parsed MailboxStatus
   */
  async status(mailbox = 'INBOX', items = ['MESSAGES', 'UNSEEN', 'RECENT', 'UIDNEXT', 'UIDVALIDITY']) {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot query status in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    try {
      const itemsStr = items.join(' ');
      const res = await this.sendCommand(`STATUS ${escapeImapString(mailbox)} (${itemsStr})`);
      const parsed = parseStatusResponse(res.untagged, mailbox);

      return parsed || {
        mailbox,
        totalMessages: 0,
        unseen: 0,
        recent: 0,
        uidNext: null,
        uidValidity: null,
        raw: ''
      };
    } catch (err) {
      throw err;
    }
  }

  /**
   * Alias for status.
   *
   * @param {string} [mailbox='INBOX'] - Mailbox name
   * @param {string[]} [items] - Status items
   * @returns {Promise<object>} Parsed MailboxStatus
   */
  async getStatus(mailbox, items) {
    return this.status(mailbox, items);
  }

  /**
   * Discovers mailboxes / folders via IMAP LIST command.
   *
   * @param {string} [reference=''] - Reference name (default empty string)
   * @param {string} [pattern='*'] - Mailbox search pattern (default '*')
   * @returns {Promise<Array<{path: string, name: string, delimiter: string|null, flags: string[], selectable: boolean}>>}
   */
  async listMailboxes(reference = '', pattern = '*') {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot list mailboxes in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    const res = await this.sendCommand(`LIST ${escapeImapString(reference)} ${escapeImapString(pattern)}`);
    return parseListResponse(res.untagged);
  }

  /**
   * Alias for listMailboxes.
   */
  async list(reference, pattern) {
    return this.listMailboxes(reference, pattern);
  }

  /**
   * Selects an IMAP mailbox, entering SELECTED state and extracting metadata.
   *
   * @param {string} [mailbox='INBOX'] - Mailbox name
   * @param {boolean} [readOnly=false] - Whether to use EXAMINE instead of SELECT
   * @returns {Promise<object>} Parsed mailbox metadata
   */
  async selectMailbox(mailbox = 'INBOX', readOnly = false) {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot select mailbox in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    const verb = readOnly ? 'EXAMINE' : 'SELECT';
    const res = await this.sendCommand(`${verb} ${escapeImapString(mailbox)}`);
    return parseSelectResponse(res.untagged, mailbox, res.line);
  }

  /**
   * Alias for selectMailbox.
   */
  async select(mailbox, readOnly) {
    return this.selectMailbox(mailbox, readOnly);
  }

  /**
   * Searches for message UIDs matching criteria (e.g. 'ALL', 'UNSEEN', 'UID 100:*').
   *
   * @param {string} [criteria='ALL'] - Search criteria
   * @returns {Promise<number[]>} Array of integer UIDs
   */
  async searchUids(criteria = 'ALL') {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot search UIDs in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    const res = await this.sendCommand(`UID SEARCH ${criteria}`);
    return parseSearchResponse(res.untagged);
  }

  /**
   * Alias for searchUids.
   */
  async uidSearch(criteria) {
    return this.searchUids(criteria);
  }

  /**
   * Fetches message headers, flags, and snippets via UID FETCH.
   * Crucially uses BODY.PEEK to prevent clearing remote \Seen flags during background sync.
   *
   * @param {string|number} uidRange - UID sequence set (e.g. '1:100', '101', '101,102')
   * @param {object} [options={}]
   * @param {string[]} [options.items] - Optional custom fetch items
   * @returns {Promise<object[]>} Parsed message records
   */
  async fetchMessages(uidRange, options = {}) {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot fetch messages in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    const defaultItems = [
      'UID',
      'FLAGS',
      'RFC822.SIZE',
      'BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC BCC SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES LIST-UNSUBSCRIBE PRECEDENCE)]',
      'BODY.PEEK[TEXT]<0.1000>'
    ];

    const items = options.items || defaultItems;
    const itemsStr = items.join(' ');
    const range = String(uidRange);

    const res = await this.sendCommand(`UID FETCH ${range} (${itemsStr})`);
    return parseFetchResponses(res.untagged);
  }

  /**
   * Alias for fetchMessages.
   */
  async uidFetch(uidRange, options) {
    return this.fetchMessages(uidRange, options);
  }

  /**
   * Modifies flags on remote messages via UID STORE.
   *
   * @param {string|number} uid - UID or range
   * @param {string[]|string} flags - Flags to store
   * @param {string} [mode='+FLAGS'] - Operation mode ('+FLAGS', '-FLAGS', 'FLAGS')
   * @returns {Promise<object>} Command execution result
   */
  async storeFlags(uid, flags, mode = '+FLAGS') {
    if (!this.isAuthenticated) {
      throw new Error(`Cannot store flags in unauthenticated state ${this._state}`);
    }

    if (this._state !== IMAP_STATES.QUERYING) {
      this._setState(IMAP_STATES.QUERYING);
    }

    let action = mode.toUpperCase();
    if (action === 'ADD' || action === '+') action = '+FLAGS';
    else if (action === 'REMOVE' || action === '-') action = '-FLAGS';
    else if (action === 'SET' || action === 'REPLACE') action = 'FLAGS';

    const flagsArr = Array.isArray(flags) ? flags : [flags];
    const flagsStr = flagsArr.join(' ');

    const res = await this.sendCommand(`UID STORE ${uid} ${action} (${flagsStr})`);
    return res;
  }

  /**
   * Alias for storeFlags.
   */
  async uidStore(uid, flags, mode) {
    return this.storeFlags(uid, flags, mode);
  }

  /**
   * Enters RFC 2177 IDLE state.
   * Sends "tag IDLE\r\n", waits for "+ idling" or "+" continuation line,
   * transitions state to IMAP_STATES.IDLE, and emits 'idle'.
   *
   * @param {object} [options={}]
   * @param {number} [options.timeoutMs] - Continuation wait timeout
   * @returns {Promise<{tag: string, line: string}>}
   */
  async idle(options = {}) {
    if (!this.transport) {
      throw new Error('Cannot start IDLE: transport is not connected');
    }
    if (!this.isAuthenticated) {
      throw new Error(`Cannot start IDLE in state ${this._state} (must be AUTHENTICATED)`);
    }
    if (this._state === IMAP_STATES.IDLE) {
      return { tag: this._idleTag, line: '+ idling' };
    }

    return this._commandQueue.enqueue(async () => {
      if (this._state === IMAP_STATES.IDLE) {
        return { tag: this._idleTag, line: '+ idling' };
      }

      const tag = this._nextTag();
      const timeoutMs = options.timeoutMs ?? this.options.commandTimeoutMs ?? 10000;
      const wireLine = `${tag} IDLE\r\n`;

      return new Promise((resolve, reject) => {
        let timer = null;
        if (timeoutMs > 0) {
          timer = setTimeout(() => {
            if (this._currentCommand && this._currentCommand.tag === tag) {
              this._currentCommand = null;
              this._idleTag = null;
              const err = createErrorByCode(
                ERROR_CODES.CONNECTION_TIMEOUT,
                `IDLE continuation timed out after ${timeoutMs}ms`,
                { provider: this.options.provider }
              );
              reject(err);
            }
          }, timeoutMs);
        }

        this._idleTag = tag;
        this._currentCommand = {
          tag,
          commandText: `${tag} IDLE`,
          untagged: [],
          timer,
          onContinuation: (line) => {
            if (timer) clearTimeout(timer);
            this._setState(IMAP_STATES.IDLE);
            this.emit('idle', { tag, line });
            resolve({ tag, line });
          },
          resolve: (res) => {
            if (timer) clearTimeout(timer);
            resolve(res);
          },
          reject: (err) => {
            if (timer) clearTimeout(timer);
            this._idleTag = null;
            reject(err);
          }
        };

        this.transport.write(wireLine);
      });
    });
  }

  /**
   * Exits RFC 2177 IDLE state by sending "DONE\r\n".
   * Awaits tagged OK completion, transitions back to IMAP_STATES.AUTHENTICATED.
   *
   * @param {object} [options={}]
   * @param {number} [options.timeoutMs] - Completion wait timeout
   * @returns {Promise<{tag: string, status: string, line: string}>}
   */
  async done(options = {}) {
    if (this._state !== IMAP_STATES.IDLE) {
      return { tag: this._idleTag || 'A0000', status: 'OK', line: 'OK Not in IDLE state' };
    }

    const tag = this._idleTag;
    const timeoutMs = options.timeoutMs ?? this.options.commandTimeoutMs ?? 10000;

    return new Promise((resolve, reject) => {
      let timer = null;
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          if (this._currentCommand && this._currentCommand.tag === tag) {
            this._currentCommand = null;
            this._idleTag = null;
            this._setState(IMAP_STATES.AUTHENTICATED);
            const err = createErrorByCode(
              ERROR_CODES.CONNECTION_TIMEOUT,
              `IDLE completion (DONE) timed out after ${timeoutMs}ms`,
              { provider: this.options.provider }
            );
            reject(err);
          }
        }, timeoutMs);
      }

      if (this._currentCommand) {
        this._currentCommand.timer = timer;
        this._currentCommand.resolve = (res) => {
          if (timer) clearTimeout(timer);
          this._idleTag = null;
          this._setState(IMAP_STATES.AUTHENTICATED);
          this.emit('idleDone', res);
          resolve(res);
        };
        this._currentCommand.reject = (err) => {
          if (timer) clearTimeout(timer);
          this._idleTag = null;
          this._setState(IMAP_STATES.AUTHENTICATED);
          reject(err);
        };
      } else {
        this._currentCommand = {
          tag,
          commandText: 'DONE',
          untagged: [],
          timer,
          resolve: (res) => {
            if (timer) clearTimeout(timer);
            this._idleTag = null;
            this._setState(IMAP_STATES.AUTHENTICATED);
            this.emit('idleDone', res);
            resolve(res);
          },
          reject: (err) => {
            if (timer) clearTimeout(timer);
            this._idleTag = null;
            this._setState(IMAP_STATES.AUTHENTICATED);
            reject(err);
          }
        };
      }

      this.transport.write('DONE\r\n');
    });
  }

  /**
   * Cleanly logs out from the IMAP session and closes the socket transport.
   *
   * @returns {Promise<void>}
   */
  async logout() {
    if (this._state === IMAP_STATES.DISCONNECTED || this._state === IMAP_STATES.CLOSING) {
      return;
    }

    if (this._state === IMAP_STATES.IDLE) {
      try {
        await this.done({ timeoutMs: 1500 });
      } catch {
        // Ignore exit IDLE error on teardown
      }
    }

    this._setState(IMAP_STATES.CLOSING);

    try {
      if (this.transport && !this.transport.destroyed) {
        await this.sendCommand('LOGOUT', { timeoutMs: 2000 });
      }
    } catch {
      // Ignore errors during logout - socket is being torn down
    }

    if (this.transport && !this.transport.destroyed) {
      await new Promise((resolve) => {
        let finished = false;
        let timer = null;
        const done = () => {
          if (!finished) {
            finished = true;
            if (timer) clearTimeout(timer);
            resolve();
          }
        };

        this.once('close', done);
        if (this.transport.destroyed) {
          done();
          return;
        }

        try {
          this.transport.end();
        } catch {
          // Ignore error if socket is already closing/closed
        }

        timer = setTimeout(() => {
          if (!finished) {
            finished = true;
            if (this.transport && !this.transport.destroyed) {
              this.transport.destroy();
            }
            resolve();
          }
        }, 1500);
        if (timer.unref) timer.unref();
      });
    }

    if (this._state !== IMAP_STATES.DISCONNECTED) {
      this._setState(IMAP_STATES.DISCONNECTED);
    }
    this._detachTransportListeners();
  }

  /**
   * Executes connection, capability query, authentication, INBOX status, and logout.
   * Throws classified MailboxerError on any failure.
   *
   * @param {object} [accountConfig] - Optional account configuration
   * @returns {Promise<object>} DiagnosticResult
   */
  async connectAndVerify(accountConfig) {
    const config = accountConfig || this.accountConfig || this.options.accountConfig || this.options;
    const startTime = performance.now();
    let connectStart = 0;
    let authStart = 0;
    let queryStart = 0;

    const metrics = {
      connectDurationMs: 0,
      authDurationMs: 0,
      mailboxQueryDurationMs: 0,
      totalDurationMs: 0
    };

    try {
      // 1. Connect & Greeting
      connectStart = performance.now();
      await this.connect({
        host: config.imap?.host || config.host || this.options.host,
        port: config.imap?.port || config.port || this.options.port,
        secure: config.imap?.secure ?? config.secure ?? this.options.secure,
        tls: config.imap?.tls || config.tls || this.options.tls,
        connectionTimeoutMs: config.imap?.connectionTimeoutMs || config.connectionTimeoutMs || this.options.connectionTimeoutMs || this.options.timeoutMs,
        provider: config.provider || this.options.provider
      });
      metrics.connectDurationMs = Math.round(performance.now() - connectStart);

      // 2. Capabilities
      await this.capability();

      // 3. Authenticate
      authStart = performance.now();
      const user = config.auth?.user || config.email || this.options.user;
      const pass = config.auth?.pass || this.options.pass;
      await this.login(user, pass, {
        type: config.auth?.type,
        accessToken: config.auth?.accessToken
      });
      metrics.authDurationMs = Math.round(performance.now() - authStart);

      // 4. Status INBOX
      queryStart = performance.now();
      const inboxStatus = await this.status('INBOX');
      metrics.mailboxQueryDurationMs = Math.round(performance.now() - queryStart);

      // 5. Clean LOGOUT
      await this.logout();
      metrics.totalDurationMs = Math.round(performance.now() - startTime);

      this.metrics = metrics;

      return {
        accountId: config.id || 'unknown',
        provider: config.provider || this.options.provider || 'unknown',
        success: true,
        tlsDetails: this.tlsDetails ? {
          protocol: this.tlsDetails.protocol,
          cipherName: this.tlsDetails.cipherName,
          cipherVersion: this.tlsDetails.cipherVersion,
          authorized: this.tlsDetails.authorized
        } : undefined,
        capabilities: this.capabilities,
        inboxStatus: inboxStatus ? {
          totalMessages: inboxStatus.totalMessages,
          unseen: inboxStatus.unseen,
          recent: inboxStatus.recent
        } : undefined,
        metrics
      };
    } catch (err) {
      metrics.totalDurationMs = Math.round(performance.now() - startTime);
      this.metrics = metrics;

      try {
        if (this.transport && !this.transport.destroyed) {
          this.transport.destroy();
        }
      } catch {
        // ignore teardown errors
      }

      const classified = isMailboxerError(err)
        ? err
        : classifySocketError(err, config.provider || this.options.provider);

      throw classified;
    }
  }

  /**
   * Executes a complete verification pipeline for an account configuration.
   * Catches errors and returns DiagnosticResult object without throwing.
   *
   * @param {object} [accountConfig] - Resolved account configuration
   * @returns {Promise<object>} DiagnosticResult
   */
  async verify(accountConfig) {
    const config = accountConfig || this.accountConfig || this.options.accountConfig || this.options;
    try {
      return await this.connectAndVerify(config);
    } catch (err) {
      const classified = isMailboxerError(err)
        ? err
        : classifySocketError(err, config?.provider || this.options.provider);

      return {
        accountId: config?.id || 'unknown',
        provider: config?.provider || this.options.provider || 'unknown',
        success: false,
        capabilities: this.capabilities,
        metrics: this.metrics,
        error: {
          code: classified.code,
          message: classified.message,
          remediationAdvice: classified.remediation || classified.details?.remediationAdvice || ''
        }
      };
    }
  }
}
