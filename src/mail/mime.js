/**
 * Zero-dependency MIME (RFC 2045-2047, 2231) parser and builder.
 *
 * - parseMessage(raw): full RFC 822 message -> headers, text, html, attachment list
 * - getAttachment(raw, index): extract one attachment's bytes
 * - decodeHeaderValue(str): RFC 2047 encoded-word decoding with real charsets
 * - buildMessage(opts): compose a UTF-8 text/plain message for SMTP sending
 *
 * Raw messages are handled as Buffers (or latin1 "byte strings") so 8-bit
 * content in any charset survives until it is decoded with TextDecoder.
 *
 * @module mail/mime
 */

import crypto from 'node:crypto';

const MAX_DEPTH = 20;
const MAX_PARTS = 500;
const MAX_INLINE_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_INLINE_BYTES = 8 * 1024 * 1024;

// ==========================================
// CHARSETS & ENCODINGS
// ==========================================

/**
 * Decodes bytes with a MIME charset label, falling back to UTF-8 then latin1.
 * @param {Buffer} buf
 * @param {string} [charset]
 * @returns {string}
 */
export function decodeBytes(buf, charset) {
  const label = String(charset || 'utf-8').trim().toLowerCase().replace(/^"|"$/g, '');
  const normalized = label === 'us-ascii' || label === 'ascii' ? 'utf-8' : label;
  try {
    return new TextDecoder(normalized, { fatal: false }).decode(buf);
  } catch {
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(buf);
    } catch {
      return buf.toString('latin1');
    }
  }
}

/**
 * Decodes quoted-printable text into raw bytes.
 * @param {string} str - latin1 byte string
 * @returns {Buffer}
 */
export function decodeQuotedPrintableBytes(str) {
  const s = String(str || '').replace(/=\r?\n/g, '');
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(s.charCodeAt(i) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/**
 * Decodes RFC 2047 encoded words (=?charset?B|Q?data?=), joining adjacent words.
 * Raw 8-bit header bytes are assumed to already be decoded as UTF-8 by the caller.
 * @param {string} str
 * @returns {string}
 */
export function decodeHeaderValue(str) {
  if (!str || typeof str !== 'string') return '';
  // Whitespace between two encoded words is not significant (RFC 2047 §6.2)
  const joined = str.replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?)/g, '$1');

  // Group consecutive words with the same charset so multi-byte characters split
  // across words decode correctly.
  return joined.replace(/(?:=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=)+/g, (run) => {
    const words = [...run.matchAll(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g)];
    let out = '';
    let pending = [];
    let pendingCharset = null;
    const flush = () => {
      if (pending.length) out += decodeBytes(Buffer.concat(pending), pendingCharset);
      pending = [];
    };
    for (const [, rawCharset, enc, data] of words) {
      const charset = rawCharset.split('*')[0]; // strip RFC 2231 language tag
      let bytes;
      try {
        bytes = enc.toUpperCase() === 'B'
          ? Buffer.from(data, 'base64')
          : decodeQuotedPrintableBytes(data.replace(/_/g, ' '));
      } catch {
        bytes = Buffer.from(data, 'latin1');
      }
      if (pendingCharset && pendingCharset.toLowerCase() !== charset.toLowerCase()) flush();
      pendingCharset = charset;
      pending.push(bytes);
    }
    flush();
    return out;
  });
}

// ==========================================
// HEADERS
// ==========================================

/**
 * Splits a raw part into header text and body (both latin1 byte strings).
 * @param {string} raw
 */
function splitHeaderBody(raw) {
  const m = raw.match(/\r?\n\r?\n/);
  if (!m) {
    // A part with only headers, or only a body
    return /^[A-Za-z0-9-]+:/.test(raw) ? { headerText: raw, body: '' } : { headerText: '', body: raw };
  }
  return { headerText: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

/**
 * Parses a header block into a Map of lowercase name -> array of raw values.
 * Values are decoded from bytes as UTF-8 but encoded words are left intact.
 * @param {string} headerText - latin1 byte string
 * @returns {Map<string, string[]>}
 */
function parseHeaderBlock(headerText) {
  const map = new Map();
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = Buffer.from(line.slice(idx + 1).trim(), 'latin1').toString('utf8');
    if (!map.has(name)) map.set(name, []);
    map.get(name).push(value);
  }
  return map;
}

function first(map, name) {
  const v = map.get(name);
  return v && v.length ? v[0] : '';
}

/**
 * Parses a structured header value like `text/plain; charset="utf-8"; name*=UTF-8''r%C3%A9.pdf`.
 * Supports RFC 2231 extended and continued parameters.
 * @param {string} value
 * @returns {{ value: string, params: Record<string, string> }}
 */
export function parseStructuredHeader(value) {
  const str = String(value || '');
  const parts = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '"' && str[i - 1] !== '\\') inQuote = !inQuote;
    if (ch === ';' && !inQuote) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  parts.push(cur);

  const main = (parts.shift() || '').trim().toLowerCase();
  const raw = {};
  for (const p of parts) {
    const eq = p.indexOf('=');
    if (eq === -1) continue;
    const key = p.slice(0, eq).trim().toLowerCase();
    let val = p.slice(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1).replace(/\\(.)/g, '$1');
    raw[key] = val;
  }

  // Combine RFC 2231 continuations: name*0*=..., name*1*=...
  const params = {};
  const continued = {};
  for (const [key, val] of Object.entries(raw)) {
    const m = key.match(/^([^*]+)\*(\d+)(\*?)$/);
    if (m) {
      (continued[m[1]] ||= []).push({ n: Number(m[2]), val, encoded: Boolean(m[3]) });
      continue;
    }
    const ext = key.match(/^([^*]+)\*$/);
    if (ext) {
      params[ext[1]] = decodeRfc2231(val, true);
    } else if (params[key] === undefined) {
      params[key] = decodeHeaderValue(val);
    }
  }
  for (const [name, pieces] of Object.entries(continued)) {
    pieces.sort((a, b) => a.n - b.n);
    const charsetMatch = pieces[0].encoded ? pieces[0].val.match(/^([^']*)'[^']*'/) : null;
    const charset = charsetMatch ? charsetMatch[1] : 'utf-8';
    const bytes = [];
    pieces.forEach((piece, i) => {
      let v = piece.val;
      if (i === 0 && charsetMatch) v = v.slice(charsetMatch[0].length);
      bytes.push(piece.encoded ? percentDecodeBytes(v) : Buffer.from(v, 'utf8'));
    });
    params[name] = decodeBytes(Buffer.concat(bytes), charset);
  }

  return { value: main, params };
}

function percentDecodeBytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(str.slice(i + 1, i + 3))) {
      bytes.push(parseInt(str.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(...Buffer.from(str[i], 'utf8'));
    }
  }
  return Buffer.from(bytes);
}

function decodeRfc2231(val) {
  const m = val.match(/^([^']*)'[^']*'(.*)$/);
  if (!m) return val;
  return decodeBytes(percentDecodeBytes(m[2]), m[1] || 'utf-8');
}

// ==========================================
// MIME TREE
// ==========================================

/**
 * Parses one MIME entity (recursively for multiparts).
 * @param {string} raw - latin1 byte string
 * @param {number} depth
 * @param {{count: number}} counter
 */
function parseEntity(raw, depth, counter) {
  counter.count++;
  const { headerText, body } = splitHeaderBody(raw);
  const headers = parseHeaderBlock(headerText);
  const ct = parseStructuredHeader(first(headers, 'content-type') || 'text/plain; charset=us-ascii');
  const cd = parseStructuredHeader(first(headers, 'content-disposition'));
  const entity = {
    headers,
    contentType: ct.value || 'text/plain',
    params: ct.params,
    disposition: cd.value || '',
    dispositionParams: cd.params,
    transferEncoding: first(headers, 'content-transfer-encoding').trim().toLowerCase(),
    contentId: first(headers, 'content-id').trim().replace(/^<|>$/g, ''),
    body,
    children: []
  };

  if (entity.contentType.startsWith('multipart/') && entity.params.boundary && depth < MAX_DEPTH) {
    const boundary = entity.params.boundary;
    const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const delimiter = new RegExp(`(?:^|\\r?\\n)--${escaped}(--)?[ \\t]*(?=\\r?\\n|$)`, 'g');
    let lastIndex = null;
    let match;
    while ((match = delimiter.exec(body)) !== null) {
      if (lastIndex !== null && counter.count < MAX_PARTS) {
        const partRaw = body.slice(lastIndex, match.index).replace(/^\r?\n/, '');
        entity.children.push(parseEntity(partRaw, depth + 1, counter));
      }
      if (match[1]) break; // closing delimiter
      lastIndex = match.index + match[0].length;
    }
  }
  return entity;
}

/**
 * Returns a leaf part's decoded bytes.
 * @param {object} entity
 * @returns {Buffer}
 */
function decodeEntityBody(entity) {
  const body = entity.body || '';
  if (entity.transferEncoding === 'base64') {
    return Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  }
  if (entity.transferEncoding === 'quoted-printable') {
    return decodeQuotedPrintableBytes(body);
  }
  return Buffer.from(body, 'latin1');
}

function entityFilename(entity) {
  return entity.dispositionParams.filename || entity.params.name || '';
}

function isAttachmentEntity(entity) {
  if (entity.disposition === 'attachment') return true;
  const isTextBody = entity.contentType === 'text/plain' || entity.contentType === 'text/html';
  if (isTextBody && !entityFilename(entity)) return false;
  return !entity.contentType.startsWith('multipart/');
}

/** Depth-first list of leaf entities. */
function leaves(entity, out = []) {
  if (entity.children.length > 0) {
    for (const child of entity.children) leaves(child, out);
  } else {
    out.push(entity);
  }
  return out;
}

function toBuffer(raw) {
  if (Buffer.isBuffer(raw)) return raw;
  return Buffer.from(String(raw || ''), 'utf8');
}

function defaultFilename(entity, index) {
  const ext = {
    'message/rfc822': 'eml',
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/gif': 'gif',
    'text/calendar': 'ics',
    'text/plain': 'txt',
    'text/html': 'html'
  }[entity.contentType] || 'bin';
  return `attachment-${index + 1}.${ext}`;
}

/**
 * Removes active content from email HTML. The result is still meant to be shown
 * in a sandboxed iframe with a restrictive CSP; this is defense in depth.
 * @param {string} html
 * @returns {string}
 */
export function sanitizeHtml(html) {
  return String(html || '')
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<script\b[^>]*>/gi, '')
    .replace(/<(iframe|frame|frameset|object|embed|applet|form|base|meta|link)\b[\s\S]*?>/gi, '')
    .replace(/<\/(iframe|frame|frameset|object|embed|applet|form)\s*>/gi, '')
    .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(href|src|action|formaction|xlink:href)\s*=\s*(["']?)\s*(javascript|vbscript|data:text\/html)[^"'\s>]*\2/gi, '$1="#"');
}

/**
 * Parses a complete RFC 822 message.
 *
 * @param {Buffer|string} raw
 * @param {object} [options]
 * @param {boolean} [options.inlineImages=true] - Replace cid: references with data: URIs
 * @returns {{
 *   headers: object, text: string, html: string,
 *   attachments: Array<{index: number, filename: string, contentType: string, size: number, contentId: string, inline: boolean}>
 * }}
 */
export function parseMessage(raw, options = {}) {
  const latin1 = toBuffer(raw).toString('latin1');
  const root = parseEntity(latin1, 0, { count: 0 });

  const h = root.headers;
  const headers = {
    subject: decodeHeaderValue(first(h, 'subject')),
    from: decodeHeaderValue(first(h, 'from')),
    to: decodeHeaderValue((h.get('to') || []).join(', ')),
    cc: decodeHeaderValue((h.get('cc') || []).join(', ')),
    replyTo: decodeHeaderValue(first(h, 'reply-to')),
    date: first(h, 'date'),
    messageId: first(h, 'message-id').trim(),
    inReplyTo: first(h, 'in-reply-to').trim(),
    references: first(h, 'references').trim(),
    listUnsubscribe: first(h, 'list-unsubscribe').trim()
  };

  let text = '';
  let html = '';
  const attachments = [];
  const inlineById = new Map();

  leaves(root).forEach((leaf) => {
    if (isAttachmentEntity(leaf)) {
      const content = decodeEntityBody(leaf);
      const index = attachments.length;
      const att = {
        index,
        filename: entityFilename(leaf) || defaultFilename(leaf, index),
        contentType: leaf.contentType,
        size: content.length,
        contentId: leaf.contentId || '',
        inline: leaf.disposition === 'inline' || Boolean(leaf.contentId && leaf.contentType.startsWith('image/'))
      };
      attachments.push(att);
      if (att.contentId && leaf.contentType.startsWith('image/')) inlineById.set(att.contentId, { att, content });
      return;
    }
    const decoded = decodeBytes(decodeEntityBody(leaf), leaf.params.charset);
    if (leaf.contentType === 'text/html') {
      if (!html) html = decoded;
    } else if (!text) {
      text = decoded;
    }
  });

  if (html) {
    html = sanitizeHtml(html);
    if (options.inlineImages !== false && inlineById.size > 0) {
      let budget = MAX_TOTAL_INLINE_BYTES;
      html = html.replace(/cid:([^"'\s)>]+)/gi, (whole, id) => {
        const hit = inlineById.get(decodeURIComponent(id));
        if (!hit || hit.content.length > MAX_INLINE_IMAGE_BYTES || hit.content.length > budget) return whole;
        budget -= hit.content.length;
        return `data:${hit.att.contentType};base64,${hit.content.toString('base64')}`;
      });
    }
  }

  if (!text && html) {
    text = htmlToText(html);
  }

  return { headers, text: text.replace(/\r\n/g, '\n'), html, attachments };
}

/**
 * Extracts one attachment (by index from parseMessage) as bytes.
 * @param {Buffer|string} raw
 * @param {number} index
 * @returns {{filename: string, contentType: string, content: Buffer}|null}
 */
export function getAttachment(raw, index) {
  const latin1 = toBuffer(raw).toString('latin1');
  const root = parseEntity(latin1, 0, { count: 0 });
  const atts = leaves(root).filter(isAttachmentEntity);
  const leaf = atts[Number(index)];
  if (!leaf) return null;
  return {
    filename: entityFilename(leaf) || defaultFilename(leaf, Number(index)),
    contentType: leaf.contentType,
    content: decodeEntityBody(leaf)
  };
}

/**
 * Converts HTML to readable plain text (keeps paragraph breaks).
 * @param {string} html
 * @returns {string}
 */
export function htmlToText(html) {
  return String(html || '')
    .replace(/<(style|script|head)\b[\s\S]*?<\/\1>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|h[1-6]|li|blockquote)>/gi, '\n')
    .replace(/<li\b[^>]*>/gi, '• ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/gi, '&')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ==========================================
// BUILDING OUTGOING MESSAGES
// ==========================================

/** RFC 2047 B-encodes a header value when it isn't plain ASCII. */
export function encodeHeaderValue(value) {
  const str = String(value || '');
  if (/^[\x20-\x7e]*$/.test(str)) return str;
  // Split into chunks that stay under the 75-char encoded-word limit
  const words = [];
  let chunk = '';
  for (const ch of str) {
    if (Buffer.byteLength(chunk + ch, 'utf8') > 45) {
      words.push(chunk);
      chunk = '';
    }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map(w => `=?UTF-8?B?${Buffer.from(w, 'utf8').toString('base64')}?=`).join(' ');
}

/** Formats a display-name + address, encoding the name if needed. */
export function formatAddress(name, email) {
  if (!name) return email;
  const encoded = /^[\x20-\x7e]*$/.test(name)
    ? `"${String(name).replace(/["\\]/g, '\\$&')}"`
    : encodeHeaderValue(name);
  return `${encoded} <${email}>`;
}

/**
 * Splits a comma/semicolon separated recipient string into addresses.
 * @param {string|string[]} value
 * @returns {string[]} Bare email addresses
 */
export function parseAddressList(value) {
  const list = Array.isArray(value) ? value.join(',') : String(value || '');
  const out = [];
  for (const part of list.split(/[,;](?=(?:[^"]*"[^"]*")*[^"]*$)/)) {
    const p = part.trim();
    if (!p) continue;
    const angle = p.match(/<([^>]+)>/);
    const email = (angle ? angle[1] : p).trim();
    if (/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) out.push(email);
  }
  return out;
}

function wrapBase64(buf) {
  return buf.toString('base64').replace(/.{1,76}/g, '$&\r\n').trimEnd();
}

/**
 * Builds a UTF-8 text/plain RFC 5322 message.
 *
 * @param {object} opts
 * @param {string} opts.from - Sender address
 * @param {string} [opts.fromName]
 * @param {string[]} opts.to
 * @param {string[]} [opts.cc]
 * @param {string} opts.subject
 * @param {string} opts.text
 * @param {string} [opts.inReplyTo] - Message-ID being replied to
 * @param {string} [opts.references]
 * @param {Date} [opts.date]
 * @returns {{ raw: string, messageId: string }}
 */
export function buildMessage(opts) {
  const domain = String(opts.from).split('@')[1] || 'mailboxer.local';
  const messageId = `<${crypto.randomUUID()}@${domain}>`;
  const headers = [
    `From: ${formatAddress(opts.fromName, opts.from)}`,
    `To: ${opts.to.join(', ')}`
  ];
  if (opts.cc && opts.cc.length) headers.push(`Cc: ${opts.cc.join(', ')}`);
  headers.push(
    `Subject: ${encodeHeaderValue(opts.subject || '')}`,
    `Date: ${(opts.date || new Date()).toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: ${messageId}`
  );
  if (opts.inReplyTo) headers.push(`In-Reply-To: ${opts.inReplyTo}`);
  const refs = [opts.references, opts.inReplyTo].filter(Boolean).join(' ').trim();
  if (refs) headers.push(`References: ${refs}`);
  headers.push(
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    'User-Agent: Mailboxer'
  );

  const body = String(opts.text || '').replace(/\r?\n/g, '\r\n');
  return {
    raw: `${headers.join('\r\n')}\r\n\r\n${wrapBase64(Buffer.from(body, 'utf8'))}\r\n`,
    messageId
  };
}
