import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeHeaderValue,
  parseStructuredHeader,
  parseMessage,
  getAttachment,
  sanitizeHtml,
  htmlToText,
  buildMessage,
  parseAddressList,
  encodeHeaderValue
} from '../../src/mail/mime.js';

const CRLF = '\r\n';

describe('MIME headers (src/mail/mime.js)', () => {
  it('decodes B and Q encoded words, joining adjacent words', () => {
    assert.equal(decodeHeaderValue('=?UTF-8?B?w6l0w6k=?='), 'été');
    assert.equal(decodeHeaderValue('=?ISO-8859-1?Q?Caf=E9_au_lait?='), 'Café au lait');
    assert.equal(decodeHeaderValue('=?UTF-8?Q?a?= =?UTF-8?Q?b?= plain'), 'ab plain');
  });

  it('decodes a multi-byte character split across two words', () => {
    const bytes = Buffer.from('€', 'utf8');
    const a = bytes.subarray(0, 1).toString('base64');
    const b = bytes.subarray(1).toString('base64');
    assert.equal(decodeHeaderValue(`=?UTF-8?B?${a}?= =?UTF-8?B?${b}?=`), '€');
  });

  it('parses RFC 2231 extended and continued parameters', () => {
    const p = parseStructuredHeader("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf");
    assert.equal(p.value, 'attachment');
    assert.equal(p.params.filename, 'résumé.pdf');
    const c = parseStructuredHeader('attachment; filename*0="long"; filename*1="name.txt"');
    assert.equal(c.params.filename, 'longname.txt');
  });

  it('round-trips non-ASCII subjects through encodeHeaderValue', () => {
    const subject = 'Привет, мир — a fairly long subject line that needs several words';
    assert.equal(decodeHeaderValue(encodeHeaderValue(subject)), subject);
    assert.equal(encodeHeaderValue('plain ascii'), 'plain ascii');
  });
});

describe('parseMessage', () => {
  const png = Buffer.from('89504e470d0a1a0a', 'hex');
  const raw = [
    'From: =?UTF-8?Q?Ren=C3=A9?= <rene@example.com>',
    'To: me@example.com',
    'Subject: =?UTF-8?B?UmVwb3J0IOKckw==?=',
    'Message-ID: <abc@example.com>',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: multipart/related; boundary="rel"',
    '',
    '--rel',
    'Content-Type: multipart/alternative; boundary="alt"',
    '',
    '--alt',
    'Content-Type: text/plain; charset=iso-8859-1',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Caf=E9 menu=',
    ' today',
    '--alt',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p onclick="steal()">Hi <img src="cid:logo@x"></p><script>alert(1)</script><a href="javascript:evil()">x</a>',
    '--alt--',
    '--rel',
    'Content-Type: image/png',
    'Content-ID: <logo@x>',
    'Content-Transfer-Encoding: base64',
    '',
    png.toString('base64'),
    '--rel--',
    '--outer',
    'Content-Type: application/pdf; name="fallback.pdf"',
    "Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf",
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('%PDF-1.4 fake').toString('base64'),
    '--outer--',
    ''
  ].join(CRLF);

  it('extracts headers, text and html from nested multiparts', () => {
    const msg = parseMessage(raw);
    assert.equal(msg.headers.from, 'René <rene@example.com>');
    assert.equal(msg.headers.subject, 'Report ✓');
    assert.equal(msg.headers.messageId, '<abc@example.com>');
    assert.equal(msg.text, 'Café menu today');
    assert.match(msg.html, /Hi/);
  });

  it('sanitizes html and inlines cid images', () => {
    const { html } = parseMessage(raw);
    assert.doesNotMatch(html, /<script/i);
    assert.doesNotMatch(html, /onclick/i);
    assert.doesNotMatch(html, /javascript:/i);
    assert.match(html, /src="data:image\/png;base64,/);
  });

  it('lists attachments with decoded filenames and sizes', () => {
    const { attachments } = parseMessage(raw);
    assert.equal(attachments.length, 2);
    assert.equal(attachments[0].contentType, 'image/png');
    assert.equal(attachments[0].inline, true);
    assert.equal(attachments[1].filename, 'résumé.pdf');
    assert.equal(attachments[1].inline, false);
    assert.equal(attachments[1].size, Buffer.from('%PDF-1.4 fake').length);
  });

  it('getAttachment returns the decoded bytes', () => {
    const att = getAttachment(raw, 1);
    assert.equal(att.content.toString(), '%PDF-1.4 fake');
    assert.equal(getAttachment(raw, 1).filename, 'résumé.pdf');
    assert.equal(getAttachment(raw, 9), null);
    assert.deepEqual(getAttachment(raw, 0).content, png);
  });

  it('handles a plain single-part message with 8-bit UTF-8 bytes', () => {
    const buf = Buffer.from(`Subject: hi${CRLF}Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}naïve ☕${CRLF}`, 'utf8');
    const msg = parseMessage(buf);
    assert.equal(msg.text.trim(), 'naïve ☕');
    assert.equal(msg.html, '');
    assert.equal(msg.attachments.length, 0);
  });

  it('falls back to text derived from html', () => {
    const msg = parseMessage(`Content-Type: text/html${CRLF}${CRLF}<p>One</p><p>Two &amp; three</p>`);
    assert.equal(msg.text, 'One\nTwo & three');
  });
});

describe('sanitizeHtml / htmlToText', () => {
  it('strips active content', () => {
    const out = sanitizeHtml('<iframe src="x"></iframe><form action="y"><input></form><img src=x onerror=alert(1)><meta http-equiv="refresh">');
    assert.doesNotMatch(out, /iframe|<form|onerror|<meta/i);
  });

  it('converts lists and breaks', () => {
    assert.equal(htmlToText('<ul><li>a</li><li>b</li></ul>line<br>next'), '• a\n• b\nline\nnext');
  });
});

describe('buildMessage', () => {
  it('produces a parseable UTF-8 message with threading headers', () => {
    const { raw, messageId } = buildMessage({
      from: 'me@example.com',
      fromName: 'Zoë',
      to: ['you@example.com'],
      cc: ['cc@example.com'],
      subject: 'Re: Café',
      text: 'Line one\n.leading dot\nüñí',
      inReplyTo: '<orig@example.com>',
      references: '<root@example.com>'
    });
    assert.match(messageId, /^<[0-9a-f-]+@example\.com>$/);
    assert.match(raw, /\r\nIn-Reply-To: <orig@example\.com>\r\n/);
    assert.match(raw, /\r\nReferences: <root@example\.com> <orig@example\.com>\r\n/);
    const parsed = parseMessage(raw);
    assert.equal(parsed.headers.subject, 'Re: Café');
    assert.equal(parsed.headers.from, 'Zoë <me@example.com>');
    assert.equal(parsed.headers.cc, 'cc@example.com');
    assert.equal(parsed.text, 'Line one\n.leading dot\nüñí');
  });
});

describe('parseAddressList', () => {
  it('extracts valid addresses and ignores junk', () => {
    assert.deepEqual(
      parseAddressList('"Doe, Jane" <jane@example.com>; bob@example.org, not-an-email, '),
      ['jane@example.com', 'bob@example.org']
    );
  });
});
