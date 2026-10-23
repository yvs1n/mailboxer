import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ImapClient, parseFetchResponses } from '../../src/connection/imap-client.js';

describe('IMAP literals with UTF-8 content (src/connection/imap-client.js)', () => {
  it('counts literal sizes in bytes, even when a character is split across chunks', () => {
    const client = new ImapClient({ accountConfig: { host: 'x', port: 993, auth: { user: 'u', pass: 'p' } } });
    const lines = [];
    client._handleLine = (line) => lines.push(line);

    const literal = Buffer.from('Subject: Café ☕\r\n\r\n', 'utf8');
    const head = Buffer.from(`* 1 FETCH (UID 7 BODY[HEADER.FIELDS (SUBJECT)] {${literal.length}}\r\n`, 'utf8');
    const tail = Buffer.from(')\r\nA1 OK done\r\n', 'utf8');
    const all = Buffer.concat([head, literal, tail]);

    // Split in the middle of the 3-byte "☕"
    const cut = head.length + literal.indexOf(Buffer.from('☕', 'utf8')) + 1;
    client._onData(all.subarray(0, cut));
    client._onData(all.subarray(cut));

    assert.equal(lines.length, 2);
    assert.ok(lines[0].includes('Subject: Café ☕'), lines[0]);
    assert.ok(lines[0].endsWith(')'));
    assert.equal(lines[1], 'A1 OK done');
  });

  it('parses binary fetch lines and decodes header literals as UTF-8', () => {
    const literal = Buffer.from('Subject: Naïve\r\n\r\n', 'utf8');
    const line = Buffer.concat([
      Buffer.from(`* 1 FETCH (UID 9 FLAGS (\Seen) BODY[HEADER.FIELDS (SUBJECT)] {${literal.length}}\r\n`),
      literal,
      Buffer.from(')')
    ]).toString('latin1');
    const [msg] = parseFetchResponses([line], { binary: true });
    assert.equal(msg.uid, 9);
    assert.equal(msg.subject, 'Naïve');
  });
});
