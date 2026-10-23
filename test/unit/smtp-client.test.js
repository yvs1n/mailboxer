import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { SmtpClient, SmtpError } from '../../src/connection/smtp-client.js';

/**
 * Tiny scripted SMTP server. `options.authReply` controls the AUTH result,
 * `options.starttls` advertises STARTTLS (never actually negotiated here).
 */
function startServer(options = {}) {
  const session = { commands: [], data: '' };
  const server = net.createServer((sock) => {
    let buf = '';
    let inData = false;
    sock.write('220 test.local ESMTP\r\n');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let idx;
      while ((idx = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            sock.write('250 2.0.0 queued as 123\r\n');
          } else {
            session.data += `${line}\r\n`;
          }
          continue;
        }
        session.commands.push(line);
        const verb = line.split(' ')[0].toUpperCase();
        if (verb === 'EHLO') {
          const caps = ['250-test.local', '250-AUTH PLAIN LOGIN'];
          if (options.starttls) caps.push('250-STARTTLS');
          caps.push('250 8BITMIME');
          sock.write(`${caps.join('\r\n')}\r\n`);
        } else if (verb === 'AUTH') {
          sock.write(options.authReply || '235 2.7.0 ok\r\n');
        } else if (verb === 'MAIL') {
          sock.write('250 ok\r\n');
        } else if (verb === 'RCPT') {
          sock.write(line.includes('bad@') ? '550 5.1.1 no such user\r\n' : '250 ok\r\n');
        } else if (verb === 'DATA') {
          inData = true;
          sock.write('354 go ahead\r\n');
        } else if (verb === 'QUIT') {
          sock.end('221 bye\r\n');
        } else {
          sock.write('502 unknown\r\n');
        }
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, session }));
  });
}

describe('SmtpClient (src/connection/smtp-client.js)', () => {
  let srv;
  afterEach(() => srv?.server.close());

  it('authenticates with AUTH PLAIN and dot-stuffs the body', async () => {
    srv = await startServer();
    const client = new SmtpClient({ host: '127.0.0.1', port: srv.port, allowInsecure: true });
    const raw = 'Subject: t\r\n\r\nhello\r\n.dot line\r\nend';
    const res = await client.send({
      from: 'me@example.com',
      recipients: ['a@example.com', 'b@example.com'],
      raw,
      auth: { user: 'me@example.com', pass: 'secret' }
    });
    assert.deepEqual(res.accepted, ['a@example.com', 'b@example.com']);
    assert.match(res.response, /^250/);

    const auth = srv.session.commands.find(c => c.startsWith('AUTH PLAIN'));
    assert.equal(Buffer.from(auth.split(' ')[2], 'base64').toString(), '\0me@example.com\0secret');
    assert.ok(srv.session.commands.includes('MAIL FROM:<me@example.com>'));
    assert.ok(srv.session.commands.includes('RCPT TO:<b@example.com>'));
    assert.match(srv.session.data, /\r\n\.\.dot line\r\n/);
    assert.match(srv.session.data, /end\r\n$/);
  });

  it('rejects with a permanent SmtpError on 535', async () => {
    srv = await startServer({ authReply: '535 5.7.8 bad credentials\r\n' });
    const client = new SmtpClient({ host: '127.0.0.1', port: srv.port, allowInsecure: true });
    await assert.rejects(
      client.send({ from: 'me@example.com', recipients: ['a@example.com'], raw: 'x', auth: { user: 'u', pass: 'p' } }),
      (err) => err instanceof SmtpError && err.smtpCode === 535 && err.permanent === true
    );
  });

  it('reports a rejected recipient', async () => {
    srv = await startServer();
    const client = new SmtpClient({ host: '127.0.0.1', port: srv.port, allowInsecure: true });
    await assert.rejects(
      client.send({ from: 'me@example.com', recipients: ['bad@example.com'], raw: 'x' }),
      (err) => err.stage === 'RCPT TO' && err.smtpCode === 550
    );
  });

  it('refuses to send credentials over plain text by default', async () => {
    srv = await startServer();
    const client = new SmtpClient({ host: '127.0.0.1', port: srv.port });
    await assert.rejects(
      client.send({ from: 'me@example.com', recipients: ['a@example.com'], raw: 'x', auth: { user: 'u', pass: 'p' } }),
      /refusing to send credentials/
    );
    assert.equal(srv.session.commands.some(c => c.startsWith('AUTH')), false);
  });

  it('rejects header-injection in addresses before connecting', async () => {
    const client = new SmtpClient({ host: '127.0.0.1', port: 1 });
    await assert.rejects(
      client.send({ from: 'me@example.com', recipients: ['a@example.com>\r\nRCPT TO:<x@y.z'], raw: 'x' }),
      /Invalid email address/
    );
  });
});
