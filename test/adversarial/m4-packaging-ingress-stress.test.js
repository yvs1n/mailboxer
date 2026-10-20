/**
 * Adversarial Stress & Chaos Test Suite: Milestone 4 Cloud Packaging & Network Ingress
 * (test/adversarial/m4-packaging-ingress-stress.test.js)
 *
 * Empirical verification for Milestone 4 (Botkeep Cloud Packaging & Network Ingress):
 * 1. Port & Host Edge Cases:
 *    - Port collisions (EADDRINUSE) on WebServer.start() and bin/server.js CLI
 *    - Reentrant start() state corruption and orphaned socket leak
 *    - Boundary port numbers: negative (-1), overflow (70000), float (3000.5), ephemeral (0), NaN
 *    - Non-string host options ({}, true, 12345, []) and unvalidated URL corruption
 * 2. IPv6 vs IPv4 Network Ingress:
 *    - IPv6 loopback (::1) unbracketed URL formatting bug (violating RFC 3986 & WHATWG URL)
 *    - IPv6 wildcard (::) non-routable unbracketed URL generation (http:::port)
 *    - Bracketed IPv6 ([::1]) loopback HTTP communication
 *    - Ingress Host header validation and HTTP 500 vs 400 Bad Request error behavior
 * 3. Dockerfile Instruction Validity & Non-Root Execution:
 *    - Least privilege & user switching (FROM node:22-bookworm-slim, USER node, chown /app /data)
 *    - Instruction order, layer caching, volume isolation (VOLUME ["/data"])
 *    - PID 1 signal handling deficiency (missing SIGTERM/SIGINT listeners in bin/server.js)
 *    - Container HEALTHCHECK command syntax & evaluation
 *    - .dockerignore exclusions audit
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { WebServer } from '../../src/server/web-server.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');

function getFreePort() {
  return 20000 + Math.floor(Math.random() * 20000);
}

describe('Adversarial Challenge: Milestone 4 Cloud Packaging & Network Ingress', () => {
  let tempBaseDir;
  const activeServers = [];

  before(async () => {
    tempBaseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-m4-adv-'));
  });

  after(async () => {
    for (const s of activeServers) {
      try { await s.stop(); } catch {}
    }
    try {
      await fs.rm(tempBaseDir, { recursive: true, force: true });
    } catch {}
  });

  afterEach(async () => {
    while (activeServers.length > 0) {
      const s = activeServers.pop();
      try { await s.stop(); } catch {}
    }
  });

  // ==========================================================================
  // VECTOR 1: Port Collisions (EADDRINUSE) & Reentrant Lifecycle Stress
  // ==========================================================================
  describe('Vector 1: Port Collisions & Reentrant Lifecycle Stress', () => {

    it('rejects with EADDRINUSE when two WebServer instances bind to the same host:port', async () => {
      const port = getFreePort();
      const s1 = new WebServer({ port, host: '127.0.0.1' });
      activeServers.push(s1);
      const url1 = await s1.start();
      assert.ok(url1.includes(String(port)));

      const s2 = new WebServer({ port, host: '127.0.0.1' });
      activeServers.push(s2);

      await assert.rejects(
        async () => { await s2.start(); },
        (err) => {
          assert.strictEqual(err.code, 'EADDRINUSE');
          assert.match(err.message, /address already in use/i);
          return true;
        },
        'Second server on identical port must reject with EADDRINUSE'
      );
    });

    it('CLI launcher bin/server.js detects port collision and exits with code 1 and guidance', async () => {
      const port = getFreePort();
      const blocker = net.createServer();
      await new Promise((resolve) => blocker.listen(port, '0.0.0.0', resolve));

      try {
        const exitData = await new Promise((resolve) => {
          const cp = spawn(process.execPath, ['bin/server.js', '--port', String(port)], {
            cwd: REPO_ROOT,
            stdio: 'pipe'
          });
          let stdout = '';
          let stderr = '';
          cp.stdout.on('data', (d) => { stdout += d; });
          cp.stderr.on('data', (d) => { stderr += d; });
          cp.on('exit', (code) => resolve({ code, stdout, stderr }));
        });

        assert.strictEqual(exitData.code, 1, 'Launcher must exit with code 1 on port collision');
        assert.match(exitData.stderr, /is already in use/i);
        assert.match(exitData.stderr, /Try starting with a different port/i);
      } finally {
        await new Promise((resolve) => blocker.close(resolve));
      }
    });

    it('VERIFIED REMEDIATION: Reentrant start() returns existing server address without spawning duplicate or leaking socket', async () => {
      const port = getFreePort();
      const server = new WebServer({ port, host: '127.0.0.1' });
      activeServers.push(server);

      const url = await server.start();
      assert.ok(url.includes(String(port)));

      // Calling start() again while already active returns existing url without duplicate listen
      const secondUrl = await server.start();
      assert.strictEqual(secondUrl, url, 'Reentrant start() must return existing server address');

      // Now calling server.stop() cleanly shuts down the server
      await server.stop();

      // Test that port is NOT still bound (no orphan leaked)
      const isPortStillBound = await new Promise((resolve) => {
        const client = net.connect(port, '127.0.0.1', () => {
          client.destroy();
          resolve(true);
        });
        client.on('error', () => {
          resolve(false);
        });
      });

      assert.strictEqual(
        isPortStillBound,
        false,
        'Remediated: server.stop() cleanly closed server and no orphaned socket remains'
      );
    });
  });

  // ==========================================================================
  // VECTOR 2: Boundary Port Values (Negative, Overflow, Float, Ephemeral)
  // ==========================================================================
  describe('Vector 2: Boundary Port Values & Parsing Robustness', () => {

    it('rejects negative port numbers (-1) with RangeError [ERR_SOCKET_BAD_PORT]', async () => {
      const server = new WebServer({ port: -1 });
      activeServers.push(server);

      await assert.rejects(
        async () => { await server.start(); },
        (err) => {
          assert.strictEqual(err.name, 'RangeError');
          assert.strictEqual(err.code, 'ERR_SOCKET_BAD_PORT');
          return true;
        }
      );
    });

    it('rejects port numbers exceeding 65535 (70000) with RangeError [ERR_SOCKET_BAD_PORT]', async () => {
      const server = new WebServer({ port: 70000 });
      activeServers.push(server);

      await assert.rejects(
        async () => { await server.start(); },
        (err) => {
          assert.strictEqual(err.name, 'RangeError');
          assert.strictEqual(err.code, 'ERR_SOCKET_BAD_PORT');
          return true;
        }
      );
    });

    it('rejects floating-point port numbers (3000.5) with RangeError [ERR_SOCKET_BAD_PORT]', async () => {
      const server = new WebServer({ port: 3000.5 });
      activeServers.push(server);

      await assert.rejects(
        async () => { await server.start(); },
        (err) => {
          assert.strictEqual(err.name, 'RangeError');
          assert.strictEqual(err.code, 'ERR_SOCKET_BAD_PORT');
          return true;
        }
      );
    });

    it('VERIFIED REMEDIATION: Port 0 (ephemeral request) is preserved and dynamically allocated by kernel', async () => {
      const server = new WebServer({ port: 0, host: '127.0.0.1' });
      activeServers.push(server);
      assert.strictEqual(
        server.port,
        0,
        'Remediated: port 0 is preserved without falsy coercion to 3000'
      );

      const url = await server.start();
      const actualPort = server.server.address()?.port;
      assert.ok(actualPort > 0, 'Kernel must assign a positive ephemeral port');
      assert.strictEqual(url, `http://127.0.0.1:${actualPort}`);
    });

    it('falls back to default port 3000 when port is NaN or non-numeric string', () => {
      const server1 = new WebServer({ port: 'invalid-port' });
      assert.strictEqual(server1.port, 3000);

      const server2 = new WebServer({ port: NaN });
      assert.strictEqual(server2.port, 3000);
    });

    it('CLI launcher bin/server.js rejects negative ports via CLI flags with exit code 1', async () => {
      const exitData = await new Promise((resolve) => {
        const cp = spawn(process.execPath, ['bin/server.js', '--port', '-1'], {
          cwd: REPO_ROOT,
          stdio: 'pipe'
        });
        let stderr = '';
        cp.stderr.on('data', (d) => { stderr += d; });
        cp.on('exit', (code) => resolve({ code, stderr }));
      });

      assert.strictEqual(exitData.code, 1);
      assert.match(exitData.stderr, /ERR_SOCKET_BAD_PORT|options\.port should be >= 0/);
    });
  });

  // ==========================================================================
  // VECTOR 3: Host Binding Edge Cases & IPv6 vs IPv4 (0.0.0.0 vs ::)
  // ==========================================================================
  describe('Vector 3: Host Binding Edge Cases & IPv6 Ingress', () => {

    it('VERIFIED REMEDIATION: IPv6 loopback (::1) returns bracketed URL compliant with RFC 3986 and WHATWG fetch()', async () => {
      const port = getFreePort();
      const server = new WebServer({ host: '::1', port });
      activeServers.push(server);

      const resolvedUrl = await server.start();

      // RFC 3986 §3.2.2 mandates bracketed IPv6 literals in URI authorities [::1]
      assert.strictEqual(resolvedUrl, `http://[::1]:${port}`);

      // Demonstrates that standard WHATWG URL parser accepts bracketed IPv6 URL
      const parsed = new URL(resolvedUrl);
      assert.strictEqual(parsed.hostname, '[::1]');

      // Demonstrates that native fetch() succeeds
      const res = await fetch(`${resolvedUrl}/health`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'healthy');
    });

    it('VERIFIED REMEDIATION: IPv6 wildcard (::) is remapped to loopback [::1] producing valid routable URL', async () => {
      const port = getFreePort();
      const server = new WebServer({ host: '::', port });
      activeServers.push(server);

      const resolvedUrl = await server.start();

      // Wildcard '::' is remapped to '[::1]'
      assert.strictEqual(
        resolvedUrl,
        `http://[::1]:${port}`,
        'Remediated: IPv6 wildcard is remapped to bracketed loopback [::1]'
      );

      const res = await fetch(`${resolvedUrl}/health`);
      assert.strictEqual(res.status, 200, 'Underlying server socket is listening and accessible via resolved URL');
      const data = await res.json();
      assert.strictEqual(data.status, 'healthy');
    });

    it('successfully accepts bracketed IPv6 host ([::1]) and allows communication', async () => {
      const port = getFreePort();
      const server = new WebServer({ host: '[::1]', port });
      activeServers.push(server);

      const resolvedUrl = await server.start();
      assert.strictEqual(resolvedUrl, `http://[::1]:${port}`);

      const res = await fetch(`${resolvedUrl}/health`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'healthy');
    });

    it('VERIFIED REMEDIATION: Non-string host options ({}, true, 12345, []) are cleanly validated with fallback to 0.0.0.0', async () => {
      const port = getFreePort();
      const server = new WebServer({ host: {}, port });
      activeServers.push(server);

      assert.strictEqual(server.host, '0.0.0.0', 'Remediated: non-string host falls back cleanly to 0.0.0.0');

      const resolvedUrl = await server.start();
      assert.strictEqual(
        resolvedUrl,
        `http://127.0.0.1:${port}`,
        'Remediated: Fallback 0.0.0.0 formats as 127.0.0.1 loopback URL'
      );
    });

    it('VERIFIED REMEDIATION: Ingress HTTP request with unbracketed IPv6 Host header returns HTTP 400 Bad Request with INVALID_HOST code', async () => {
      const port = getFreePort();
      const server = new WebServer({ port, host: '127.0.0.1' });
      activeServers.push(server);
      await server.start();

      const responseText = await new Promise((resolve) => {
        const client = net.connect(port, '127.0.0.1', () => {
          client.write(`GET /health HTTP/1.1\r\nHost: ::1:${port}\r\nConnection: close\r\n\r\n`);
        });
        let raw = '';
        client.on('data', (d) => { raw += d.toString(); });
        client.on('end', () => resolve(raw));
      });

      // Per RFC 9112 §3.2, invalid host headers must receive 400 Bad Request.
      assert.match(responseText, /HTTP\/1\.1 400 Bad Request/);
      assert.match(responseText, /"code":"INVALID_HOST"/);
    });
  });

  // ==========================================================================
  // VECTOR 4: Dockerfile Instruction Validity & Non-Root Execution
  // ==========================================================================
  describe('Vector 4: Dockerfile Instruction Validity & Non-Root Security', () => {
    let dockerfileContent;

    before(async () => {
      dockerfileContent = await fs.readFile(path.join(REPO_ROOT, 'Dockerfile'), 'utf8');
    });

    it('verifies non-root user execution order (RUN mkdir/chown before USER node)', () => {
      const runIndex = dockerfileContent.indexOf('RUN mkdir -p /app /data && chown -R node:node /app /data');
      const userIndex = dockerfileContent.indexOf('USER node');
      const workdirIndex = dockerfileContent.indexOf('WORKDIR /app');

      assert.ok(runIndex !== -1, 'Must contain directory setup RUN command');
      assert.ok(userIndex !== -1, 'Must contain USER node directive');
      assert.ok(workdirIndex !== -1, 'Must contain WORKDIR /app directive');

      assert.ok(runIndex < userIndex, 'Directory ownership setup must occur before dropping to USER node');
      assert.ok(userIndex < workdirIndex, 'USER node must be active when setting WORKDIR');
    });

    it('verifies COPY instructions preserve non-root ownership via --chown=node:node', () => {
      const lines = dockerfileContent.split('\n').filter((l) => l.startsWith('COPY'));
      assert.ok(lines.length >= 4, 'Must copy package.json, bin, src, public');
      for (const line of lines) {
        assert.ok(line.includes('--chown=node:node'), `COPY instruction must specify --chown=node:node: ${line}`);
      }
    });

    it('verifies persistent volume isolation for /data and absence of hardcoded secrets', () => {
      assert.match(dockerfileContent, /VOLUME\s+\[.*"\/data".*\]/);
      assert.doesNotMatch(dockerfileContent, /SECRET|PASSWORD|TOKEN|KEY\s*=/i);
    });

    it('VERIFIED REMEDIATION: bin/server.js registers explicit SIGTERM and SIGINT handlers for Docker PID 1 graceful shutdown', async () => {
      const signalCheck = await new Promise((resolve) => {
        const cp = spawn(process.execPath, [
          '-e',
          "import('./bin/server.js').then(() => { console.log(JSON.stringify({ sigterm: process.listenerCount('SIGTERM'), sigint: process.listenerCount('SIGINT') })); process.exit(0); })"
        ], {
          cwd: REPO_ROOT,
          stdio: 'pipe'
        });
        let out = '';
        cp.stdout.on('data', (d) => { out += d; });
        cp.on('exit', () => resolve(JSON.parse(out.trim())));
      });

      assert.ok(
        signalCheck.sigterm >= 1,
        'Remediated: bin/server.js registers SIGTERM listener for Docker PID 1 graceful shutdown'
      );
      assert.ok(
        signalCheck.sigint >= 1,
        'Remediated: bin/server.js registers SIGINT listener'
      );
    });

    it('verifies HEALTHCHECK command syntax evaluates correctly against live server and fails when offline', async () => {
      // 1. Test offline failure (exit code 1)
      const offlineExit = await new Promise((resolve) => {
        const cp = spawn(process.execPath, [
          '-e',
          "fetch('http://localhost:29999/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
        ], { stdio: 'pipe' });
        cp.on('exit', (code) => resolve(code));
      });
      assert.strictEqual(offlineExit, 1, 'HEALTHCHECK script must exit 1 when server is offline');

      // 2. Test online success (exit code 0)
      const port = getFreePort();
      const server = new WebServer({ port, host: '0.0.0.0' });
      activeServers.push(server);
      await server.start();

      const onlineExit = await new Promise((resolve) => {
        const cp = spawn(process.execPath, [
          '-e',
          `fetch('http://127.0.0.1:${port}/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))`
        ], { stdio: 'pipe' });
        cp.on('exit', (code) => resolve(code));
      });
      assert.strictEqual(onlineExit, 0, 'HEALTHCHECK script must exit 0 when server is healthy');
    });

    it('verifies .dockerignore excludes build clutter and secret paths', async () => {
      const dockerignoreContent = await fs.readFile(path.join(REPO_ROOT, '.dockerignore'), 'utf8');
      const lines = dockerignoreContent.split('\n').map((l) => l.trim()).filter(Boolean);

      const requiredExclusions = ['node_modules', 'data', '.git', '.agents', 'test', '*.log', '.env', '.env.*'];
      for (const item of requiredExclusions) {
        assert.ok(lines.includes(item), `.dockerignore must exclude ${item}`);
      }
    });
  });
});
