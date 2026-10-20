/**
 * Botkeep Cloud Deployment & Persistent Volume Unit Test Suite
 *
 * Verifies Milestone 4 (Requirement R4) specifications:
 * 1. Dockerfile contents and non-root security standards
 * 2. .dockerignore build context exclusions
 * 3. Dynamic HOST (0.0.0.0) and PORT binding in WebServer and bin/server.js
 * 4. DATA_DIR resolution across CredentialVault and SqliteStore
 * 5. GET /health endpoint structure, 200 OK status, and storage writability telemetry
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { WebServer } from '../../src/server/web-server.js';
import { CredentialVault } from '../../src/auth/vault.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');

describe('Botkeep Cloud Deployment & Configuration (Milestone 4 / R4)', () => {
  let tempBaseDir;

  before(async () => {
    tempBaseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-deploy-test-'));
  });

  after(async () => {
    try {
      await fs.rm(tempBaseDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  describe('1. Dockerfile Specifications', () => {
    let dockerfileContent;

    before(async () => {
      const dockerfilePath = path.join(REPO_ROOT, 'Dockerfile');
      dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
    });

    it('uses official Node 22 Bookworm slim base image', () => {
      assert.ok(
        /FROM\s+node:22-bookworm-slim/i.test(dockerfileContent),
        'Dockerfile must use node:22-bookworm-slim base image'
      );
    });

    it('configures permissions for non-root user node on /app and /data', () => {
      assert.ok(
        dockerfileContent.includes('/app') && dockerfileContent.includes('/data'),
        'Dockerfile must configure /app and /data directories'
      );
      assert.ok(
        /chown\s+-R\s+node:node\s+\/app\s+\/data/.test(dockerfileContent) ||
        /chown\s+-R\s+node:node/.test(dockerfileContent),
        'Dockerfile must set ownership to node:node'
      );
    });

    it('switches to non-root USER node', () => {
      assert.ok(
        /USER\s+node\b/.test(dockerfileContent),
        'Dockerfile must switch to USER node'
      );
    });

    it('sets WORKDIR to /app', () => {
      assert.ok(
        /WORKDIR\s+\/app\b/.test(dockerfileContent),
        'Dockerfile must set WORKDIR to /app'
      );
    });

    it('copies application files (package.json, bin/, src/, public/) with node ownership', () => {
      assert.ok(dockerfileContent.includes('package.json'), 'Must copy package.json');
      assert.ok(dockerfileContent.includes('bin/'), 'Must copy bin/');
      assert.ok(dockerfileContent.includes('src/'), 'Must copy src/');
      assert.ok(dockerfileContent.includes('public/'), 'Must copy public/');
      assert.ok(dockerfileContent.includes('--chown=node:node'), 'Must copy with --chown=node:node');
    });

    it('defines production environment defaults (PORT, NODE_ENV, DATA_DIR)', () => {
      assert.ok(
        /ENV.*PORT=3000/.test(dockerfileContent),
        'Dockerfile must set ENV PORT=3000'
      );
      assert.ok(
        /ENV.*NODE_ENV=production/.test(dockerfileContent),
        'Dockerfile must set ENV NODE_ENV=production'
      );
      assert.ok(
        /ENV.*DATA_DIR=\/data/.test(dockerfileContent),
        'Dockerfile must set ENV DATA_DIR=/data'
      );
    });

    it('declares persistent volume for /data', () => {
      assert.ok(
        /VOLUME\s+\[.*"\/data".*\]/.test(dockerfileContent) || /VOLUME\s+\/data/.test(dockerfileContent),
        'Dockerfile must declare VOLUME ["/data"]'
      );
    });

    it('exposes default application port 3000', () => {
      assert.ok(
        /EXPOSE\s+3000/.test(dockerfileContent),
        'Dockerfile must expose port 3000'
      );
    });

    it('configures native Node.js fetch healthcheck', () => {
      assert.ok(
        dockerfileContent.includes('HEALTHCHECK'),
        'Dockerfile must contain HEALTHCHECK instruction'
      );
      assert.ok(
        dockerfileContent.includes('--interval=30s') &&
        dockerfileContent.includes('--timeout=5s') &&
        dockerfileContent.includes('--start-period=5s') &&
        dockerfileContent.includes('--retries=3'),
        'HEALTHCHECK must specify interval=30s, timeout=5s, start-period=5s, retries=3'
      );
      assert.ok(
        dockerfileContent.includes('/health'),
        'HEALTHCHECK must target /health endpoint'
      );
      assert.ok(
        dockerfileContent.includes("fetch('http://localhost:'"),
        'HEALTHCHECK must use native fetch command'
      );
    });

    it('defines CMD to launch bin/server.js', () => {
      assert.ok(
        /CMD\s+\[\s*"node"\s*,\s*"bin\/server\.js"\s*\]/.test(dockerfileContent),
        'Dockerfile must launch CMD ["node", "bin/server.js"]'
      );
    });
  });

  describe('2. .dockerignore Exclusions', () => {
    let dockerignoreContent;
    let lines;

    before(async () => {
      const dockerignorePath = path.join(REPO_ROOT, '.dockerignore');
      dockerignoreContent = await fs.readFile(dockerignorePath, 'utf8');
      lines = dockerignoreContent.split('\n').map(l => l.trim()).filter(Boolean);
    });

    it('ignores dependencies and local cache directories', () => {
      assert.ok(lines.includes('node_modules'), 'Must ignore node_modules');
      assert.ok(lines.includes('data'), 'Must ignore data');
    });

    it('ignores version control and teamwork metadata', () => {
      assert.ok(lines.includes('.git'), 'Must ignore .git');
      assert.ok(lines.includes('.agents'), 'Must ignore .agents');
    });

    it('ignores test suites and debug logs', () => {
      assert.ok(lines.includes('test'), 'Must ignore test directory');
      assert.ok(lines.includes('*.log'), 'Must ignore *.log');
    });

    it('ignores environment secrets (.env and .env.*)', () => {
      assert.ok(lines.includes('.env'), 'Must ignore .env');
      assert.ok(lines.includes('.env.*'), 'Must ignore .env.*');
    });
  });

  describe('3. Dynamic HOST and PORT Binding', () => {
    const originalEnvHost = process.env.HOST;
    const originalEnvPort = process.env.PORT;

    after(() => {
      if (originalEnvHost !== undefined) process.env.HOST = originalEnvHost;
      else delete process.env.HOST;

      if (originalEnvPort !== undefined) process.env.PORT = originalEnvPort;
      else delete process.env.PORT;
    });

    it('defaults WebServer host to 0.0.0.0 and port to 3000 when unspecified', () => {
      delete process.env.HOST;
      delete process.env.PORT;

      const server = new WebServer();
      assert.strictEqual(server.host, '0.0.0.0');
      assert.strictEqual(server.port, 3000);
    });

    it('respects options.host and options.port overrides', () => {
      const server = new WebServer({ host: '127.0.0.1', port: 8088 });
      assert.strictEqual(server.host, '127.0.0.1');
      assert.strictEqual(server.port, 8088);
    });

    it('respects process.env.HOST and process.env.PORT environment variables', () => {
      process.env.HOST = '10.0.0.5';
      process.env.PORT = '9090';

      const server = new WebServer();
      assert.strictEqual(server.host, '10.0.0.5');
      assert.strictEqual(server.port, 9090);

      delete process.env.HOST;
      delete process.env.PORT;
    });

    it('successfully binds to 0.0.0.0 on random high port and returns routable address', async () => {
      const randomPort = 15000 + Math.floor(Math.random() * 30000);
      const server = new WebServer({ port: randomPort });
      assert.strictEqual(server.host, '0.0.0.0');

      const url = await server.start();
      try {
        assert.ok(url.startsWith('http://'), 'Resolved address must start with http://');
        assert.ok(url.includes(String(randomPort)), 'Resolved address must include the port');

        // Check that /health responds through loopback interface
        const res = await fetch(`http://127.0.0.1:${randomPort}/health`);
        assert.strictEqual(res.status, 200);
        const data = await res.json();
        assert.strictEqual(data.status, 'healthy');
      } finally {
        await server.stop();
      }
    });

    it('validates launcher bin/server.js sets process.env.HOST fallback to 0.0.0.0', async () => {
      const serverScript = await fs.readFile(path.join(REPO_ROOT, 'bin/server.js'), 'utf8');
      assert.ok(
        serverScript.includes("process.env.HOST || '0.0.0.0'"),
        'bin/server.js must bind to process.env.HOST || "0.0.0.0"'
      );
      assert.ok(
        serverScript.includes('Number(process.env.PORT) || 3000'),
        'bin/server.js must bind to Number(process.env.PORT) || 3000'
      );
      assert.ok(
        serverScript.includes('new WebServer({ port, host })'),
        'bin/server.js must pass { port, host } to WebServer'
      );
    });
  });

  describe('4. DATA_DIR Environment Wiring & Volume Persistence', () => {
    const originalDataDir = process.env.DATA_DIR;

    after(() => {
      if (originalDataDir !== undefined) process.env.DATA_DIR = originalDataDir;
      else delete process.env.DATA_DIR;
    });

    it('CredentialVault defaults dataDir to process.env.DATA_DIR when options.dataDir is omitted', () => {
      const testDataPath = path.join(tempBaseDir, 'custom-env-data');
      process.env.DATA_DIR = testDataPath;

      const vault = new CredentialVault();
      assert.strictEqual(vault.dataDir, testDataPath);
      assert.strictEqual(vault.vaultFilePath, path.join(testDataPath, 'accounts.vault.json'));
      assert.strictEqual(vault.keyFilePath, path.join(testDataPath, '.vault-key'));

      delete process.env.DATA_DIR;
    });

    it('CredentialVault prioritizes options.dataDir over process.env.DATA_DIR', () => {
      process.env.DATA_DIR = path.join(tempBaseDir, 'ignored-env-data');
      const explicitDataPath = path.join(tempBaseDir, 'explicit-data');

      const vault = new CredentialVault({ dataDir: explicitDataPath });
      assert.strictEqual(vault.dataDir, explicitDataPath);

      delete process.env.DATA_DIR;
    });

    it('persists encrypted vault files into DATA_DIR directory on init and save', async () => {
      const customDataDir = path.join(tempBaseDir, 'volume-data-dir');
      process.env.DATA_DIR = customDataDir;

      const vault = new CredentialVault();
      await vault.init();

      // Check key file was created inside DATA_DIR
      const keyStat = await fs.stat(vault.keyFilePath);
      assert.ok(keyStat.isFile(), 'Key file must be created inside custom DATA_DIR');

      // Save an account and verify accounts.vault.json was created inside DATA_DIR
      await vault.saveAccount({
        id: 'cloud-botkeep-acc-1',
        provider: 'apple',
        email: 'botkeep@mailboxer.test',
        auth: { type: 'app_password', password: 'abcd-efgh-ijkl-mnop' }
      });

      const vaultStat = await fs.stat(vault.vaultFilePath);
      assert.ok(vaultStat.isFile(), 'Vault file must be created inside custom DATA_DIR');
      assert.ok(vaultStat.size > 0, 'Vault file must contain encrypted bytes');

      delete process.env.DATA_DIR;
    });

    it('SqliteStore initializes database file inside designated DATA_DIR directory', () => {
      const dbFile = path.join(tempBaseDir, 'sqlite-volume', 'mailboxer.sqlite');
      const store = new SqliteStore(dbFile);
      try {
        assert.strictEqual(store.dbPath, dbFile);
        store.upsertAccount({
          id: 'acc-vol-1',
          email: 'store@volume.test',
          provider: 'gmail'
        });
        const account = store.getAccount('acc-vol-1');
        assert.strictEqual(account.email, 'store@volume.test');
      } finally {
        store.close();
      }
    });
  });

  describe('5. GET /health Telemetry & Storage Telemetry', () => {
    let server;
    let baseUrl;
    let testDataDir;

    before(async () => {
      testDataDir = path.join(tempBaseDir, 'health-check-dir');
      await fs.mkdir(testDataDir, { recursive: true });

      const vault = new CredentialVault({
        dataDir: testDataDir,
        masterKey: crypto.randomBytes(32)
      });
      await vault.init();

      const randomPort = 16000 + Math.floor(Math.random() * 30000);
      server = new WebServer({
        port: randomPort,
        dataDir: testDataDir
      });

      baseUrl = await server.start();
    });

    after(async () => {
      if (server) {
        await server.stop();
      }
    });

    it('returns HTTP 200 OK with application/json content type', async () => {
      const res = await fetch(`${baseUrl}/health`);
      assert.strictEqual(res.status, 200);
      assert.ok(res.headers.get('content-type').includes('application/json'));
    });

    it('returns valid root health metadata (status, uptime, timestamp, version)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.strictEqual(body.status, 'healthy');
      assert.strictEqual(typeof body.uptimeSeconds, 'number');
      assert.ok(body.uptimeSeconds >= 0);
      assert.strictEqual(typeof body.timestamp, 'string');
      assert.ok(!Number.isNaN(Date.parse(body.timestamp)));
      assert.strictEqual(body.version, '0.1.0');
    });

    it('returns system runtime metrics (nodeVersion, platform, arch, memoryUsageMb, pid)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.ok(body.system, 'Must include system telemetry');
      assert.strictEqual(body.system.nodeVersion, process.version);
      assert.strictEqual(body.system.platform, process.platform);
      assert.strictEqual(body.system.arch, process.arch);
      assert.strictEqual(body.system.pid, process.pid);
      assert.ok(body.system.memoryUsageMb, 'Must include memory metrics');
      assert.strictEqual(typeof body.system.memoryUsageMb.rss, 'number');
      assert.strictEqual(typeof body.system.memoryUsageMb.heapTotal, 'number');
      assert.strictEqual(typeof body.system.memoryUsageMb.heapUsed, 'number');
    });

    it('returns storage volume telemetry (dataDir, persistent, writable, sqlite, vault)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.ok(body.storage, 'Must include storage telemetry');
      assert.strictEqual(body.storage.dataDir, testDataDir);
      assert.strictEqual(body.storage.persistent, true);
      assert.strictEqual(body.storage.writable, true);
      assert.ok(body.storage.databasePath.includes('mailboxer.sqlite'));
      assert.ok(body.storage.vaultPath.includes('accounts.vault.json'));

      assert.ok(body.storage.sqlite, 'Must include sqlite storage status');
      assert.strictEqual(body.storage.sqlite.connected, true);
      assert.strictEqual(body.storage.sqlite.journalMode, 'wal');
      assert.ok(Array.isArray(body.storage.sqlite.tables));
      assert.ok(body.storage.sqlite.tables.includes('accounts'));
      assert.ok(body.storage.sqlite.tables.includes('messages'));

      assert.ok(body.storage.vault, 'Must include vault storage status');
      assert.strictEqual(body.storage.vault.initialized, true);
      assert.strictEqual(body.storage.vault.hasKey, true);
    });

    it('returns accounts telemetry (total and connected count)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.ok(body.accounts, 'Must include accounts telemetry');
      assert.strictEqual(typeof body.accounts.total, 'number');
      assert.strictEqual(typeof body.accounts.connected, 'number');
      assert.ok(body.accounts.connected <= body.accounts.total);
    });

    it('returns idle and syncEngine telemetry (running, idleAccounts, pollingAccounts)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.ok(body.idle, 'Must include idle telemetry');
      assert.strictEqual(typeof body.idle.running, 'boolean');
      assert.strictEqual(typeof body.idle.idleAccounts, 'number');
      assert.strictEqual(typeof body.idle.pollingAccounts, 'number');

      assert.ok(body.syncEngine, 'Must include syncEngine telemetry');
      assert.strictEqual(typeof body.syncEngine.active, 'boolean');
      assert.ok(['running', 'idle'].includes(body.syncEngine.status));
    });

    it('returns notification channels status (webPush, ntfy)', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();

      assert.ok(body.notifications, 'Must include notifications telemetry');
      assert.strictEqual(typeof body.notifications.webPushEnabled, 'boolean');
      assert.strictEqual(typeof body.notifications.ntfyEnabled, 'boolean');
      assert.ok(body.notifications.webPush, 'Must include webPush details');
      assert.ok(body.notifications.ntfy, 'Must include ntfy details');
    });
  });
});
