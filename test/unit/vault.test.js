/**
 * Credential Vault Unit Test Suite (test/unit/vault.test.js)
 *
 * Tests:
 * - AES-256-GCM authenticated encryption and decryption
 * - Tampering and corrupt payload detection
 * - Atomic persistence to disk
 * - Permanent session storage (save, get, list, remove)
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { CredentialVault } from '../../src/auth/vault.js';

describe('Encrypted Credential Vault (src/auth/vault.js)', () => {
  let tempDir;
  let vault;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-vault-test-'));
    vault = new CredentialVault({
      dataDir: tempDir,
      masterKey: crypto.randomBytes(32)
    });
    await vault.init();
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('encrypts and decrypts strings and objects using AES-256-GCM', () => {
    const secretText = 'super-secret-apple-password-1234';
    const encrypted = vault.encrypt(secretText);

    assert.notStrictEqual(encrypted, secretText);
    assert.strictEqual(encrypted.split(':').length, 3); // iv:authTag:ciphertext

    const decrypted = vault.decrypt(encrypted);
    assert.strictEqual(decrypted, secretText);
  });

  it('detects tampering and throws an error on modified ciphertext or auth tag', () => {
    const encrypted = vault.encrypt('top-secret');
    const parts = encrypted.split(':');

    // Tamper with ciphertext by altering last character
    const tamperedCiphertext = parts[2].slice(0, -2) + (parts[2].endsWith('a') ? 'b' : 'a');
    const tamperedPayload = `${parts[0]}:${parts[1]}:${tamperedCiphertext}`;

    assert.throws(() => {
      vault.decrypt(tamperedPayload);
    });

    // Tamper with auth tag
    const lastTagChar = parts[1].slice(-1);
    const flippedTag = (parseInt(lastTagChar, 16) ^ 1).toString(16);
    const tamperedAuthTag = parts[1].slice(0, -1) + flippedTag;
    const tamperedTagPayload = `${parts[0]}:${tamperedAuthTag}:${parts[2]}`;

    assert.throws(() => {
      vault.decrypt(tamperedTagPayload);
    });

    // Tamper with IV
    const lastIvChar = parts[0].slice(-1);
    const flippedIv = (parseInt(lastIvChar, 16) ^ 1).toString(16);
    const tamperedIvPayload = `${parts[0].slice(0, -1) + flippedIv}:${parts[1]}:${parts[2]}`;

    assert.throws(() => {
      vault.decrypt(tamperedIvPayload);
    });

    // Corrupted payload format
    assert.throws(() => {
      vault.decrypt('invalid:payload');
    });
  });

  it('saves an account permanently and reads it back from disk', async () => {
    const account = {
      provider: 'apple',
      email: 'user@icloud.com',
      auth: {
        type: 'app_password',
        pass: 'abcd-efgh-ijkl-mnop'
      },
      label: 'My Apple Mail'
    };

    const saved = await vault.saveAccount(account);
    assert.ok(saved.id);
    assert.ok(saved.createdAt);
    assert.ok(saved.updatedAt);

    // Read back via getAll
    const all = await vault.getAll();
    assert.strictEqual(all.length, 1);
    assert.strictEqual(all[0].email, 'user@icloud.com');
    assert.strictEqual(all[0].auth.pass, 'abcd-efgh-ijkl-mnop');

    // Read back via getPublicList (passwords must NOT be in public list)
    const publicList = await vault.getPublicList();
    assert.strictEqual(publicList.length, 1);
    assert.strictEqual(publicList[0].email, 'user@icloud.com');
    assert.strictEqual(publicList[0].auth, undefined);
    assert.strictEqual(publicList[0].connected, true);

    // Simulate process restart with new CredentialVault instance pointing to same storage
    const reloadedVault = new CredentialVault({
      dataDir: tempDir,
      masterKey: vault.explicitMasterKey
    });
    await reloadedVault.init();
    const reloadedAll = await reloadedVault.getAll();
    assert.strictEqual(reloadedAll.length, 1);
    assert.strictEqual(reloadedAll[0].email, 'user@icloud.com');
    assert.strictEqual(reloadedAll[0].auth.pass, 'abcd-efgh-ijkl-mnop');
  });

  it('updates an existing account when saving with matching ID', async () => {
    const account = await vault.saveAccount({
      id: 'acc-1',
      provider: 'gmail',
      email: 'test@gmail.com',
      auth: { type: 'oauth2', accessToken: 'token-v1' }
    });

    await vault.saveAccount({
      id: 'acc-1',
      provider: 'gmail',
      email: 'test@gmail.com',
      auth: { type: 'oauth2', accessToken: 'token-v2' }
    });

    const all = await vault.getAll();
    assert.strictEqual(all.length, 1);
    assert.strictEqual(all[0].auth.accessToken, 'token-v2');
  });

  it('removes an account explicitly on logout', async () => {
    await vault.saveAccount({
      id: 'acc-to-delete',
      provider: 'outlook',
      email: 'student@uni.edu'
    });

    let all = await vault.getAll();
    assert.strictEqual(all.length, 1);

    const removed = await vault.removeAccount('acc-to-delete');
    assert.strictEqual(removed, true);

    all = await vault.getAll();
    assert.strictEqual(all.length, 0);

    const removedAgain = await vault.removeAccount('acc-to-delete');
    assert.strictEqual(removedAgain, false);
  });

  it('safely handles concurrent saveAccount operations without losing accounts', async () => {
    // Dispatch 5 concurrent save operations
    const accounts = Array.from({ length: 5 }, (_, i) => ({
      id: `concurrent-${i}`,
      provider: 'gmail',
      email: `user${i}@example.com`,
      auth: { type: 'oauth2', accessToken: `token-${i}` }
    }));

    await Promise.all(accounts.map((acc) => vault.saveAccount(acc)));

    const all = await vault.getAll();
    assert.strictEqual(all.length, 5);
    for (let i = 0; i < 5; i++) {
      assert.ok(all.some((a) => a.id === `concurrent-${i}` && a.email === `user${i}@example.com`));
    }
  });

  it('generates machine-local .vault-key on first run and reuses it on subsequent loads', async () => {
    const localDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-key-test-'));
    try {
      const v1 = new CredentialVault({ dataDir: localDir });
      await v1.init();

      const keyPath = path.join(localDir, '.vault-key');
      const keyHex = await fs.readFile(keyPath, 'utf8');
      assert.strictEqual(keyHex.trim().length, 64); // 32 bytes = 64 hex chars

      await v1.saveAccount({ id: 'acc-restart', email: 'persisted@test.com' });

      // Simulate process restart without masterKey override
      const v2 = new CredentialVault({ dataDir: localDir });
      await v2.init();
      const loaded = await v2.getAll();
      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].email, 'persisted@test.com');
    } finally {
      await fs.rm(localDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('detects corrupted .vault-key and throws error without overwriting file', async () => {
    const localDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-corrupt-key-'));
    try {
      const keyPath = path.join(localDir, '.vault-key');
      // Write corrupted key (invalid length / invalid hex)
      await fs.writeFile(keyPath, 'corrupted-short-key');

      const v = new CredentialVault({ dataDir: localDir });
      await assert.rejects(
        () => v.init(),
        /Corrupted vault key/
      );

      // Verify the file was NOT overwritten
      const content = await fs.readFile(keyPath, 'utf8');
      assert.strictEqual(content, 'corrupted-short-key');
    } finally {
      await fs.rm(localDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('throws descriptive error if .vault-key is missing but accounts.vault.json exists with data', async () => {
    const localDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-missing-key-'));
    try {
      const vaultPath = path.join(localDir, 'accounts.vault.json');
      await fs.writeFile(vaultPath, 'iv:tag:ciphertext', 'utf8');

      const v = new CredentialVault({ dataDir: localDir });
      await assert.rejects(
        () => v.init(),
        /Vault key file not found.*encrypted vault data exists/
      );
    } finally {
      await fs.rm(localDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('safely synchronizes concurrent saveAccount across distinct CredentialVault instances via file lock', async () => {
    const multiDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-multi-vault-'));
    const masterKey = crypto.randomBytes(32);
    try {
      const v1 = new CredentialVault({ dataDir: multiDir, masterKey });
      const v2 = new CredentialVault({ dataDir: multiDir, masterKey });
      await v1.init();
      await v2.init();

      // Concurrently save from two independent instances
      await Promise.all([
        v1.saveAccount({ id: 'acc-inst-1', email: 'inst1@example.com' }),
        v2.saveAccount({ id: 'acc-inst-2', email: 'inst2@example.com' })
      ]);

      const all = await v1.getAll();
      assert.strictEqual(all.length, 2, 'Both accounts must be preserved without clobbering');
      assert.ok(all.some((a) => a.id === 'acc-inst-1'));
      assert.ok(all.some((a) => a.id === 'acc-inst-2'));
    } finally {
      await fs.rm(multiDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('recovers from stale lock file and completes mutation', async () => {
    const lockDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-stale-lock-'));
    try {
      const v = new CredentialVault({ dataDir: lockDir });
      await v.init();

      // Create a simulated stale lock file with an mtime 20 seconds in the past
      const lockPath = path.join(lockDir, 'accounts.vault.json.lock');
      await fs.writeFile(lockPath, JSON.stringify({ pid: 99999, time: Date.now() - 25000 }));
      const pastTime = new Date(Date.now() - 25000);
      await fs.utimes(lockPath, pastTime, pastTime);

      // Mutating operation should detect stale lock, unlink it, and succeed
      const saved = await v.saveAccount({ id: 'acc-after-stale', email: 'stale-recover@test.com' });
      assert.strictEqual(saved.id, 'acc-after-stale');

      const all = await v.getAll();
      assert.strictEqual(all.length, 1);
      assert.strictEqual(all[0].email, 'stale-recover@test.com');
    } finally {
      await fs.rm(lockDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('cleans up partial lock file and does not leave orphan if lock write throws', async () => {
    const lockDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-partial-lock-'));
    try {
      const v = new CredentialVault({ dataDir: lockDir });
      await v.init();

      // Spy/intercept fs.open to inject a failure on handle.writeFile
      const originalOpen = fs.open;
      let injected = false;
      fs.open = async (...args) => {
        const handle = await originalOpen.apply(fs, args);
        if (!injected && args[0].endsWith('.lock')) {
          injected = true;
          handle.writeFile = async () => {
            const err = new Error('Disk write simulated failure');
            err.code = 'EIO';
            throw err;
          };
        }
        return handle;
      };

      try {
        await assert.rejects(
          () => v.saveAccount({ id: 'will-fail', email: 'fail@test.com' }),
          /Disk write simulated failure/
        );
      } finally {
        fs.open = originalOpen;
      }

      // Verify the lock file was unlinked and does NOT exist as an orphan
      const lockPath = path.join(lockDir, 'accounts.vault.json.lock');
      let lockExists = true;
      try {
        await fs.stat(lockPath);
      } catch {
        lockExists = false;
      }
      assert.strictEqual(lockExists, false, 'Lockfile must be unlinked after write failure');

      // Subsequent operation must succeed immediately without waiting
      const saved = await v.saveAccount({ id: 'acc-next', email: 'next@test.com' });
      assert.strictEqual(saved.id, 'acc-next');
    } finally {
      await fs.rm(lockDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('throws descriptive error on lock acquisition when permission is denied (EACCES)', async () => {
    const permDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-perm-lock-'));
    try {
      const v = new CredentialVault({ dataDir: permDir });
      await v.init();

      const originalOpen = fs.open;
      fs.open = async (...args) => {
        if (args[0].endsWith('.lock')) {
          const err = new Error('permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return originalOpen.apply(fs, args);
      };

      try {
        await assert.rejects(
          () => v.saveAccount({ id: 'perm-fail', email: 'perm@test.com' }),
          /Vault lock acquisition failed: Permission denied/
        );
      } finally {
        fs.open = originalOpen;
      }
    } finally {
      await fs.rm(permDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('handles transient Windows lock contention (EPERM and EBUSY) with retry backoff', async () => {
    const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-eperm-retry-'));
    try {
      const v = new CredentialVault({ dataDir: testDir });
      await v.init();

      const originalOpen = fs.open;
      let epermCount = 0;
      let ebusyCount = 0;

      fs.open = async (...args) => {
        if (args[0].endsWith('.lock')) {
          if (epermCount < 2) {
            epermCount++;
            const err = new Error('simulated Windows EPERM contention');
            err.code = 'EPERM';
            throw err;
          }
          if (ebusyCount < 2) {
            ebusyCount++;
            const err = new Error('simulated Windows EBUSY contention');
            err.code = 'EBUSY';
            throw err;
          }
        }
        return originalOpen.apply(fs, args);
      };

      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });

      try {
        const saved = await v.saveAccount({ id: 'acc-contention', email: 'contention@test.com' });
        assert.strictEqual(saved.id, 'acc-contention');
        assert.strictEqual(epermCount, 2, 'Must have retried through both EPERM failures');
        assert.strictEqual(ebusyCount, 2, 'Must have retried through both EBUSY failures');
      } finally {
        fs.open = originalOpen;
        Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
      }
    } finally {
      await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('throws descriptive timeout error when lock contention exceeds maxWaitMs on Windows', async () => {
    const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-lock-timeout-'));
    try {
      const v = new CredentialVault({ dataDir: testDir });
      await v.init();

      const originalOpen = fs.open;
      fs.open = async (...args) => {
        if (args[0].endsWith('.lock')) {
          const err = new Error('persistent EPERM');
          err.code = 'EPERM';
          throw err;
        }
        return originalOpen.apply(fs, args);
      };

      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });

      try {
        await assert.rejects(
          () => v._acquireFileLock(60),
          /Timeout waiting for vault file lock/
        );
      } finally {
        fs.open = originalOpen;
        Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
      }
    } finally {
      await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it('safely completes high-concurrency cross-instance mutations on Windows without EPERM rejections', async () => {
    const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailboxer-high-concur-'));
    const masterKey = crypto.randomBytes(32);
    try {
      const instances = Array.from({ length: 10 }, () => new CredentialVault({ dataDir: testDir, masterKey }));
      await Promise.all(instances.map((inst) => inst.init()));

      const tasks = [];
      for (let i = 0; i < 30; i++) {
        const inst = instances[i % instances.length];
        tasks.push(
          inst.saveAccount({
            id: `cross-win-${i}`,
            provider: 'apple',
            email: `user${i}@icloud.com`,
            auth: { type: 'app_password', pass: `pass-${i}` }
          })
        );
      }

      const results = await Promise.allSettled(tasks);
      const rejections = results.filter((r) => r.status === 'rejected');
      assert.strictEqual(rejections.length, 0, `Expected 0 rejections, got: ${rejections.map((r) => r.reason?.message).join(', ')}`);

      const all = await instances[0].getAll();
      assert.strictEqual(all.length, 30, 'All 30 accounts must be saved and preserved');
      for (let i = 0; i < 30; i++) {
        assert.ok(all.some((a) => a.id === `cross-win-${i}`));
      }
    } finally {
      await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
    }
  });
});
