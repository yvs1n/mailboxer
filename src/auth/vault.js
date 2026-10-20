/**
 * Mailboxer Encrypted Credential Vault
 *
 * Provides persistent, AES-256-GCM authenticated encryption for storing
 * email account credentials (OAuth2 refresh/access tokens and App-Specific Passwords).
 *
 * Guarantees that credentials remain permanently saved on the local machine
 * until the user explicitly logs out or removes an account.
 *
 * Zero-dependency native Node.js 22 implementation using node:crypto and node:fs.
 *
 * @module auth/vault
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard 96-bit IV for GCM
const AUTH_TAG_LENGTH = 16; // Standard 128-bit authentication tag

export class CredentialVault {
  /**
   * @param {object} [options={}]
   * @param {string} [options.dataDir] - Path to directory for vault storage (default: ./data)
   * @param {string} [options.vaultFile] - Filename for encrypted vault (default: accounts.vault.json)
   * @param {string} [options.keyFile] - Filename for secret key (default: .vault-key)
   * @param {Buffer|string} [options.masterKey] - Optional master key override
   */
  constructor(options = {}) {
    this.dataDir = options.dataDir || process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
    this.vaultFilePath = path.join(this.dataDir, options.vaultFile || 'accounts.vault.json');
    this.keyFilePath = path.join(this.dataDir, options.keyFile || '.vault-key');
    this.lockFilePath = `${this.vaultFilePath}.lock`;
    this.explicitMasterKey = options.masterKey || null;
    this._key = null;
    this._initialized = false;
    this._mutationQueue = Promise.resolve();
  }

  /**
   * Initializes vault directories and loads/creates the 256-bit encryption key.
   */
  async init() {
    if (this._initialized && this._key) {
      return;
    }

    try {
      await fs.mkdir(this.dataDir, { recursive: true });
    } catch (err) {
      if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EROFS') {
        throw new Error(`Failed to initialize vault directory: Permission denied on ${this.dataDir} (${err.code})`);
      }
      throw err;
    }

    if (this.explicitMasterKey) {
      if (Buffer.isBuffer(this.explicitMasterKey)) {
        this._key = this.explicitMasterKey;
      } else {
        this._key = crypto.createHash('sha256').update(String(this.explicitMasterKey)).digest();
      }
    } else if (process.env.MAILBOXER_MASTER_KEY) {
      this._key = crypto.createHash('sha256').update(process.env.MAILBOXER_MASTER_KEY).digest();
    } else {
      // Load or generate machine-local persistent key
      let keyFileExists = false;
      let keyHex = null;

      try {
        keyHex = await fs.readFile(this.keyFilePath, 'utf8');
        keyFileExists = true;
      } catch (err) {
        if (err.code === 'EACCES' || err.code === 'EPERM') {
          throw new Error(`Failed to read vault key: Permission denied on ${this.keyFilePath} (${err.code})`);
        }
        if (err.code !== 'ENOENT') {
          throw new Error(`Failed to read vault key at ${this.keyFilePath}: ${err.message}`);
        }
      }

      if (keyFileExists) {
        const trimmed = (keyHex || '').trim();
        if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
          throw new Error(`Corrupted vault key at ${this.keyFilePath}: expected 64-character hex string (32 bytes), received length ${trimmed.length}`);
        }
        this._key = Buffer.from(trimmed, 'hex');
      } else {
        // Key file does not exist. Check if vault file exists with encrypted data!
        let vaultHasData = false;
        try {
          const vaultStat = await fs.stat(this.vaultFilePath);
          if (vaultStat.size > 0) {
            vaultHasData = true;
          }
        } catch {
          // vault file doesn't exist
        }

        if (vaultHasData) {
          throw new Error(`Vault key file not found at ${this.keyFilePath}, but encrypted vault data exists at ${this.vaultFilePath}. Restoring or regenerating a key would cause data loss.`);
        }

        // Clean initial setup: generate new 256-bit random key
        this._key = crypto.randomBytes(32);
        try {
          await fs.writeFile(this.keyFilePath, this._key.toString('hex'), { mode: 0o600 });
        } catch (err) {
          if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EROFS') {
            throw new Error(`Failed to create vault key: Permission denied on ${this.keyFilePath} (${err.code})`);
          }
          throw err;
        }
      }
    }

    this._initialized = true;
  }

  /**
   * Encrypts plaintext data using AES-256-GCM.
   * Format: iv_hex:authTag_hex:ciphertext_hex
   *
   * @param {string|object} data - Data to encrypt
   * @returns {string} Encrypted string payload
   */
  encrypt(data) {
    if (!this._key) {
      throw new Error('Vault is not initialized. Call init() first.');
    }

    const text = typeof data === 'object' ? JSON.stringify(data) : String(data);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this._key, iv, {
      authTagLength: AUTH_TAG_LENGTH
    });

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  /**
   * Decrypts AES-256-GCM encrypted payload.
   *
   * @param {string} payload - Encrypted string format (iv:authTag:ciphertext)
   * @returns {string} Decrypted plaintext string
   */
  decrypt(payload) {
    if (!this._key) {
      throw new Error('Vault is not initialized. Call init() first.');
    }

    if (typeof payload !== 'string') {
      throw new Error('Invalid encrypted payload format');
    }

    const parts = payload.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted payload format');
    }

    const [ivHex, authTagHex, encryptedHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, this._key, iv, {
      authTagLength: AUTH_TAG_LENGTH
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Reads and decrypts all stored accounts from disk.
   *
   * @returns {Promise<Array<object>>} List of decrypted account objects
   */
  async getAll() {
    await this.init();

    try {
      const raw = await fs.readFile(this.vaultFilePath, 'utf8');
      if (!raw.trim()) return [];

      const decryptedJson = this.decrypt(raw.trim());
      const accounts = JSON.parse(decryptedJson);
      return Array.isArray(accounts) ? accounts : [];
    } catch (err) {
      if (err.code === 'ENOENT') {
        return [];
      }
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        throw new Error(`Failed to read vault data: Permission denied on ${this.vaultFilePath} (${err.code})`);
      }
      throw err;
    }
  }

  /**
   * Retrieves public summary of accounts without sensitive passwords or tokens.
   *
   * @returns {Promise<Array<object>>}
   */
  async getPublicList() {
    const accounts = await this.getAll();
    return accounts.map((acc) => ({
      id: acc.id,
      provider: acc.provider,
      label: acc.label,
      email: acc.email,
      authType: acc.auth?.type || 'password',
      connected: true,
      lastVerifiedAt: acc.lastVerifiedAt || null,
      createdAt: acc.createdAt || null,
      updatedAt: acc.updatedAt || null,
      expiresAt: acc.auth?.expiresAt || null,
      inboxStatus: acc.inboxStatus || null
    }));
  }

  /**
   * Finds an account by ID.
   *
   * @param {string} id - Account ID
   * @returns {Promise<object|null>}
   */
  async getById(id) {
    const accounts = await this.getAll();
    return accounts.find((a) => a.id === id) || null;
  }

  /**
   * Acquires a cross-process file-level lock on the vault.
   * Uses exclusive atomic file creation ('wx' flag) with backoff and stale lock eviction.
   * @private
   */
  async _acquireFileLock(maxWaitMs = 10000) {
    const lockFile = this.lockFilePath;
    const start = Date.now();
    const staleThresholdMs = 15000;

    while (true) {
      let handle = null;
      try {
        handle = await fs.open(lockFile, 'wx');
        try {
          await handle.writeFile(JSON.stringify({ pid: process.pid, time: Date.now() }));
        } finally {
          await handle.close().catch(() => {});
        }

        let released = false;
        return async () => {
          if (!released) {
            released = true;
            try {
              await fs.unlink(lockFile);
            } catch {
              // ignore cleanup error
            }
          }
        };
      } catch (err) {
        if (handle) {
          // If handle was opened but writing failed, clean up partial lockfile
          await fs.unlink(lockFile).catch(() => {});
        }

        const isContention =
          err.code === 'EEXIST' ||
          (process.platform === 'win32' && (err.code === 'EPERM' || err.code === 'EBUSY'));

        if (isContention) {
          // Check for stale lock from dead or interrupted process
          try {
            const stat = await fs.stat(lockFile);
            if (Date.now() - stat.mtimeMs > staleThresholdMs) {
              await fs.unlink(lockFile).catch(() => {});
              continue;
            }
          } catch {
            // Stat may fail if lock file is in transit or temporarily locked
          }

          if (Date.now() - start > maxWaitMs) {
            throw new Error(`Timeout waiting for vault file lock at ${lockFile}`);
          }

          await new Promise((resolve) => setTimeout(resolve, 20 + Math.random() * 30));
          continue;
        }

        if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EROFS') {
          throw new Error(`Vault lock acquisition failed: Permission denied on ${lockFile} (${err.code})`);
        }

        throw err;
      }
    }
  }

  /**
   * Helper to serialize all mutating operations through both an in-memory queue
   * and a cross-instance file lock.
   * Prevents concurrent read-modify-write race conditions across calls and processes.
   * @private
   */
  _enqueueMutation(task) {
    const run = async () => {
      await this.init();
      const release = await this._acquireFileLock();
      try {
        return await task();
      } finally {
        await release();
      }
    };
    const queued = this._mutationQueue.then(run, run);
    this._mutationQueue = queued.catch(() => {});
    return queued;
  }

  /**
   * Saves or updates an account in the vault.
   * Automatically adds timestamp and writes atomically.
   *
   * @param {object} account - Account object
   * @returns {Promise<object>} The saved account
   */
  async saveAccount(account) {
    return this._enqueueMutation(async () => {
      if (!account.id) {
        account.id = crypto.randomUUID();
      }

      const now = new Date().toISOString();
      account.updatedAt = now;
      if (!account.createdAt) {
        account.createdAt = now;
      }

      const accounts = await this.getAll();
      const existingIndex = accounts.findIndex((a) => a.id === account.id || (a.email && a.email.toLowerCase() === account.email.toLowerCase()));

      if (existingIndex >= 0) {
        accounts[existingIndex] = { ...accounts[existingIndex], ...account };
      } else {
        accounts.push(account);
      }

      await this._writeVault(accounts);
      return account;
    });
  }

  /**
   * Explicitly removes an account (user logout).
   *
   * @param {string} id - Account ID to remove
   * @returns {Promise<boolean>} True if removed, false if not found
   */
  async removeAccount(id) {
    return this._enqueueMutation(async () => {
      const accounts = await this.getAll();
      const filtered = accounts.filter((a) => a.id !== id);

      if (filtered.length === accounts.length) {
        return false;
      }

      await this._writeVault(filtered);
      return true;
    });
  }

  /**
   * Writes accounts array to encrypted vault file atomically using a temp file.
   * Includes Windows rename retry loop to withstand transient file locks.
   * @private
   */
  async _writeVault(accounts) {
    const serialized = JSON.stringify(accounts, null, 2);
    const encrypted = this.encrypt(serialized);
    const tempFile = `${this.vaultFilePath}.tmp-${crypto.randomUUID()}`;

    try {
      await fs.writeFile(tempFile, encrypted, 'utf8');

      // On Windows, fs.rename can momentarily fail with EPERM or EBUSY if locked by reader/indexer
      let renamed = false;
      let lastErr = null;
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          await fs.rename(tempFile, this.vaultFilePath);
          renamed = true;
          break;
        } catch (renameErr) {
          lastErr = renameErr;
          if (['EPERM', 'EBUSY', 'EACCES'].includes(renameErr.code) && attempt < 4) {
            await new Promise((r) => setTimeout(r, 25 * (attempt + 1)));
            continue;
          }
          throw renameErr;
        }
      }
      if (!renamed && lastErr) {
        throw lastErr;
      }
    } catch (err) {
      try {
        await fs.unlink(tempFile);
      } catch {
        // ignore cleanup error
      }
      if (err.code === 'EACCES' || err.code === 'EROFS') {
        throw new Error(`Failed to write vault data: Permission denied on ${this.vaultFilePath} (${err.code})`);
      }
      throw err;
    }
  }

  /**
   * Clears all accounts from the vault.
   */
  async clear() {
    return this._enqueueMutation(async () => {
      try {
        await fs.unlink(this.vaultFilePath);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    });
  }
}

// Default singleton instance
export const defaultVault = new CredentialVault();
