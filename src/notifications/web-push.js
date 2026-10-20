/**
 * Mailboxer Zero-Dependency Web Push Notification Engine
 *
 * Implements IETF Web Push protocols:
 * - RFC 8292: Voluntary Application Server Identification (VAPID) for Web Push
 * - RFC 8291: Message Encryption for Web Push (aes128gcm with native ECDH / HKDF)
 *
 * Uses 100% native Node.js 22 built-ins (node:crypto, node:fs, globalThis.fetch)
 * with zero external npm dependencies.
 *
 * @module notifications/web-push
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const VAPID_KEY_FILE = process.env.VAPID_KEY_PATH || path.resolve(process.env.DATA_DIR || './data', 'vapid.json');

/**
 * Generates an uncompressed NIST P-256 (prime256v1) EC keypair for VAPID.
 *
 * @returns {{publicKey: string, privateKey: string}} Base64URL-encoded keypair
 */
export function generateVapidKeys() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();

  const publicKeyBuffer = ecdh.getPublicKey(); // 65 bytes uncompressed point 0x04 || X || Y
  const privateKeyBuffer = ecdh.getPrivateKey(); // 32 bytes scalar

  return {
    publicKey: publicKeyBuffer.toString('base64url'),
    privateKey: privateKeyBuffer.toString('base64url')
  };
}

/**
 * Loads or automatically generates persistent VAPID keys.
 *
 * @param {string} [filePath] - Optional custom path for vapid.json
 * @returns {{publicKey: string, privateKey: string}}
 */
export function getOrCreateVapidKeys(filePath = VAPID_KEY_FILE) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(content);
      if (parsed.publicKey && parsed.privateKey) {
        return parsed;
      }
    }
  } catch {
    // If invalid or missing, generate new
  }

  const keys = generateVapidKeys();
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(keys, null, 2), { mode: 0o600 });
  } catch (err) {
    // In-memory or restricted environments
  }

  return keys;
}

/**
 * Creates an RFC 8292 compliant VAPID JWT token signed with ES256 (ECDSA P-256 with SHA-256).
 *
 * @param {string} audience - Push service origin (e.g. 'https://fcm.googleapis.com' or 'https://push.services.mozilla.com')
 * @param {string} subject - Contact URI (e.g. 'mailto:admin@mailboxer.local')
 * @param {string} privateKeyBase64Url - 32-byte scalar base64url
 * @param {string} publicKeyBase64Url - 65-byte point base64url
 * @param {number} [expirationSeconds=43200] - Expiration duration (default: 12 hours)
 * @returns {string} Signed JWT
 */
export function createVapidJwt(audience, subject, privateKeyBase64Url, publicKeyBase64Url, expirationSeconds = 43200) {
  const header = {
    typ: 'JWT',
    alg: 'ES256'
  };

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    aud: audience,
    exp: now + expirationSeconds,
    sub: subject || 'mailto:admin@mailboxer.local'
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const claimsB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const unsignedToken = `${headerB64}.${claimsB64}`;

  const pubBuf = Buffer.from(publicKeyBase64Url, 'base64url');
  const privBuf = Buffer.from(privateKeyBase64Url, 'base64url');

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: pubBuf.subarray(1, 33).toString('base64url'),
    y: pubBuf.subarray(33, 65).toString('base64url'),
    d: privBuf.toString('base64url')
  };

  const privateKeyObj = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const signature = crypto.sign('sha256', Buffer.from(unsignedToken, 'utf8'), {
    key: privateKeyObj,
    dsaEncoding: 'ieee-p1363'
  });

  return `${unsignedToken}.${signature.toString('base64url')}`;
}

/**
 * Encrypts a plaintext payload using RFC 8291 aes128gcm message encryption.
 *
 * @param {string|Buffer|object} payload - Notification data to encrypt
 * @param {string|Buffer} clientPublicKey - Subscriber's p256dh key (uncompressed point, 65 bytes)
 * @param {string|Buffer} clientAuth - Subscriber's 16-byte auth secret
 * @returns {Buffer} Formatted binary body for Web Push request
 */
export function encryptWebPushPayload(payload, clientPublicKey, clientAuth) {
  const clientPubBuf = Buffer.isBuffer(clientPublicKey) ? clientPublicKey : Buffer.from(clientPublicKey, 'base64url');
  const authBuf = Buffer.isBuffer(clientAuth) ? clientAuth : Buffer.from(clientAuth, 'base64url');

  // Convert payload to buffer
  const payloadBuf = typeof payload === 'string'
    ? Buffer.from(payload, 'utf8')
    : (Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload), 'utf8'));

  // 1. Generate ephemeral local EC P-256 keypair
  const localEcdh = crypto.createECDH('prime256v1');
  localEcdh.generateKeys();
  const localPublicKey = localEcdh.getPublicKey(); // 65 bytes uncompressed point

  // 2. Compute shared secret via ECDH
  const sharedSecret = localEcdh.computeSecret(clientPubBuf);

  // 3. Generate 16-byte random salt
  const salt = crypto.randomBytes(16);

  // 4. Derive Pseudo-Random Key (PRK) per RFC 8291 §3.2
  const keyInfo = Buffer.concat([
    Buffer.from('WebPush: info\0', 'utf8'),
    clientPubBuf,
    localPublicKey
  ]);
  const prk = crypto.hkdfSync('sha256', sharedSecret, authBuf, keyInfo, 32);

  // 5. Derive Content Encryption Key (CEK) and Nonce per RFC 8291 §3.3
  const cekInfo = Buffer.from('Content-Encoding: aes128gcm\0', 'utf8');
  const cek = crypto.hkdfSync('sha256', prk, salt, cekInfo, 16);

  const nonceInfo = Buffer.from('Content-Encoding: nonce\0', 'utf8');
  const nonce = crypto.hkdfSync('sha256', prk, salt, nonceInfo, 12);

  // 6. Delimit payload record with 0x02 for final record per RFC 8291 §4
  const padded = Buffer.concat([payloadBuf, Buffer.from([0x02])]);

  // 7. Encrypt payload with AES-128-GCM
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final(), cipher.getAuthTag()]);

  // 8. Assemble RFC 8291 message wire header:
  // salt (16 bytes) || rs (4 bytes) || idlen (1 byte) || keyid (localPublicKey) || ciphertext
  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096, 0); // standard record size
  const idlen = Buffer.from([localPublicKey.length]);

  return Buffer.concat([salt, rs, idlen, localPublicKey, ciphertext]);
}

/**
 * Decrypts an RFC 8291 aes128gcm encrypted payload (for testing and client verification).
 *
 * @param {Buffer} encryptedWireBody
 * @param {crypto.ECDH} clientEcdh
 * @param {Buffer} authSecret
 * @returns {Buffer} Decrypted plaintext
 */
export function decryptWebPushPayload(encryptedWireBody, clientEcdh, authSecret) {
  const salt = encryptedWireBody.subarray(0, 16);
  const idlen = encryptedWireBody[20];
  const serverPubKey = encryptedWireBody.subarray(21, 21 + idlen);
  const ciphertextWithTag = encryptedWireBody.subarray(21 + idlen);

  const clientPubKey = clientEcdh.getPublicKey();
  const sharedSecret = clientEcdh.computeSecret(serverPubKey);

  const keyInfo = Buffer.concat([
    Buffer.from('WebPush: info\0', 'utf8'),
    clientPubKey,
    serverPubKey
  ]);
  const prk = crypto.hkdfSync('sha256', sharedSecret, authSecret, keyInfo, 32);

  const cekInfo = Buffer.from('Content-Encoding: aes128gcm\0', 'utf8');
  const cek = crypto.hkdfSync('sha256', prk, salt, cekInfo, 16);

  const nonceInfo = Buffer.from('Content-Encoding: nonce\0', 'utf8');
  const nonce = crypto.hkdfSync('sha256', prk, salt, nonceInfo, 12);

  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);

  const decipher = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(authTag);
  const decryptedPadded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // Remove final delimiter
  return decryptedPadded.subarray(0, decryptedPadded.length - 1);
}

/**
 * Web Push Notification Conduit.
 */
export class WebPushConduit {
  /**
   * @param {object} [options={}]
   * @param {string} [options.contactEmail] - VAPID contact email (mailto:...)
   * @param {import('../storage/sqlite-store.js').SqliteStore} [options.store] - SQLite store for subscription management
   * @param {string} [options.vapidPath] - Path to vapid.json
   */
  constructor(options = {}) {
    this.options = { ...options };
    this.contactEmail = options.contactEmail || process.env.VAPID_CONTACT_EMAIL || 'mailto:admin@mailboxer.local';
    this.store = options.store || null;
    this.keys = getOrCreateVapidKeys(options.vapidPath || VAPID_KEY_FILE);
  }

  /**
   * Returns the base64url uncompressed VAPID public key.
   * @returns {string}
   */
  getPublicKey() {
    return this.keys.publicKey;
  }

  /**
   * Sends a Web Push notification to a specific push subscription.
   *
   * @param {object} subscription - Push subscription { endpoint, keys: { p256dh, auth } }
   * @param {object|string} payload - Notification payload
   * @param {object} [options={}]
   * @returns {Promise<boolean>}
   */
  async send(subscription, payload, options = {}) {
    if (!subscription || !subscription.endpoint) {
      throw new Error('Push subscription must provide an endpoint');
    }

    const endpoint = subscription.endpoint;
    const p256dh = subscription.keys?.p256dh || subscription.p256dh;
    const auth = subscription.keys?.auth || subscription.auth;

    if (!p256dh || !auth) {
      throw new Error('Push subscription must provide p256dh and auth keys');
    }

    // Determine push service origin audience
    const url = new URL(endpoint);
    const audience = `${url.protocol}//${url.host}`;

    // 1. Generate VAPID JWT
    const jwt = createVapidJwt(
      audience,
      this.contactEmail,
      this.keys.privateKey,
      this.keys.publicKey,
      options.expirationSeconds || 43200
    );

    // 2. Encrypt payload
    const body = encryptWebPushPayload(payload, p256dh, auth);

    // 3. Dispatch POST request
    const headers = {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': String(options.ttl || 86400),
      'Authorization': `vapid t=${jwt}, k=${this.keys.publicKey}`,
      ...(options.headers || {})
    };

    const fetchFn = options.fetch || globalThis.fetch;
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers,
      body
    });

    if (res.status === 201 || res.status === 200 || res.status === 202) {
      if (this.store?.touchPushSubscription) {
        try { this.store.touchPushSubscription(endpoint); } catch {}
      }
      return true;
    }

    // Auto-purge expired or revoked subscriptions
    if (res.status === 410 || res.status === 404) {
      if (this.store?.deletePushSubscription) {
        try { this.store.deletePushSubscription(endpoint); } catch {}
      }
      return false;
    }

    const text = await res.text().catch(() => '');
    throw new Error(`Web Push delivery failed with HTTP ${res.status}: ${text}`);
  }

  /**
   * Broadcasts a notification to all registered subscriptions in SQLite store.
   *
   * @param {object|string} payload
   * @param {object} [options={}]
   * @returns {Promise<{sent: number, failed: number}>}
   */
  async sendToAll(payload, options = {}) {
    if (!this.store?.getPushSubscriptions) {
      return { sent: 0, failed: 0 };
    }

    const subscriptions = this.store.getPushSubscriptions();
    let sent = 0;
    let failed = 0;

    const promises = subscriptions.map(async (sub) => {
      try {
        const ok = await this.send(sub, payload, options);
        if (ok) sent++;
        else failed++;
      } catch {
        failed++;
      }
    });

    await Promise.allSettled(promises);
    return { sent, failed };
  }
}
