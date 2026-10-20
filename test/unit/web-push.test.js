/**
 * Web Push (RFC 8292 VAPID & RFC 8291 aes128gcm) Unit Test Suite
 *
 * Verifies zero-dependency NIST P-256 key generation, ES256 JWT creation,
 * IEEE-P1363 signature verification, RFC 8291 aes128gcm encryption & round-trip
 * decryption, conduit HTTP dispatch, and 410 auto-purge lifecycle.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import {
  generateVapidKeys,
  getOrCreateVapidKeys,
  createVapidJwt,
  encryptWebPushPayload,
  decryptWebPushPayload,
  WebPushConduit
} from '../../src/notifications/web-push.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

describe('Web Push Engine (RFC 8292 VAPID & RFC 8291 aes128gcm)', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'web-push-test-'));
  });

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('1. VAPID Keypair Generation & Persistence', () => {
    it('generates compliant NIST P-256 (prime256v1) keypair in base64url', () => {
      const keys = generateVapidKeys();

      assert.ok(keys.publicKey, 'Expected publicKey in generated keys');
      assert.ok(keys.privateKey, 'Expected privateKey in generated keys');

      const pubBuf = Buffer.from(keys.publicKey, 'base64url');
      const privBuf = Buffer.from(keys.privateKey, 'base64url');

      // Uncompressed P-256 public key is 65 bytes (0x04 || X_32 || Y_32)
      assert.equal(pubBuf.length, 65);
      assert.equal(pubBuf[0], 0x04, 'Public key must start with uncompressed point prefix 0x04');

      // Private key scalar is 32 bytes
      assert.equal(privBuf.length, 32);

      // Verify successive calls generate distinct keys
      const secondKeys = generateVapidKeys();
      assert.notEqual(keys.publicKey, secondKeys.publicKey);
      assert.notEqual(keys.privateKey, secondKeys.privateKey);
    });

    it('persists and reloads VAPID keys from disk', () => {
      const keyFile = path.join(tmpDir, 'test-vapid.json');
      const keys1 = getOrCreateVapidKeys(keyFile);

      assert.ok(fs.existsSync(keyFile));
      const fileData = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      assert.equal(fileData.publicKey, keys1.publicKey);
      assert.equal(fileData.privateKey, keys1.privateKey);

      // Second call reads existing file
      const keys2 = getOrCreateVapidKeys(keyFile);
      assert.equal(keys2.publicKey, keys1.publicKey);
      assert.equal(keys2.privateKey, keys1.privateKey);
    });
  });

  describe('2. RFC 8292 VAPID ES256 JWT Generation & Verification', () => {
    it('creates valid ES256 JWT with correct claims and IEEE-P1363 signature', () => {
      const keys = generateVapidKeys();
      const audience = 'https://fcm.googleapis.com';
      const subject = 'mailto:admin@mailboxer.local';

      const jwt = createVapidJwt(audience, subject, keys.privateKey, keys.publicKey, 3600);
      assert.ok(jwt);

      const parts = jwt.split('.');
      assert.equal(parts.length, 3, 'JWT must have 3 dot-separated parts');

      // 1. Verify Header
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      assert.equal(header.typ, 'JWT');
      assert.equal(header.alg, 'ES256');

      // 2. Verify Claims
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      assert.equal(claims.aud, audience);
      assert.equal(claims.sub, subject);
      assert.ok(claims.exp > Math.floor(Date.now() / 1000));

      // 3. Verify Signature using native crypto.verify
      const pubBuf = Buffer.from(keys.publicKey, 'base64url');
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: pubBuf.subarray(1, 33).toString('base64url'),
        y: pubBuf.subarray(33, 65).toString('base64url')
      };
      const publicKeyObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });

      const unsigned = `${parts[0]}.${parts[1]}`;
      const signatureBuf = Buffer.from(parts[2], 'base64url');
      assert.equal(signatureBuf.length, 64, 'IEEE-P1363 ES256 signature must be exactly 64 bytes (r || s)');

      const isValid = crypto.verify(
        'sha256',
        Buffer.from(unsigned, 'utf8'),
        { key: publicKeyObj, dsaEncoding: 'ieee-p1363' },
        signatureBuf
      );
      assert.equal(isValid, true, 'VAPID JWT signature must verify against public key');
    });
  });

  describe('3. RFC 8291 aes128gcm Encryption & Round-Trip Decryption', () => {
    it('encrypts plaintext payload and decrypts back to exact original content', () => {
      // Simulate client browser ECDH keypair and 16-byte auth secret
      const clientEcdh = crypto.createECDH('prime256v1');
      clientEcdh.generateKeys();
      const clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
      const clientAuthSecret = crypto.randomBytes(16).toString('base64url');

      const originalPayload = JSON.stringify({
        title: '⭐ VIP Alert: Dean of Engineering',
        body: 'Urgent notice regarding grant proposal submission.',
        url: '/#msg-992'
      });

      const encryptedWireBody = encryptWebPushPayload(originalPayload, clientPublicKey, clientAuthSecret);

      assert.ok(Buffer.isBuffer(encryptedWireBody));
      // Wire header checks: salt (16), rs (4), idlen (1), keyid (65) = 86 bytes header
      assert.ok(encryptedWireBody.length > 86);
      const salt = encryptedWireBody.subarray(0, 16);
      assert.equal(salt.length, 16);

      const rs = encryptedWireBody.readUInt32BE(16);
      assert.equal(rs, 4096);

      const idlen = encryptedWireBody[20];
      assert.equal(idlen, 65);

      // Decrypt using subscriber's private ECDH and auth secret
      const decryptedBuffer = decryptWebPushPayload(
        encryptedWireBody,
        clientEcdh,
        Buffer.from(clientAuthSecret, 'base64url')
      );

      const decryptedText = decryptedBuffer.toString('utf8');
      assert.equal(decryptedText, originalPayload);
    });
  });

  describe('4. WebPushConduit Dispatch & SQLite Subscription Lifecycle', () => {
    let store;

    beforeEach(() => {
      store = new SqliteStore(':memory:');
    });

    afterEach(() => {
      store?.close();
    });

    it('successfully dispatches push payload with correct headers and handles 201 Created', async () => {
      const conduit = new WebPushConduit({
        store,
        vapidPath: path.join(tmpDir, 'vapid.json'),
        contactEmail: 'mailto:notifications@mailboxer.local'
      });

      const clientEcdh = crypto.createECDH('prime256v1');
      clientEcdh.generateKeys();
      const clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
      const clientAuthSecret = crypto.randomBytes(16).toString('base64url');

      const subscription = {
        endpoint: 'https://push.services.mozilla.com/wpush/v2/test_sub_123',
        keys: {
          p256dh: clientPublicKey,
          auth: clientAuthSecret
        }
      };

      store.upsertPushSubscription(subscription);
      assert.equal(store.getPushSubscriptions().length, 1);

      let fetchCalled = false;
      let requestedHeaders = null;
      let requestedBody = null;

      const mockFetch = async (url, init) => {
        fetchCalled = true;
        assert.equal(url, subscription.endpoint);
        assert.equal(init.method, 'POST');
        requestedHeaders = init.headers;
        requestedBody = init.body;

        return {
          status: 201,
          ok: true,
          text: async () => 'Created'
        };
      };

      const ok = await conduit.send(subscription, { message: 'Hello Push' }, { fetch: mockFetch });

      assert.equal(ok, true);
      assert.equal(fetchCalled, true);
      assert.equal(requestedHeaders['Content-Type'], 'application/octet-stream');
      assert.equal(requestedHeaders['Content-Encoding'], 'aes128gcm');
      assert.ok(requestedHeaders['Authorization'].startsWith('vapid t='));
      assert.ok(Buffer.isBuffer(requestedBody));

      // Subscriber touched in database
      const sub = store.getPushSubscription(subscription.endpoint);
      assert.ok(sub.last_used_at);
    });

    it('automatically purges expired subscription from SQLite on HTTP 410 Gone', async () => {
      const conduit = new WebPushConduit({
        store,
        vapidPath: path.join(tmpDir, 'vapid.json')
      });

      const clientEcdh = crypto.createECDH('prime256v1');
      clientEcdh.generateKeys();
      const clientPublicKey = clientEcdh.getPublicKey().toString('base64url');
      const clientAuthSecret = crypto.randomBytes(16).toString('base64url');

      const subscription = {
        endpoint: 'https://fcm.googleapis.com/fcm/send/expired_sub_456',
        keys: {
          p256dh: clientPublicKey,
          auth: clientAuthSecret
        }
      };

      store.upsertPushSubscription(subscription);
      assert.equal(store.getPushSubscriptions().length, 1);

      const mockFetch = async () => ({
        status: 410,
        ok: false,
        text: async () => 'Gone'
      });

      const ok = await conduit.send(subscription, { message: 'Dead push' }, { fetch: mockFetch });

      assert.equal(ok, false);
      // Subscription must be automatically purged
      assert.equal(store.getPushSubscription(subscription.endpoint), null);
      assert.equal(store.getPushSubscriptions().length, 0);
    });

    it('broadcasts to all registered subscriptions via sendToAll', async () => {
      const conduit = new WebPushConduit({
        store,
        vapidPath: path.join(tmpDir, 'vapid.json')
      });

      // Add two subscriptions
      for (let i = 1; i <= 2; i++) {
        const ecdh = crypto.createECDH('prime256v1');
        ecdh.generateKeys();
        store.upsertPushSubscription({
          endpoint: `https://push.mock/client${i}`,
          keys: {
            p256dh: ecdh.getPublicKey().toString('base64url'),
            auth: crypto.randomBytes(16).toString('base64url')
          }
        });
      }

      assert.equal(store.getPushSubscriptions().length, 2);

      let callCount = 0;
      const mockFetch = async () => {
        callCount++;
        return { status: 201, ok: true, text: async () => 'Created' };
      };

      const result = await conduit.sendToAll({ title: 'Broadcast Test' }, { fetch: mockFetch });

      assert.equal(result.sent, 2);
      assert.equal(result.failed, 0);
      assert.equal(callCount, 2);
    });
  });
});
