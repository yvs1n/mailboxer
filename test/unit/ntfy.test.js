/**
 * ntfy.sh Notification Conduit Unit Test Suite
 *
 * Verifies payload construction (priority 5, rotating_light tags, view/http action buttons),
 * Authorization token inclusion, gracefully unconfigured skipping, and HTTP dispatch handling.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NtfyConduit } from '../../src/notifications/ntfy.js';

describe('ntfy.sh Alert Conduit (src/notifications/ntfy.js)', () => {
  describe('1. Configuration & URL Normalization', () => {
    it('detects unconfigured vs configured topic and normalizes base URLs', () => {
      const emptyConduit = new NtfyConduit({ topic: '' });
      assert.equal(emptyConduit.isConfigured, false);

      const conduit = new NtfyConduit({
        topic: 'mailboxer-vip-alerts',
        serverUrl: 'https://ntfy.sh///',
        appBaseUrl: 'http://localhost:3000///',
        token: 'tk_secret_123'
      });

      assert.equal(conduit.isConfigured, true);
      assert.equal(conduit.serverUrl, 'https://ntfy.sh');
      assert.equal(conduit.appBaseUrl, 'http://localhost:3000');
      assert.equal(conduit.token, 'tk_secret_123');
    });
  });

  describe('2. Payload Formatting for VIP and Interactive Action Buttons', () => {
    it('formats priority 5 VIP alert with tags and mark-read action button', () => {
      const conduit = new NtfyConduit({
        topic: 'my-alerts',
        appBaseUrl: 'http://localhost:3000'
      });

      const payload = conduit.formatPayload({
        category: 'VIP',
        priority: 5,
        title: '⭐ VIP: advisor@stanford.edu',
        body: 'Urgent: thesis defense schedule confirmation',
        messageId: 'msg_987',
        clickUrl: 'http://localhost:3000/#msg-msg_987'
      });

      assert.equal(payload.topic, 'my-alerts');
      assert.equal(payload.title, '⭐ VIP: advisor@stanford.edu');
      assert.equal(payload.priority, 5);
      assert.ok(payload.tags.includes('rotating_light'));
      assert.ok(payload.tags.includes('star'));
      assert.equal(payload.click, 'http://localhost:3000/#msg-msg_987');

      // Verify actions
      assert.equal(payload.actions.length, 2);
      assert.equal(payload.actions[0].action, 'view');
      assert.equal(payload.actions[0].url, 'http://localhost:3000/#msg-msg_987');

      assert.equal(payload.actions[1].action, 'http');
      assert.equal(payload.actions[1].label, 'Mark Read');
      assert.equal(payload.actions[1].method, 'POST');
      assert.equal(payload.actions[1].url, 'http://localhost:3000/api/messages/msg_987/read');
    });

    it('formats standard notification with priority 3 for non-VIP', () => {
      const conduit = new NtfyConduit({ topic: 'my-alerts' });

      const payload = conduit.formatPayload({
        category: 'UPDATE',
        message: 'Canvas quiz grade posted'
      });

      assert.equal(payload.priority, 3);
      assert.equal(payload.tags.includes('rotating_light'), false);
    });
  });

  describe('3. HTTP Dispatch & Error Handling', () => {
    it('gracefully returns false when topic is not configured', async () => {
      const conduit = new NtfyConduit({ topic: '' });
      let fetchCalled = false;
      const res = await conduit.send({ category: 'VIP', body: 'Test' }, {
        fetch: async () => { fetchCalled = true; }
      });

      assert.equal(res, false);
      assert.equal(fetchCalled, false);
    });

    it('dispatches HTTP POST with bearer token and JSON body to ntfy server', async () => {
      const conduit = new NtfyConduit({
        topic: 'student-vip-inbox',
        serverUrl: 'https://ntfy.sh',
        token: 'tk_test_auth'
      });

      let requestedUrl = null;
      let requestedMethod = null;
      let requestedHeaders = null;
      let requestedPayload = null;

      const mockFetch = async (url, init) => {
        requestedUrl = url;
        requestedMethod = init.method;
        requestedHeaders = init.headers;
        requestedPayload = JSON.parse(init.body);

        return {
          ok: true,
          status: 200,
          text: async () => '{"id":"ntfy_evt_1"}'
        };
      };

      const success = await conduit.send({
        category: 'VIP',
        title: '⭐ VIP Alert',
        body: 'Office hours updated'
      }, { fetch: mockFetch });

      assert.equal(success, true);
      assert.equal(requestedUrl, 'https://ntfy.sh/student-vip-inbox');
      assert.equal(requestedMethod, 'POST');
      assert.equal(requestedHeaders['Content-Type'], 'application/json');
      assert.equal(requestedHeaders['Authorization'], 'Bearer tk_test_auth');
      assert.equal(requestedPayload.topic, 'student-vip-inbox');
      assert.equal(requestedPayload.priority, 5);
    });

    it('throws descriptive error on server HTTP failure', async () => {
      const conduit = new NtfyConduit({ topic: 'restricted-topic' });

      const mockFetch = async () => ({
        ok: false,
        status: 403,
        text: async () => 'Forbidden: topic requires write authentication'
      });

      await assert.rejects(
        () => conduit.send({ body: 'test' }, { fetch: mockFetch }),
        /ntfy dispatch to "restricted-topic" failed with HTTP 403/
      );
    });
  });
});
