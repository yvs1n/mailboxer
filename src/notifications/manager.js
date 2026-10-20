/**
 * Mailboxer Unified Notification Manager
 *
 * Orchestrates dual conduits (Web Push & ntfy.sh), formats VIP alerts,
 * and handles dispatch filtering based on anti-noise triage results.
 *
 * @module notifications/manager
 */

import { WebPushConduit } from './web-push.js';
import { NtfyConduit } from './ntfy.js';

/**
 * Unified Notification Manager.
 */
export class NotificationManager {
  /**
   * @param {object} [options={}]
   * @param {import('../storage/sqlite-store.js').SqliteStore} [options.store] - Database store
   * @param {WebPushConduit} [options.webPush] - Web Push conduit instance
   * @param {NtfyConduit} [options.ntfy] - ntfy conduit instance
   * @param {string} [options.ntfyTopic] - Default ntfy topic
   * @param {string} [options.appBaseUrl] - Base application URL
   */
  constructor(options = {}) {
    this.options = { ...options };
    this.store = options.store || null;
    this.webPush = options.webPush || new WebPushConduit({ store: this.store });
    this.ntfy = options.ntfy || new NtfyConduit({
      topic: options.ntfyTopic || process.env.NTFY_TOPIC,
      appBaseUrl: options.appBaseUrl
    });
    this.lastDispatchedAt = null;
  }

  /**
   * Dispatches a notification across all enabled conduits for an email message.
   *
   * @param {object} message - Message record
   * @param {object} [triageResult={}] - Triage classification result
   * @param {object} [options={}]
   * @returns {Promise<{dispatched: boolean, webPushResult: any, ntfyResult: any}>}
   */
  async dispatch(message, triageResult = {}, options = {}) {
    if (!message) {
      return { dispatched: false, reason: 'No message provided' };
    }

    const shouldNotify = options.force || triageResult.shouldNotify || triageResult.category === 'VIP';
    if (!shouldNotify) {
      return {
        dispatched: false,
        category: triageResult.category || 'NORMAL',
        reason: 'Notification muted by triage engine'
      };
    }

    const senderDisplay = message.sender || message.senderEmail || message.sender_email || 'VIP Sender';
    const subject = message.subject || '(No Subject)';
    const snippet = message.bodySnippet || message.body_snippet || message.body || '';
    const cleanSnippet = snippet ? String(snippet).replace(/\s+/g, ' ').trim().slice(0, 160) : '';

    const title = `⭐ VIP: ${senderDisplay}`;
    const body = cleanSnippet ? `${subject}\n\n${cleanSnippet}` : subject;
    const msgId = message.id || message.messageId || message.message_id || message.uid;
    const clickUrl = `/#msg-${msgId}`;

    const notificationPayload = {
      title,
      body,
      category: triageResult.category || 'VIP',
      score: triageResult.score || 95,
      messageId: msgId,
      accountId: message.accountId || message.account_id,
      clickUrl,
      data: {
        messageId: msgId,
        accountId: message.accountId || message.account_id,
        category: triageResult.category || 'VIP',
        url: clickUrl
      }
    };

    const results = {
      dispatched: true,
      timestamp: new Date().toISOString(),
      webPushResult: null,
      ntfyResult: null
    };

    // 1. Web Push Dispatch
    try {
      if (this.webPush) {
        results.webPushResult = await this.webPush.sendToAll(notificationPayload, options);
      }
    } catch (err) {
      results.webPushResult = { error: err.message };
    }

    // 2. ntfy.sh Dispatch
    try {
      if (this.ntfy && this.ntfy.isConfigured) {
        results.ntfyResult = await this.ntfy.send(notificationPayload, options);
      }
    } catch (err) {
      results.ntfyResult = { error: err.message };
    }

    this.lastDispatchedAt = results.timestamp;
    return results;
  }

  /**
   * Dispatches a test alert across conduits to verify deliverability.
   *
   * @param {object} [options={}]
   * @returns {Promise<object>} Dispatch results
   */
  async sendTestAlert(options = {}) {
    const testMessage = {
      id: `test_${Date.now()}`,
      sender: 'Prof. Mailboxer Test',
      senderEmail: 'test@mailboxer.local',
      subject: options.subject || 'Mailboxer VIP Conduit Verification Test',
      bodySnippet: options.body || 'This is a genuine verification alert confirming your Web Push & ntfy.sh conduits are fully operational.'
    };

    const testTriage = {
      category: 'VIP',
      action: 'notify',
      shouldNotify: true,
      score: 100,
      matchedRule: 'SYSTEM_TEST',
      reason: 'User-triggered conduit verification test'
    };

    return this.dispatch(testMessage, testTriage, { force: true, ...options });
  }
}
