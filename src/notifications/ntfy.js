/**
 * Mailboxer ntfy.sh Notification Conduit
 *
 * Dispatches high-priority push alerts to ntfy.sh (or self-hosted ntfy servers)
 * with deep links, sound/vibration priority levels, and interactive action buttons.
 *
 * Zero-dependency native Node.js 22 implementation using globalThis.fetch.
 *
 * @module notifications/ntfy
 */

/**
 * ntfy.sh Alert Conduit.
 */
export class NtfyConduit {
  /**
   * @param {object} [options={}]
   * @param {string} [options.topic] - ntfy topic channel name
   * @param {string} [options.serverUrl='https://ntfy.sh'] - Server base URL
   * @param {string} [options.token] - Optional auth token for private topics
   * @param {string} [options.appBaseUrl='http://localhost:3000'] - Base URL for deep links
   */
  constructor(options = {}) {
    this.topic = options.topic || process.env.NTFY_TOPIC || '';
    this.serverUrl = (options.serverUrl || process.env.NTFY_SERVER_URL || 'https://ntfy.sh').replace(/\/+$/, '');
    this.token = options.token || process.env.NTFY_TOKEN || null;
    this.appBaseUrl = (options.appBaseUrl || process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
  }

  /**
   * Whether ntfy is configured with a valid topic.
   * @returns {boolean}
   */
  get isConfigured() {
    return Boolean(this.topic && this.topic.trim().length > 0);
  }

  /**
   * Formats an alert payload for ntfy.sh.
   *
   * @param {object} notification - Notification details
   * @returns {object} Formatted ntfy payload
   */
  formatPayload(notification = {}) {
    const topic = notification.topic || this.topic;
    const isVip = notification.category === 'VIP' || notification.priority === 5;
    const title = notification.title || (isVip ? '⭐ Mailboxer VIP Alert' : 'Mailboxer Notification');
    const message = notification.body || notification.message || 'New email message received';
    const priority = notification.priority ?? (isVip ? 5 : 3);
    const tags = notification.tags || (isVip ? ['rotating_light', 'email', 'star'] : ['email']);

    const clickUrl = notification.clickUrl || notification.url || `${this.appBaseUrl}/`;

    const actions = notification.actions || [
      {
        action: 'view',
        label: 'Open in Mailboxer',
        url: clickUrl
      }
    ];

    if (notification.messageId) {
      actions.push({
        action: 'http',
        label: 'Mark Read',
        url: `${this.appBaseUrl}/api/messages/${encodeURIComponent(notification.messageId)}/read`,
        method: 'POST'
      });
    }

    return {
      topic,
      title,
      message,
      priority,
      tags,
      click: clickUrl,
      actions
    };
  }

  /**
   * Dispatches a notification payload to ntfy.sh.
   *
   * @param {object} notification
   * @param {object} [options={}]
   * @returns {Promise<boolean>}
   */
  async send(notification, options = {}) {
    const payload = this.formatPayload(notification);
    if (!payload.topic) {
      // Not configured, gracefully skip
      return false;
    }

    const endpoint = `${this.serverUrl}/${encodeURIComponent(payload.topic)}`;
    const headers = {
      'Content-Type': 'application/json'
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const fetchFn = options.fetch || globalThis.fetch;
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      return true;
    }

    const text = await res.text().catch(() => '');
    throw new Error(`ntfy dispatch to "${payload.topic}" failed with HTTP ${res.status}: ${text}`);
  }
}
