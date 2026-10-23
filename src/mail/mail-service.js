/**
 * Message reading and sending on top of the sync engine.
 *
 * - getBody: full message body (cached in SQLite after the first open)
 * - getAttachment: download one attachment from the server
 * - send: compose and submit over SMTP, optionally as a reply
 *
 * @module mail/mail-service
 */

import { parseMessage, getAttachment, buildMessage, parseAddressList } from './mime.js';
import { SmtpClient } from '../connection/smtp-client.js';
import { getPreset } from '../config/presets.js';

const MAX_CACHED_HTML = 2 * 1024 * 1024;

// These providers store a copy of SMTP-submitted mail in Sent on their own.
const PROVIDERS_THAT_SAVE_SENT = new Set(['gmail', 'outlook']);
const SENT_NAMES = ['sent', 'sent messages', 'sent items', 'sent mail', '[gmail]/sent mail'];

export class MailService {
  /**
   * @param {object} options
   * @param {import('../sync/sync-engine.js').SyncEngine} options.syncEngine
   * @param {import('../storage/sqlite-store.js').SqliteStore} options.store
   * @param {object} options.accountManager
   * @param {(cfg: object) => {send: Function}} [options.createSmtpClient]
   */
  constructor(options) {
    this.syncEngine = options.syncEngine;
    this.store = options.store;
    this.accountManager = options.accountManager;
    this.createSmtpClient = options.createSmtpClient || ((cfg) => new SmtpClient(cfg));
  }

  /**
   * Returns the full body of a stored message.
   * @param {object} message
   * @param {{refresh?: boolean}} [options]
   */
  async getBody(message, options = {}) {
    if (!options.refresh) {
      const cached = this.store.getMessageBody(message.id);
      if (cached) return { ...cached, cached: true };
    }

    const { parsed } = await this.syncEngine.fetchFullMessage(message, (raw) => parseMessage(raw));
    const body = {
      text: parsed.text,
      html: parsed.html.length > MAX_CACHED_HTML ? '' : parsed.html,
      attachments: parsed.attachments,
      headers: parsed.headers
    };
    // The message may have been deleted while we were fetching
    if (this.store.getMessage(message.id)) {
      this.store.saveMessageBody(message.id, body);
    }
    return { ...body, cached: false };
  }

  /**
   * Downloads one attachment.
   * @param {object} message
   * @param {number} index
   */
  async getAttachment(message, index) {
    const { raw } = await this.syncEngine.fetchFullMessage(message);
    return getAttachment(raw, index);
  }

  /** Resolves SMTP settings for an account (saved settings, else provider preset). */
  _smtpConfig(account) {
    const preset = getPreset(account.provider) || getPreset('custom');
    const smtp = account.smtp?.host ? account.smtp : preset?.smtp;
    if (!smtp?.host) {
      const err = new Error('No SMTP server is configured for this account');
      err.statusCode = 400;
      throw err;
    }
    return {
      host: smtp.host,
      port: smtp.port || 587,
      secure: smtp.secure ?? (Number(smtp.port) === 465),
      tls: smtp.tls
    };
  }

  /**
   * Sends a plain-text email.
   *
   * @param {object} params
   * @param {string} params.accountId - Account to send from
   * @param {string|string[]} params.to
   * @param {string|string[]} [params.cc]
   * @param {string|string[]} [params.bcc]
   * @param {string} [params.subject]
   * @param {string} [params.text]
   * @param {string} [params.replyToMessageId] - Stored message row ID being replied to
   * @returns {Promise<{messageId: string, accepted: string[], savedToSent: boolean}>}
   */
  async send(params) {
    const to = parseAddressList(params.to);
    const cc = parseAddressList(params.cc);
    const bcc = parseAddressList(params.bcc);
    if (to.length + cc.length + bcc.length === 0) {
      const err = new Error('Add at least one valid recipient');
      err.statusCode = 400;
      throw err;
    }

    const account = await this.accountManager.getImapConfig(params.accountId);
    const smtpConfig = this._smtpConfig(account);

    let inReplyTo;
    let references;
    if (params.replyToMessageId) {
      const original = this.store.getMessage(params.replyToMessageId);
      if (original?.messageId) {
        inReplyTo = original.messageId;
        references = this.store.getMessageBody(original.id)?.headers?.references || '';
      }
    }

    const { raw, messageId } = buildMessage({
      from: account.email,
      to,
      cc,
      subject: params.subject || '',
      text: params.text || '',
      inReplyTo,
      references
    });

    const smtp = this.createSmtpClient(smtpConfig);
    const auth = account.auth?.type === 'oauth2'
      ? { type: 'oauth2', user: account.auth.user || account.email, accessToken: account.auth.accessToken }
      : { type: 'password', user: account.auth?.user || account.email, pass: account.auth?.pass || account.appPassword || account.password };

    const result = await smtp.send({ from: account.email, recipients: [...to, ...cc, ...bcc], raw, auth });

    let savedToSent = PROVIDERS_THAT_SAVE_SENT.has(account.provider);
    if (!savedToSent) {
      savedToSent = await this._saveToSent(account.id, raw).catch((err) => {
        console.error(`[Mailboxer] Sent, but could not save a copy to Sent: ${err.message}`);
        return false;
      });
    }

    if (inReplyTo && params.replyToMessageId) {
      // Replying implies the original was read
      const original = this.store.getMessage(params.replyToMessageId);
      if (original && !original.isSeen) this.syncEngine.setMessageState(original, { seen: true });
    }

    return { messageId, accepted: result.accepted, savedToSent };
  }

  /** Appends a sent message to the account's Sent folder. @private */
  async _saveToSent(accountId, raw) {
    const client = await this.syncEngine._getAuthenticatedClient(accountId);
    try {
      const folders = await client.listMailboxes('', '*');
      const sent = folders.find(f => (f.flags || []).some(fl => String(fl).toLowerCase() === '\\sent'))
        || folders.find(f => SENT_NAMES.includes(String(f.path || '').toLowerCase()) || SENT_NAMES.includes(String(f.name || '').toLowerCase()));
      if (!sent) return false;
      await client.appendMessage(sent.path, raw, ['\\Seen']);
      return true;
    } finally {
      try { await client.logout(); } catch { client.destroy?.(); }
    }
  }
}
