/**
 * In-memory fake of the ImapClient surface the SyncEngine uses.
 * Lets tests script server state (folders, messages, flags) and inspect
 * the commands that were issued, without any socket protocol.
 */

export class FakeImapServerState {
  constructor() {
    /** path -> { flags: string[], messages: Map<uid, {uid, subject, from, date, flags: Set, raw?}> } */
    this.folders = new Map();
    this.commands = [];
    this.capabilities = ['IMAP4rev1', 'MOVE', 'UIDPLUS', 'IDLE'];
    this.failNext = null;
  }

  addFolder(path, flags = []) {
    if (!this.folders.has(path)) this.folders.set(path, { flags, messages: new Map(), uidNext: 1 });
    return this.folders.get(path);
  }

  addMessage(path, msg) {
    const folder = this.addFolder(path);
    const uid = msg.uid ?? folder.uidNext;
    folder.uidNext = Math.max(folder.uidNext, uid + 1);
    folder.messages.set(uid, {
      uid,
      subject: msg.subject || `Message ${uid}`,
      from: msg.from || 'Sender <sender@example.com>',
      date: msg.date || '2026-10-20T10:00:00.000Z',
      flags: new Set(msg.flags || []),
      raw: msg.raw || null
    });
    return uid;
  }

  messages(path) {
    return this.folders.get(path)?.messages || new Map();
  }
}

export class FakeImapClient {
  constructor(state) {
    this.state = state;
    this.selected = null;
    this.isConnected = false;
    this.isAuthenticated = false;
    this.capabilities = state.capabilities;
  }

  _record(cmd) {
    this.state.commands.push(cmd);
    if (this.state.failNext && cmd.startsWith(this.state.failNext.prefix)) {
      const err = this.state.failNext.error;
      this.state.failNext = null;
      throw err;
    }
  }

  hasCapability(name) {
    return this.capabilities.includes(String(name).toUpperCase());
  }

  async connect() { this.isConnected = true; }
  async login() { this.isAuthenticated = true; }
  async logout() { this.isAuthenticated = false; this.isConnected = false; }
  destroy() { this.isAuthenticated = false; this.isConnected = false; }

  async listMailboxes() {
    this._record('LIST');
    return [...this.state.folders.entries()].map(([path, f]) => ({
      path,
      name: path.split('/').pop(),
      delimiter: '/',
      flags: f.flags,
      selectable: true
    }));
  }

  async selectMailbox(path) {
    this._record(`SELECT ${path}`);
    const folder = this.state.folders.get(path);
    if (!folder) throw new Error(`No such mailbox ${path}`);
    this.selected = path;
    return { uidValidity: 1, uidNext: folder.uidNext, exists: folder.messages.size, totalMessages: folder.messages.size, flags: [] };
  }

  async searchUids(criteria) {
    this._record(`SEARCH ${criteria}`);
    const msgs = [...this.state.messages(this.selected).values()];
    let out;
    if (criteria === 'UNSEEN') out = msgs.filter(m => !m.flags.has('\\Seen'));
    else if (criteria === 'FLAGGED') out = msgs.filter(m => m.flags.has('\\Flagged'));
    else if (/^UID (\d+):\*$/.test(criteria)) {
      const min = Number(criteria.match(/^UID (\d+)/)[1]);
      out = msgs.filter(m => m.uid >= min);
      if (out.length === 0 && msgs.length) out = [msgs[msgs.length - 1]]; // RFC 3501 n:* quirk
    } else if (criteria.startsWith('SINCE')) out = msgs.filter(m => new Date(m.date) >= new Date('2025-01-01'));
    else out = msgs;
    return out.map(m => m.uid).sort((a, b) => a - b);
  }

  async fetchMessages(range) {
    this._record(`FETCH ${range}`);
    const uids = String(range).split(',').map(Number);
    const folder = this.state.messages(this.selected);
    return uids.filter(u => folder.has(u)).map((u) => {
      const m = folder.get(u);
      return {
        uid: u,
        subject: m.subject,
        sender: m.from,
        senderEmail: (m.from.match(/<([^>]+)>/) || [])[1] || m.from,
        date: m.date,
        flags: [...m.flags],
        isSeen: m.flags.has('\\Seen'),
        isFlagged: m.flags.has('\\Flagged'),
        bodySnippet: `Body of ${m.subject}`,
        messageId: `<msg-${u}@example.com>`,
        recipients: ['me@example.com']
      };
    });
  }

  async fetchRawMessages(uid) {
    this._record(`FETCHRAW ${uid}`);
    const m = this.state.messages(this.selected).get(Number(uid));
    if (!m) return [];
    const raw = m.raw || `From: ${m.from}\r\nSubject: ${m.subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nFull body of ${m.subject}\r\n`;
    return [{ uid: m.uid, raw: Buffer.from(raw, 'utf8') }];
  }

  async storeFlags(uid, flags, mode) {
    this._record(`STORE ${uid} ${mode} ${flags.join(' ')}`);
    const m = this.state.messages(this.selected).get(Number(uid));
    if (!m) return;
    for (const f of flags) {
      if (mode === '-FLAGS') m.flags.delete(f);
      else m.flags.add(f);
    }
  }

  async moveMessages(uid, dest) {
    this._record(`MOVE ${uid} ${dest}`);
    const src = this.state.messages(this.selected);
    const m = src.get(Number(uid));
    if (!m) return;
    src.delete(Number(uid));
    this.state.addMessage(dest, { ...m, uid: undefined, flags: [...m.flags] });
  }

  async deleteMessages(uid) {
    this._record(`EXPUNGE ${uid}`);
    this.state.messages(this.selected).delete(Number(uid));
  }

  async appendMessage(path, raw) {
    this._record(`APPEND ${path}`);
    this.state.addMessage(path, { subject: 'appended', raw: String(raw) });
  }
}
