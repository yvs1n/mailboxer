/**
 * Mailboxer single-user authentication.
 *
 * - Password login (MAILBOXER_PASSWORD) issues a signed, HttpOnly session cookie.
 * - Optional bearer token (MAILBOXER_API_TOKEN) for scripts and CLI access.
 * - Failed logins are rate limited per client and globally.
 * - Changing the password invalidates every existing session.
 *
 * Modes:
 * - "enabled":  a password is set; requests need a valid session or token.
 * - "disabled": no password and not production; everything is allowed (local dev and tests).
 * - "locked":   no password in production; the API refuses to run until one is set.
 *
 * @module server/auth
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const SESSION_COOKIE = 'mb_session';
const TOKEN_VERSION = 'v1';
const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_PER_CLIENT = 10;
const MAX_FAILS_GLOBAL = 100;

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function safeEqual(a, b) {
  // Hash both sides so lengths always match and timing doesn't leak length.
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      out[name] = part.slice(idx + 1).trim();
    }
  }
  return out;
}

export class AuthGuard {
  /**
   * @param {object} [options]
   * @param {string} [options.password] - Login password (default: MAILBOXER_PASSWORD)
   * @param {string} [options.apiToken] - Bearer token (default: MAILBOXER_API_TOKEN)
   * @param {string} [options.dataDir] - Where the session secret is stored
   * @param {string|Buffer} [options.secret] - Session signing secret (skips the file)
   * @param {boolean} [options.production] - Default: NODE_ENV === 'production'
   * @param {boolean} [options.trustProxy] - Read client IP / protocol from X-Forwarded-* (default: TRUST_PROXY === 'true')
   * @param {number} [options.sessionTtlMs]
   * @param {() => number} [options.now]
   */
  constructor(options = {}) {
    const password = options.password ?? process.env.MAILBOXER_PASSWORD ?? '';
    const apiToken = options.apiToken ?? process.env.MAILBOXER_API_TOKEN ?? '';
    this.password = typeof password === 'string' ? password : '';
    this.apiToken = typeof apiToken === 'string' ? apiToken.trim() : '';
    this.production = options.production ?? process.env.NODE_ENV === 'production';
    this.trustProxy = options.trustProxy ?? process.env.TRUST_PROXY === 'true';
    this.sessionTtlMs = options.sessionTtlMs || DEFAULT_SESSION_TTL_MS;
    this.now = options.now || (() => Date.now());

    // Only touch the disk when sessions will actually be issued.
    const secret = options.secret || (this.password ? this._loadOrCreateSecret(options.dataDir) : crypto.randomBytes(32));
    // Mixing in the password means a password change revokes all sessions.
    this._signingKey = crypto.createHmac('sha256', secret).update(this.password).digest();

    this._fails = new Map();
    this._globalFails = { count: 0, resetAt: 0 };
  }

  /** @returns {'enabled'|'disabled'|'locked'} */
  get mode() {
    if (this.password) return 'enabled';
    return this.production ? 'locked' : 'disabled';
  }

  get required() {
    return this.mode !== 'disabled';
  }

  _loadOrCreateSecret(dataDir) {
    if (!dataDir) return crypto.randomBytes(32);
    const file = path.join(dataDir, '.session-secret');
    try {
      const existing = fs.readFileSync(file);
      if (existing.length >= 32) return existing;
    } catch {}
    const fresh = crypto.randomBytes(32);
    try {
      fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(file, fresh, { mode: 0o600, flag: 'wx' });
      return fresh;
    } catch {
      // Another process may have written it first; prefer that copy.
      try {
        const existing = fs.readFileSync(file);
        if (existing.length >= 32) return existing;
      } catch {}
      return fresh;
    }
  }

  _sign(payload) {
    return crypto.createHmac('sha256', this._signingKey).update(payload).digest('base64url');
  }

  createSessionToken() {
    const expiresAt = this.now() + this.sessionTtlMs;
    const payload = `${TOKEN_VERSION}.${expiresAt}`;
    return `${payload}.${this._sign(payload)}`;
  }

  verifySessionToken(token) {
    if (!token || typeof token !== 'string') return false;
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) return false;
    const expiresAt = Number(parts[1]);
    if (!Number.isFinite(expiresAt) || expiresAt <= this.now()) return false;
    const expected = this._sign(`${parts[0]}.${parts[1]}`);
    return safeEqual(expected, parts[2]);
  }

  /** True when the request may access protected routes. */
  isAuthenticated(req) {
    const mode = this.mode;
    if (mode === 'disabled') return true;
    if (mode === 'locked') return false;

    const authHeader = req.headers.authorization || '';
    if (this.apiToken && authHeader.startsWith('Bearer ')) {
      if (safeEqual(authHeader.slice(7).trim(), this.apiToken)) return true;
    }

    const cookies = parseCookies(req.headers.cookie);
    return this.verifySessionToken(cookies[SESSION_COOKIE]);
  }

  clientKey(req) {
    if (this.trustProxy) {
      const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (forwarded) return forwarded;
    }
    return req.socket?.remoteAddress || 'unknown';
  }

  _isSecureRequest(req) {
    if (req.socket?.encrypted) return true;
    if (this.trustProxy && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') return true;
    return this.production;
  }

  _cookie(req, value, maxAgeSeconds) {
    const parts = [
      `${SESSION_COOKIE}=${value}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAgeSeconds}`
    ];
    if (this._isSecureRequest(req)) parts.push('Secure');
    return parts.join('; ');
  }

  clearCookie(req) {
    return this._cookie(req, '', 0);
  }

  /** Seconds until this client may try again, or 0 if allowed. */
  _retryAfter(key) {
    const now = this.now();
    let wait = 0;
    const entry = this._fails.get(key);
    if (entry && entry.resetAt > now && entry.count >= MAX_FAILS_PER_CLIENT) {
      wait = Math.max(wait, entry.resetAt - now);
    }
    const g = this._globalFails;
    if (g.resetAt > now && g.count >= MAX_FAILS_GLOBAL) {
      wait = Math.max(wait, g.resetAt - now);
    }
    return Math.ceil(wait / 1000);
  }

  _recordFailure(key) {
    const now = this.now();
    const entry = this._fails.get(key);
    if (!entry || entry.resetAt <= now) {
      this._fails.set(key, { count: 1, resetAt: now + FAIL_WINDOW_MS });
    } else {
      entry.count++;
    }
    if (this._globalFails.resetAt <= now) {
      this._globalFails = { count: 1, resetAt: now + FAIL_WINDOW_MS };
    } else {
      this._globalFails.count++;
    }
    // Keep the map from growing without bound.
    if (this._fails.size > 10000) {
      for (const [k, v] of this._fails) {
        if (v.resetAt <= now) this._fails.delete(k);
      }
    }
  }

  /**
   * Checks a login attempt.
   * @returns {{ ok: true, cookie: string } | { ok: false, status: number, code: string, error: string, retryAfter?: number }}
   */
  login(req, password) {
    const mode = this.mode;
    if (mode === 'locked') {
      return { ok: false, status: 503, code: 'AUTH_NOT_CONFIGURED', error: 'Set MAILBOXER_PASSWORD on the server to enable login.' };
    }
    if (mode === 'disabled') {
      return { ok: true, cookie: null };
    }

    const key = this.clientKey(req);
    const retryAfter = this._retryAfter(key);
    if (retryAfter > 0) {
      return { ok: false, status: 429, code: 'TOO_MANY_ATTEMPTS', error: 'Too many failed attempts. Try again later.', retryAfter };
    }

    if (typeof password !== 'string' || !safeEqual(password, this.password)) {
      this._recordFailure(key);
      return { ok: false, status: 401, code: 'INVALID_PASSWORD', error: 'Incorrect password.' };
    }

    this._fails.delete(key);
    const token = this.createSessionToken();
    return { ok: true, cookie: this._cookie(req, token, Math.floor(this.sessionTtlMs / 1000)) };
  }
}

/**
 * Rejects cross-site state-changing requests. Browsers always send Origin on
 * cross-origin POST/DELETE, so a mismatch means another site is calling us.
 */
export function isCrossSiteRequest(req, trustProxy = false) {
  const method = (req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return false;
  const origin = req.headers.origin;
  // No Origin: not a browser cross-site call (curl, scripts, same-origin in old browsers).
  if (!origin) return false;
  // "null" comes from sandboxed frames, file:// pages and some redirects.
  if (origin === 'null') return true;
  let originHost;
  try {
    originHost = new URL(origin).host;
  } catch {
    return true;
  }
  const hosts = [req.headers.host];
  if (trustProxy && req.headers['x-forwarded-host']) {
    hosts.push(String(req.headers['x-forwarded-host']).split(',')[0].trim());
  }
  return !hosts.filter(Boolean).includes(originHost);
}
