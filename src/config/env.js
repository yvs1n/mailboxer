/**
 * Mailboxer Environment & Credential Engine
 *
 * Implements native Node 22 environment loading (`process.loadEnvFile`),
 * bulletproof fallback line parser, template placeholder detection,
 * secret masking for safe logging and diagnostic reports, and automated account inventory extraction.
 *
 * @module config/env
 */

import fs from 'node:fs';
import path from 'node:path';
import { resolveAccountConfig } from './schema.js';

/**
 * Standard list of known template placeholder values.
 */
export const TEMPLATE_PLACEHOLDERS = Object.freeze([
  'your.account@gmail.com',
  'your-16-char-app-password',
  'your.account@icloud.com',
  'your-16-char-apple-password',
  'your.id@university.edu',
  'your.student.id@university.edu',
  'your_university_app_password',
  'your_custom_password',
  'user@customdomain.com',
  'user@example.com',
  'username@domain.com',
  'xxxx-xxxx-xxxx-xxxx',
  'xxxx xxxx xxxx xxxx',
  'xxxxxxxxxxxxxxxx',
  'your-app-password',
  'your_app_password',
  'your_password',
  'YOUR_PASSWORD_HERE'
]);

/**
 * Regex matching placeholder prefixes and patterns.
 */
const PLACEHOLDER_PREFIX_REGEX = /^(your[._-]|xxxx|changeme|sample|placeholder|todo|YOUR_PASSWORD|<.*>|\.\.\.)/i;
const EXAMPLE_DOMAIN_REGEX = /@example\.(com|org|net)$/i;

/**
 * Checks whether a given string is a template placeholder.
 * Safe for null, undefined, and non-string types (returns false).
 *
 * @param {*} value - Value to check
 * @returns {boolean} True if value is a recognized template placeholder
 */
export function detectPlaceholders(value) {
  if (value === null || value === undefined || typeof value !== 'string') {
    return false;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }

  if (TEMPLATE_PLACEHOLDERS.includes(trimmed)) {
    return true;
  }
  if (PLACEHOLDER_PREFIX_REGEX.test(trimmed)) {
    return true;
  }
  if (EXAMPLE_DOMAIN_REGEX.test(trimmed)) {
    return true;
  }
  if (trimmed.toLowerCase() === 'username@domain.com' || trimmed.toLowerCase() === 'user@customdomain.com') {
    return true;
  }

  return false;
}

/**
 * Helper to check if a value is empty or represents a placeholder.
 *
 * @param {*} value - Value to check
 * @returns {boolean} True if empty or placeholder
 */
export function isPlaceholder(value) {
  if (value === null || value === undefined || typeof value !== 'string') return true;
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  return detectPlaceholders(trimmed);
}

/**
 * Validates whether an account object has both non-empty, non-placeholder email and password.
 *
 * @param {object} account - Account object to test
 * @returns {boolean} True if fully configured with real credentials
 */
export function isAccountConfigured(account) {
  if (!account || typeof account !== 'object') return false;
  const email = account.email;
  const pass = account.password ?? account.auth?.pass;

  if (typeof email !== 'string' || email.trim().length === 0 || detectPlaceholders(email)) {
    return false;
  }
  if (typeof pass !== 'string' || pass.trim().length === 0 || detectPlaceholders(pass)) {
    return false;
  }
  return true;
}

/**
 * Masks a secret string (e.g. password, token) for defensive logging and reporting.
 * - 16-character app passwords format as 'abcd-****-****-mnop'.
 * - Passwords < 5 chars return '***'.
 * - Arbitrary passwords retain first 2 and last 2 characters with middle masked.
 * - Null, undefined, empty return ''.
 *
 * @param {*} secret - Credential string to mask
 * @returns {string} Redacted string
 */
export function maskSecret(secret) {
  if (secret === null || secret === undefined || typeof secret !== 'string') {
    return '';
  }
  const trimmed = secret.trim();
  if (trimmed.length === 0) {
    return '';
  }

  // App-specific password check: 16 alphanumeric characters (excluding spaces/hyphens)
  const cleanAlphanumeric = trimmed.replace(/[\s-]/g, '');
  if (cleanAlphanumeric.length === 16) {
    const prefix = cleanAlphanumeric.slice(0, 4);
    const suffix = cleanAlphanumeric.slice(12, 16);
    return `${prefix}-****-****-${suffix}`;
  }

  // Very short secrets (< 5 characters)
  if (trimmed.length < 5) {
    return '***';
  }

  // Medium and long secrets: keep first 2 and last 2, mask middle with at least 3 '*'
  const prefix = trimmed.slice(0, 2);
  const suffix = trimmed.slice(-2);
  const maskLength = Math.max(3, trimmed.length - 4);
  return `${prefix}${'*'.repeat(maskLength)}${suffix}`;
}

/**
 * Masks an email address for defensive logging (e.g. 'u***r@gmail.com').
 *
 * @param {*} email - Email address to mask
 * @returns {string} Redacted email
 */
export function maskEmail(email) {
  if (!email || typeof email !== 'string') return '';
  const trimmed = email.trim();
  const parts = trimmed.split('@');
  if (parts.length !== 2) return '****';
  const [user, domain] = parts;
  if (!user || user.length === 0) {
    return `***@${domain || '***'}`;
  }
  const safeDomain = domain || '***';
  if (user.length <= 2) {
    return `${user[0]}***@${safeDomain}`;
  }
  return `${user[0]}***${user[user.length - 1]}@${safeDomain}`;
}

/**
 * Standalone parser for .env file contents.
 *
 * @param {string} content - Raw content of .env file
 * @returns {Record<string, string>} Key-value map of parsed variables
 */
export function parseEnvContent(content) {
  const result = {};
  if (!content || typeof content !== 'string') return result;
  const lines = content.split(/\r?\n/);

  for (let rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    let cleanLine = line;
    if (cleanLine.startsWith('export ')) {
      cleanLine = cleanLine.slice(7).trim();
    }

    const eqIdx = cleanLine.indexOf('=');
    if (eqIdx === -1) continue;

    const key = cleanLine.slice(0, eqIdx).trim();
    let val = cleanLine.slice(eqIdx + 1).trim();
    if (!key) continue;

    if (val.startsWith('"')) {
      let endIdx = -1;
      let isEscaped = false;
      for (let i = 1; i < val.length; i++) {
        const char = val[i];
        if (isEscaped) {
          isEscaped = false;
          continue;
        }
        if (char === '\\') {
          isEscaped = true;
          continue;
        }
        if (char === '"') {
          endIdx = i;
          break;
        }
      }

      if (endIdx !== -1) {
        val = val.slice(1, endIdx)
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\t/g, '\t')
          .replace(/\\"/g, '"');
      } else {
        const commentIdx = val.indexOf('#');
        if (commentIdx !== -1) {
          val = val.slice(0, commentIdx).trim();
        }
      }
    } else if (val.startsWith("'")) {
      let endIdx = -1;
      let isEscaped = false;
      for (let i = 1; i < val.length; i++) {
        const char = val[i];
        if (isEscaped) {
          isEscaped = false;
          continue;
        }
        if (char === '\\') {
          isEscaped = true;
          continue;
        }
        if (char === "'") {
          endIdx = i;
          break;
        }
      }

      if (endIdx !== -1) {
        val = val.slice(1, endIdx);
      } else {
        const commentIdx = val.indexOf('#');
        if (commentIdx !== -1) {
          val = val.slice(0, commentIdx).trim();
        }
      }
    } else {
      const commentIdx = val.indexOf('#');
      if (commentIdx !== -1) {
        val = val.slice(0, commentIdx).trim();
      }
    }
    result[key] = val;
  }
  return result;
}

/**
 * Loads environment variables from an env file without throwing on missing file.
 *
 * @param {string} [envPath='.env'] - Relative or absolute path to .env file
 * @param {Object} [options={}] - Options
 * @param {boolean} [options.override=false] - Whether to override existing process.env values
 * @returns {{ loaded: boolean, path: string | null, error?: Error }}
 */
export function loadEnv(envPath = '.env', options = {}) {
  const resolvedPath = path.resolve(process.cwd(), envPath);
  if (!fs.existsSync(resolvedPath)) {
    return { loaded: false, path: null };
  }

  try {
    if (typeof process.loadEnvFile === 'function' && !options.override) {
      process.loadEnvFile(resolvedPath);
      return { loaded: true, path: resolvedPath };
    }
  } catch {
    // If process.loadEnvFile fails, fall through to fallback parser
  }

  try {
    const content = fs.readFileSync(resolvedPath, 'utf8');
    const parsed = parseEnvContent(content);
    for (const [key, val] of Object.entries(parsed)) {
      if (options.override || process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
    return { loaded: true, path: resolvedPath };
  } catch (err) {
    return { loaded: false, path: resolvedPath, error: err };
  }
}

/**
 * Definition of provider env mapping for known providers.
 */
export const PROVIDER_ENV_DEFINITIONS = Object.freeze([
  {
    provider: 'gmail',
    defaultLabel: 'Google Mail',
    enabledKey: 'GMAIL_ENABLED',
    emailKey: 'GMAIL_EMAIL',
    passKey: 'GMAIL_APP_PASSWORD',
    labelKey: 'GMAIL_LABEL',
    imapHostKey: 'GMAIL_IMAP_HOST',
    imapPortKey: 'GMAIL_IMAP_PORT',
    smtpHostKey: 'GMAIL_SMTP_HOST',
    smtpPortKey: 'GMAIL_SMTP_PORT',
    connTimeoutKey: 'GMAIL_CONNECTION_TIMEOUT_MS',
    authTimeoutKey: 'GMAIL_AUTH_TIMEOUT_MS',
    setupAdvice: 'Generate an App Password at https://myaccount.google.com/apppasswords and enable IMAP in Gmail Web Settings. See .env.example.'
  },
  {
    provider: 'apple',
    defaultLabel: 'Apple Mail (iCloud)',
    enabledKey: 'APPLE_ENABLED',
    emailKey: 'APPLE_EMAIL',
    passKey: 'APPLE_APP_PASSWORD',
    labelKey: 'APPLE_LABEL',
    imapHostKey: 'APPLE_IMAP_HOST',
    imapPortKey: 'APPLE_IMAP_PORT',
    smtpHostKey: 'APPLE_SMTP_HOST',
    smtpPortKey: 'APPLE_SMTP_PORT',
    connTimeoutKey: 'APPLE_CONNECTION_TIMEOUT_MS',
    authTimeoutKey: 'APPLE_AUTH_TIMEOUT_MS',
    setupAdvice: 'Generate an App-Specific Password at https://appleid.apple.com (Sign-In and Security > App-Specific Passwords). See .env.example.'
  },
  {
    provider: 'outlook',
    defaultLabel: 'Microsoft Outlook',
    enabledKey: 'OUTLOOK_ENABLED',
    emailKey: 'OUTLOOK_EMAIL',
    passKey: 'OUTLOOK_PASSWORD',
    labelKey: 'OUTLOOK_LABEL',
    imapHostKey: 'OUTLOOK_IMAP_HOST',
    imapPortKey: 'OUTLOOK_IMAP_PORT',
    smtpHostKey: 'OUTLOOK_SMTP_HOST',
    smtpPortKey: 'OUTLOOK_SMTP_PORT',
    connTimeoutKey: 'OUTLOOK_CONNECTION_TIMEOUT_MS',
    authTimeoutKey: 'OUTLOOK_AUTH_TIMEOUT_MS',
    setupAdvice: 'Use your university or personal Outlook credentials, or an App Password from https://account.live.com/proofs/manage/additional. See .env.example.'
  }
]);

/**
 * Scans environment variables and extracts configured accounts and unconfigured reasons.
 *
 * @param {Object} [options={}]
 * @param {string|null} [options.envPath='.env'] - Path to env file to load (if options.env is supplied, envPath is ignored)
 * @param {Record<string, string|undefined>} [options.env] - Custom env dictionary for isolated testing
 * @param {Function} [options.resolveAccount=resolveAccountConfig] - Account resolver
 * @returns {{ accounts: Array<any>, unconfigured: Array<{ provider: string, reason: string, envKeys: string[], message?: string, advice?: string }> }}
 */
export function loadEnvironmentAccounts(options = {}) {
  let env = options.env;

  // Only load from disk if caller did not supply custom env dictionary
  if (!env) {
    const envPath = options.envPath !== undefined ? options.envPath : '.env';
    if (envPath) {
      loadEnv(envPath);
    }
    env = process.env;
  }

  const resolveAccount = options.resolveAccount || resolveAccountConfig;
  const accounts = [];
  const unconfigured = [];

  for (const def of PROVIDER_ENV_DEFINITIONS) {
    const rawEnabled = env[def.enabledKey];
    const normalized = typeof rawEnabled === 'string'
      ? rawEnabled.trim().toLowerCase()
      : (typeof rawEnabled === 'boolean' ? String(rawEnabled) : '');
    const isExplicitlyDisabled = rawEnabled === false || normalized === 'false' || normalized === '0' || normalized === 'no';

    if (isExplicitlyDisabled) {
      // Disabled accounts are excluded from both active accounts and unconfigured diagnostic checklist
      continue;
    }

    const emailRaw = env[def.emailKey];
    const passRaw = env[def.passKey];

    const hasEmail = typeof emailRaw === 'string' && emailRaw.trim().length > 0;
    const hasPass = typeof passRaw === 'string' && passRaw.trim().length > 0;

    // Check missing credentials
    if (!hasEmail || !hasPass) {
      const missingKeys = [];
      if (!hasEmail) missingKeys.push(def.emailKey);
      if (!hasPass) missingKeys.push(def.passKey);

      unconfigured.push({
        provider: def.provider,
        reason: 'MISSING_CREDENTIALS',
        envKeys: missingKeys,
        message: `${def.defaultLabel} missing credentials (${missingKeys.join(', ')})`,
        advice: def.setupAdvice
      });
      continue;
    }

    // Check placeholder credentials
    const emailIsPlaceholder = detectPlaceholders(emailRaw);
    const passIsPlaceholder = detectPlaceholders(passRaw);

    if (emailIsPlaceholder || passIsPlaceholder) {
      const placeholderKeys = [];
      if (emailIsPlaceholder) placeholderKeys.push(def.emailKey);
      if (passIsPlaceholder) placeholderKeys.push(def.passKey);

      unconfigured.push({
        provider: def.provider,
        reason: 'PLACEHOLDER_CREDENTIALS',
        envKeys: placeholderKeys,
        message: `${def.defaultLabel} has placeholder credentials in ${placeholderKeys.join(', ')}`,
        advice: `Replace placeholder values in ${placeholderKeys.join(', ')} with genuine credentials. Refer to .env.example for step-by-step setup instructions.`
      });
      continue;
    }

    // Build raw account input
    const accountInput = {
      provider: def.provider,
      email: emailRaw.trim(),
      password: passRaw.trim(),
      label: env[def.labelKey] || def.defaultLabel
    };

    // Add optional server overrides if present
    const imapHost = env[def.imapHostKey];
    const imapPort = env[def.imapPortKey];
    const connTimeout = env[def.connTimeoutKey];
    const authTimeout = env[def.authTimeoutKey];

    if (imapHost || imapPort || connTimeout || authTimeout) {
      accountInput.imap = {};
      if (imapHost) accountInput.imap.host = imapHost.trim();
      if (imapPort) accountInput.imap.port = Number(imapPort);
      if (connTimeout) accountInput.imap.connectionTimeoutMs = Number(connTimeout);
      if (authTimeout) accountInput.imap.authTimeoutMs = Number(authTimeout);
    }

    const smtpHost = env[def.smtpHostKey];
    const smtpPort = env[def.smtpPortKey];
    if (smtpHost || smtpPort) {
      accountInput.smtp = {};
      if (smtpHost) accountInput.smtp.host = smtpHost.trim();
      if (smtpPort) accountInput.smtp.port = Number(smtpPort);
    }

    try {
      const resolved = typeof resolveAccount === 'function' ? resolveAccount(accountInput) : accountInput;
      accounts.push(resolved);
    } catch (err) {
      unconfigured.push({
        provider: def.provider,
        reason: 'VALIDATION_ERROR',
        envKeys: [def.emailKey, def.passKey],
        message: `Validation failed for ${def.defaultLabel}: ${err.message}`,
        advice: 'Check your configuration parameters against schema requirements.'
      });
    }
  }

  // Handle optional custom provider
  const customEnabledRaw = env.CUSTOM_ENABLED;
  const customNormalized = typeof customEnabledRaw === 'string'
    ? customEnabledRaw.trim().toLowerCase()
    : (typeof customEnabledRaw === 'boolean' ? String(customEnabledRaw) : '');
  const isCustomDisabled = customEnabledRaw === false || customNormalized === 'false' || customNormalized === '0' || customNormalized === 'no';
  const isCustomExplicitlyEnabled = customEnabledRaw === true || customNormalized === 'true' || customNormalized === '1' || customNormalized === 'yes';

  if (!isCustomDisabled && (isCustomExplicitlyEnabled || (env.CUSTOM_EMAIL && !detectPlaceholders(env.CUSTOM_EMAIL)))) {
    const customEmail = env.CUSTOM_EMAIL;
    const customPass = env.CUSTOM_PASSWORD;
    const customHost = env.CUSTOM_IMAP_HOST;

    if (!customEmail || !customPass || !customHost || detectPlaceholders(customEmail) || detectPlaceholders(customPass)) {
      unconfigured.push({
        provider: 'custom',
        reason: (detectPlaceholders(customEmail) || detectPlaceholders(customPass)) ? 'PLACEHOLDER_CREDENTIALS' : 'MISSING_CREDENTIALS',
        envKeys: ['CUSTOM_EMAIL', 'CUSTOM_PASSWORD', 'CUSTOM_IMAP_HOST'].filter((k) => !env[k] || detectPlaceholders(env[k])),
        message: 'Custom mail server is enabled but missing required credentials or host',
        advice: 'Define CUSTOM_EMAIL, CUSTOM_PASSWORD, and CUSTOM_IMAP_HOST in your .env file.'
      });
    } else {
      try {
        const resolvedCustom = typeof resolveAccount === 'function' ? resolveAccount({
          provider: 'custom',
          email: customEmail.trim(),
          password: customPass.trim(),
          label: env.CUSTOM_LABEL || 'Custom Account',
          imap: {
            host: customHost.trim(),
            port: Number(env.CUSTOM_IMAP_PORT) || 993,
            secure: env.CUSTOM_IMAP_SECURE !== 'false'
          },
          smtp: env.CUSTOM_SMTP_HOST ? {
            host: env.CUSTOM_SMTP_HOST.trim(),
            port: Number(env.CUSTOM_SMTP_PORT) || 587,
            secure: env.CUSTOM_SMTP_SECURE === 'true'
          } : undefined
        }) : null;
        if (resolvedCustom) accounts.push(resolvedCustom);
      } catch (err) {
        unconfigured.push({
          provider: 'custom',
          reason: 'VALIDATION_ERROR',
          envKeys: ['CUSTOM_EMAIL', 'CUSTOM_PASSWORD'],
          message: `Validation failed for custom account: ${err.message}`,
          advice: 'Check your custom server parameters against schema requirements.'
        });
      }
    }
  }

  return { accounts, unconfigured };
}

/**
 * Alias for loadEnvironmentAccounts
 */
export const loadConfigFromEnv = loadEnvironmentAccounts;
