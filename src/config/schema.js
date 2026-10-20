/**
 * Mailboxer Account Configuration Schema Validator & Resolution Engine
 *
 * Strict, zero-dependency schema validation for multi-provider mail configurations.
 * Enforces RFC 5322 email formatting, port ranges (1-65535), TLS options,
 * and app-password sanitization.
 *
 * @module config/schema
 */

import {
  PROVIDER_PRESETS,
  getPreset,
  inferProviderFromEmail,
  isSupportedProvider,
  deepFreeze
} from './presets.js';

/**
 * Standard configuration schema validation error class.
 */
export class ValidationError extends Error {
  /**
   * @param {string} message - Summary error message
   * @param {Array<{field: string, message: string, received: *}>} [errors=[]] - Detailed list of validation failures
   * @param {string} [code='CONFIG_SCHEMA_INVALID'] - Error taxonomy code
   */
  constructor(message, errors = [], code = 'CONFIG_SCHEMA_INVALID') {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
    this.errors = errors;
  }
}

/**
 * Alias for ValidationError to support both naming conventions across taxonomy.
 */
export const ConfigurationError = ValidationError;

/**
 * Validates an email address against RFC 5322 standards.
 *
 * @param {*} email - Value to validate
 * @returns {boolean} True if email is valid RFC 5322
 */
export function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;

  // Single @ character
  const atIndex = trimmed.indexOf('@');
  if (atIndex === -1 || atIndex !== trimmed.lastIndexOf('@')) return false;

  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);

  if (!local || !domain) return false;
  if (local.length > 64 || domain.length > 253) return false;

  // No consecutive dots or leading/trailing dots in local or domain
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return false;

  // RFC 5322 compliant regex for local@domain
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!emailRegex.test(trimmed)) return false;

  const domainParts = domain.split('.');
  if (domainParts.length < 2) return false;

  for (const part of domainParts) {
    if (part.length === 0 || part.length > 63 || part.startsWith('-') || part.endsWith('-')) {
      return false;
    }
  }

  const tld = domainParts[domainParts.length - 1];
  if (tld.length < 2 || !/^[a-zA-Z]{2,}$/.test(tld)) return false;

  return true;
}

/**
 * Validates a TCP port number.
 *
 * @param {*} port - Value to validate
 * @returns {boolean} True if port is an integer between 1 and 65535
 */
export function isValidPort(port) {
  if (typeof port !== 'number') return false;
  if (!Number.isInteger(port)) return false;
  return port >= 1 && port <= 65535;
}

/**
 * Validates a server hostname or IP address.
 *
 * @param {*} host - Value to validate
 * @returns {boolean} True if host is a valid hostname or IP
 */
export function isValidHostname(host) {
  if (typeof host !== 'string') return false;
  if (host !== host.trim()) return false;
  if (/[\s\r\n\t]/.test(host)) return false;
  if (host.length === 0 || host.length > 253) return false;
  if (host.includes('/') || host.includes(':')) return false;

  if (host === 'localhost') return true;

  // IPv4 check
  const ipv4Regex = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(host)) return true;

  // Hostname regex (RFC 1123 compliant)
  const hostRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return hostRegex.test(host);
}

/**
 * Normalizes app-specific passwords by stripping whitespace and hyphens.
 * Safe for null, undefined, and non-string inputs (returns empty string).
 * Standard passwords without spaces or hyphens are preserved intact.
 *
 * @param {*} secret - Raw secret input
 * @returns {string} Normalized secret
 */
export function normalizeSecret(secret) {
  if (secret === null || secret === undefined || typeof secret !== 'string') {
    return '';
  }
  return secret.trim().replace(/[-\s]/g, '');
}

/**
 * Alias for normalizeSecret
 */
export const normalizeAppPassword = normalizeSecret;

/**
 * Validates a single MailServerConfig object (IMAP or SMTP).
 *
 * @param {object} serverConfig - Server configuration object
 * @param {string} [prefix='server'] - Property name prefix for error messages ('imap' or 'smtp')
 * @returns {Array<{field: string, message: string, received: *}>} List of validation errors
 */
export function validateServerConfig(serverConfig, prefix = 'server') {
  const errors = [];

  if (!serverConfig || typeof serverConfig !== 'object' || Array.isArray(serverConfig)) {
    return [{ field: prefix, message: `${prefix} configuration must be an object`, received: serverConfig }];
  }

  // Host
  if (!isValidHostname(serverConfig.host)) {
    errors.push({
      field: `${prefix}.host`,
      message: `${prefix}.host is required and must be a valid hostname or IP address`,
      received: serverConfig.host
    });
  }

  // Port
  if (!isValidPort(serverConfig.port)) {
    errors.push({
      field: `${prefix}.port`,
      message: `${prefix}.port must be an integer between 1 and 65535`,
      received: serverConfig.port
    });
  }

  // Secure
  if (typeof serverConfig.secure !== 'boolean') {
    errors.push({
      field: `${prefix}.secure`,
      message: `${prefix}.secure must be a boolean`,
      received: serverConfig.secure
    });
  }

  // Timeouts (optional)
  if (serverConfig.connectionTimeoutMs !== undefined) {
    if (
      typeof serverConfig.connectionTimeoutMs !== 'number' ||
      !Number.isInteger(serverConfig.connectionTimeoutMs) ||
      serverConfig.connectionTimeoutMs < 500 ||
      serverConfig.connectionTimeoutMs > 300000
    ) {
      errors.push({
        field: `${prefix}.connectionTimeoutMs`,
        message: `${prefix}.connectionTimeoutMs must be an integer between 500 and 300000 ms`,
        received: serverConfig.connectionTimeoutMs
      });
    }
  }

  if (serverConfig.authTimeoutMs !== undefined) {
    if (
      typeof serverConfig.authTimeoutMs !== 'number' ||
      !Number.isInteger(serverConfig.authTimeoutMs) ||
      serverConfig.authTimeoutMs < 500 ||
      serverConfig.authTimeoutMs > 300000
    ) {
      errors.push({
        field: `${prefix}.authTimeoutMs`,
        message: `${prefix}.authTimeoutMs must be an integer between 500 and 300000 ms`,
        received: serverConfig.authTimeoutMs
      });
    }
  }

  // TLS Options (optional)
  if (serverConfig.tls !== undefined) {
    if (typeof serverConfig.tls !== 'object' || serverConfig.tls === null || Array.isArray(serverConfig.tls)) {
      errors.push({
        field: `${prefix}.tls`,
        message: `${prefix}.tls options must be an object`,
        received: serverConfig.tls
      });
    } else {
      if (serverConfig.tls.rejectUnauthorized !== undefined && typeof serverConfig.tls.rejectUnauthorized !== 'boolean') {
        errors.push({
          field: `${prefix}.tls.rejectUnauthorized`,
          message: `${prefix}.tls.rejectUnauthorized must be a boolean`,
          received: serverConfig.tls.rejectUnauthorized
        });
      }

      if (serverConfig.tls.minVersion !== undefined) {
        if (!['TLSv1.2', 'TLSv1.3'].includes(serverConfig.tls.minVersion)) {
          errors.push({
            field: `${prefix}.tls.minVersion`,
            message: `${prefix}.tls.minVersion must be 'TLSv1.2' or 'TLSv1.3'`,
            received: serverConfig.tls.minVersion
          });
        }
      }

      if (serverConfig.tls.servername !== undefined) {
        if (!isValidHostname(serverConfig.tls.servername)) {
          errors.push({
            field: `${prefix}.tls.servername`,
            message: `${prefix}.tls.servername must be a valid hostname`,
            received: serverConfig.tls.servername
          });
        }
      }
    }
  }

  return errors;
}

/**
 * Validates an account configuration object and collects all errors.
 *
 * @param {object} config - Full account configuration object
 * @returns {Array<{field: string, message: string, received: *}>} List of validation errors
 */
export function collectAccountConfigErrors(config) {
  const errors = [];

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return [{ field: 'account', message: 'Account configuration must be an object', received: config }];
  }

  // ID
  if (typeof config.id !== 'string' || config.id.trim().length === 0) {
    errors.push({ field: 'id', message: 'Account id is required and must be a non-empty string', received: config.id });
  }

  // Label
  if (config.label !== undefined && (typeof config.label !== 'string' || config.label.trim().length === 0)) {
    errors.push({ field: 'label', message: 'Account label must be a non-empty string', received: config.label });
  }

  // Provider
  if (!isSupportedProvider(config.provider)) {
    errors.push({
      field: 'provider',
      message: `Provider must be one of: ${['apple', 'gmail', 'outlook', 'custom'].join(', ')}`,
      received: config.provider
    });
  }

  // Email
  if (!isValidEmail(config.email)) {
    errors.push({ field: 'email', message: 'Email must be a valid RFC 5322 email address', received: config.email });
  }

  // Enabled (optional)
  if (config.enabled !== undefined && typeof config.enabled !== 'boolean') {
    errors.push({ field: 'enabled', message: 'Enabled flag must be a boolean', received: config.enabled });
  }

  // Auth
  if (!config.auth || typeof config.auth !== 'object' || Array.isArray(config.auth)) {
    errors.push({ field: 'auth', message: 'Auth configuration must be an object', received: config.auth });
  } else {
    const validAuthTypes = ['password', 'app_password', 'oauth2'];
    if (!validAuthTypes.includes(config.auth.type)) {
      errors.push({
        field: 'auth.type',
        message: `Auth type must be one of: ${validAuthTypes.join(', ')}`,
        received: config.auth.type
      });
    }

    if (typeof config.auth.user !== 'string' || config.auth.user.trim().length === 0) {
      errors.push({ field: 'auth.user', message: 'Auth user is required and must be a non-empty string', received: config.auth.user });
    }

    if (config.auth.type === 'password' || config.auth.type === 'app_password') {
      if (typeof config.auth.pass !== 'string' || config.auth.pass.trim().length === 0) {
        errors.push({
          field: 'auth.pass',
          message: `Password is required when auth type is ${config.auth.type}`,
          received: config.auth.pass ? '[MASKED]' : config.auth.pass
        });
      }
    }

    if (config.auth.type === 'oauth2') {
      if (typeof config.auth.accessToken !== 'string' || config.auth.accessToken.trim().length === 0) {
        errors.push({
          field: 'auth.accessToken',
          message: 'Access token is required when auth type is oauth2',
          received: config.auth.accessToken ? '[MASKED]' : config.auth.accessToken
        });
      }
    }
  }

  // IMAP Server
  errors.push(...validateServerConfig(config.imap, 'imap'));

  // SMTP Server (optional)
  if (config.smtp !== undefined) {
    errors.push(...validateServerConfig(config.smtp, 'smtp'));
  }

  return errors;
}

/**
 * Validates an account configuration object and throws ValidationError on failure.
 *
 * @param {object} config - Configuration object to validate
 * @returns {object} Validated configuration object
 * @throws {ValidationError} If configuration fails validation
 */
export function validateAccountConfig(config) {
  const errors = collectAccountConfigErrors(config);
  if (errors.length > 0) {
    const errorDetails = errors.map((e) => `  - [${e.field}]: ${e.message}`).join('\n');
    throw new ValidationError(`Account configuration validation failed:\n${errorDetails}`, errors);
  }
  return config;
}

/**
 * Non-throwing safe validation function returning structured success/failure result.
 *
 * @param {object} config - Configuration object to validate
 * @returns {{success: boolean, data?: object, errors?: Array<{field: string, message: string, received: *}>, message?: string}}
 */
export function safeValidateAccountConfig(config) {
  const errors = collectAccountConfigErrors(config);
  if (errors.length > 0) {
    const errorDetails = errors.map((e) => `  - [${e.field}]: ${e.message}`).join('\n');
    return {
      success: false,
      errors,
      message: `Account configuration validation failed:\n${errorDetails}`
    };
  }
  return { success: true, data: config };
}

/**
 * Resolves raw or partial user account inputs by merging with provider presets,
 * sanitizing credentials, and applying strict validation.
 *
 * @param {object} raw - Raw input object (e.g. from environment or user options)
 * @returns {object} Fully populated, validated, and deeply frozen AccountConfig
 * @throws {ValidationError} If resolution or validation fails
 */
export function resolveAccountConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ValidationError('Account input must be an object', [
      { field: 'raw', message: 'Input must be an object', received: raw }
    ]);
  }

  // Infer provider if not explicitly given
  const provider = raw.provider || inferProviderFromEmail(raw.email);

  if (provider === 'custom' && (!raw.imap || !raw.imap.host || !raw.imap.host.trim())) {
    throw new ValidationError('Custom provider requires explicit IMAP host', [
      { field: 'imap.host', message: 'Custom provider requires an explicit IMAP host', received: raw.imap?.host }
    ]);
  }

  const preset = getPreset(provider);

  if (!preset && provider !== 'custom') {
    throw new ValidationError(`Unsupported provider: "${provider}"`, [
      { field: 'provider', message: `Unsupported provider: "${provider}"`, received: provider }
    ]);
  }

  const email = typeof raw.email === 'string' ? raw.email.trim() : '';
  const authType = raw.auth?.type || (provider === 'apple' || provider === 'gmail' ? 'app_password' : 'password');

  // Sanitize password if app_password or if spaces/hyphens present
  let rawPass = raw.auth?.pass ?? raw.password;
  if (typeof rawPass === 'string') {
    if (authType === 'app_password' || provider === 'apple' || provider === 'gmail') {
      rawPass = normalizeSecret(rawPass);
    }
  }

  // Build resolved IMAP configuration
  const rawImapHost = typeof raw.imap?.host === 'string' ? raw.imap.host.trim() : '';
  const presetImapHost = typeof preset?.imap?.host === 'string' ? preset.imap.host.trim() : '';
  const effectiveImapHost = rawImapHost || presetImapHost;

  const rawImapServername =
    typeof raw.imap?.tls?.servername === 'string' ? raw.imap.tls.servername.trim() : raw.imap?.tls?.servername;

  const imapConfig = {
    host: effectiveImapHost,
    port: raw.imap?.port ?? preset?.imap?.port ?? 993,
    secure: raw.imap?.secure ?? preset?.imap?.secure ?? true,
    connectionTimeoutMs: raw.imap?.connectionTimeoutMs ?? preset?.imap?.connectionTimeoutMs ?? 10000,
    authTimeoutMs: raw.imap?.authTimeoutMs ?? preset?.imap?.authTimeoutMs ?? 10000,
    tls: {
      rejectUnauthorized: raw.imap?.tls?.rejectUnauthorized ?? preset?.imap?.tls?.rejectUnauthorized ?? true,
      minVersion: raw.imap?.tls?.minVersion ?? preset?.imap?.tls?.minVersion ?? 'TLSv1.2',
      ...(rawImapServername
        ? { servername: rawImapServername }
        : effectiveImapHost
          ? { servername: effectiveImapHost }
          : {})
    }
  };

  // Build resolved SMTP configuration if preset has a valid host or user explicitly supplied smtp
  let smtpConfig;
  const isSmtpExplicitlyDisabled = raw.smtp === false || raw.smtp === null;
  const hasRawSmtp = Boolean(raw.smtp && typeof raw.smtp === 'object');
  const presetSmtpHost = typeof preset?.smtp?.host === 'string' ? preset.smtp.host.trim() : '';
  const hasPresetSmtpHost = presetSmtpHost.length > 0;

  if (!isSmtpExplicitlyDisabled && (hasRawSmtp || hasPresetSmtpHost)) {
    const rawSmtpHost = typeof raw.smtp?.host === 'string' ? raw.smtp.host.trim() : '';
    const effectiveSmtpHost = rawSmtpHost || presetSmtpHost;

    const rawSmtpServername =
      typeof raw.smtp?.tls?.servername === 'string' ? raw.smtp.tls.servername.trim() : raw.smtp?.tls?.servername;

    smtpConfig = {
      host: effectiveSmtpHost,
      port: raw.smtp?.port ?? preset?.smtp?.port ?? 587,
      secure: raw.smtp?.secure ?? preset?.smtp?.secure ?? false,
      connectionTimeoutMs: raw.smtp?.connectionTimeoutMs ?? preset?.smtp?.connectionTimeoutMs ?? 10000,
      authTimeoutMs: raw.smtp?.authTimeoutMs ?? preset?.smtp?.authTimeoutMs ?? 10000,
      tls: {
        rejectUnauthorized: raw.smtp?.tls?.rejectUnauthorized ?? preset?.smtp?.tls?.rejectUnauthorized ?? true,
        minVersion: raw.smtp?.tls?.minVersion ?? preset?.smtp?.tls?.minVersion ?? 'TLSv1.2',
        ...(rawSmtpServername
          ? { servername: rawSmtpServername }
          : effectiveSmtpHost
            ? { servername: effectiveSmtpHost }
            : {})
      }
    };
  }

  // Derive ID and Label
  const localSlug = email.includes('@')
    ? email.split('@')[0].replace(/[^a-z0-9_-]/gi, '_').toLowerCase()
    : 'default';
  const id = typeof raw.id === 'string' && raw.id.trim().length > 0 ? raw.id.trim() : `${provider}-${localSlug}`;
  const label =
    typeof raw.label === 'string' && raw.label.trim().length > 0
      ? raw.label.trim()
      : `${preset?.name || 'Custom'} (${email || 'unconfigured'})`;

  let enabled = true;
  if (raw.enabled !== undefined) {
    if (typeof raw.enabled === 'boolean') {
      enabled = raw.enabled;
    } else if (typeof raw.enabled === 'string') {
      const lower = raw.enabled.trim().toLowerCase();
      if (['false', '0', 'no', 'off', 'disabled'].includes(lower)) {
        enabled = false;
      } else if (['true', '1', 'yes', 'on', 'enabled'].includes(lower)) {
        enabled = true;
      } else {
        enabled = raw.enabled; // invalid string: let validateAccountConfig throw ValidationError
      }
    } else if (raw.enabled === 0) {
      enabled = false;
    } else if (raw.enabled === 1) {
      enabled = true;
    } else {
      enabled = raw.enabled; // invalid type (null, object, etc.): let validateAccountConfig throw ValidationError
    }
  }

  const candidate = {
    id,
    label,
    provider,
    email,
    enabled,
    auth: {
      type: authType,
      user: raw.auth?.user || email,
      ...(rawPass !== undefined ? { pass: rawPass } : {}),
      ...(raw.auth?.accessToken ? { accessToken: raw.auth.accessToken } : raw.accessToken ? { accessToken: raw.accessToken } : {})
    },
    imap: imapConfig,
    ...(smtpConfig ? { smtp: smtpConfig } : {})
  };

  // Validate and deeply freeze result
  validateAccountConfig(candidate);
  return deepFreeze(candidate);
}
