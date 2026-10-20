/**
 * Mailboxer Provider Presets & Immutability Engine
 *
 * Defines deeply immutable connection presets for Apple Mail (iCloud), Google Mail (Gmail),
 * Microsoft Outlook / Office 365, and Custom providers.
 *
 * @module config/presets
 */

/**
 * Recursively freezes an object and all nested properties to guarantee deep immutability.
 *
 * @template T
 * @param {T} obj - Target object to freeze
 * @param {WeakSet<object>} [seen=new WeakSet()] - Set tracking visited objects to prevent circular loops
 * @returns {Readonly<T>} Deeply frozen object
 */
export function deepFreeze(obj, seen = new WeakSet()) {
  if (obj === null || typeof obj !== 'object' || seen.has(obj)) {
    return obj;
  }
  seen.add(obj);
  Object.freeze(obj);

  for (const key of Reflect.ownKeys(obj)) {
    const val = obj[key];
    if (val !== null && (typeof val === 'object' || typeof val === 'function') && !Object.isFrozen(val)) {
      deepFreeze(val, seen);
    }
  }

  return obj;
}

/**
 * Immutable connection definitions for supported email providers.
 */
export const PROVIDER_PRESETS = deepFreeze(
  Object.assign(Object.create(null), {
    apple: {
    id: 'apple',
    name: 'Apple Mail (iCloud)',
    authType: 'app_password',
    defaultAuthType: 'app_password',
    imap: {
      host: 'imap.mail.me.com',
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    smtp: {
      host: 'smtp.mail.me.com',
      port: 587,
      secure: false,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    }
  },
  gmail: {
    id: 'gmail',
    name: 'Google Mail',
    authType: 'app_password',
    defaultAuthType: 'app_password',
    imap: {
      host: 'imap.gmail.com',
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    smtp: {
      host: 'smtp.gmail.com',
      port: 587,
      alternativePort: 465,
      secure: false,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    }
  },
  outlook: {
    id: 'outlook',
    name: 'Microsoft Outlook / Office 365',
    authType: 'password',
    defaultAuthType: 'password',
    imap: {
      host: 'outlook.office365.com',
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    smtp: {
      host: 'smtp.office365.com',
      port: 587,
      secure: false,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    }
  },
  custom: {
    id: 'custom',
    name: 'Custom Email Provider',
    authType: 'password',
    defaultAuthType: 'password',
    imap: {
      host: '',
      port: 993,
      secure: true,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    },
    smtp: {
      host: '',
      port: 587,
      secure: false,
      connectionTimeoutMs: 10000,
      authTimeoutMs: 10000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    }
  }
})
);

/**
 * List of supported provider identifiers.
 * @type {ReadonlyArray<string>}
 */
export const SUPPORTED_PROVIDERS = Object.freeze(['apple', 'gmail', 'outlook', 'custom']);

/**
 * Retrieves the preset configuration for a given provider identifier.
 * Performs a case-insensitive lookup.
 *
 * @param {string} provider - Provider identifier ('apple', 'gmail', 'outlook', 'custom')
 * @returns {object|undefined} Frozen preset configuration or undefined if not found
 */
export function getPreset(provider) {
  if (typeof provider !== 'string') return undefined;
  const key = provider.trim().toLowerCase();
  if (!Object.hasOwn(PROVIDER_PRESETS, key)) {
    return undefined;
  }
  return PROVIDER_PRESETS[key] || undefined;
}

/**
 * Checks whether a provider identifier is supported.
 *
 * @param {string} provider - Provider identifier to check
 * @returns {boolean} True if supported, false otherwise
 */
export function isSupportedProvider(provider) {
  if (typeof provider !== 'string') return false;
  const key = provider.trim().toLowerCase();
  if (!key) return false;
  return SUPPORTED_PROVIDERS.includes(key);
}

/**
 * Infers provider type from an email address domain.
 *
 * @param {string} email - Email address
 * @returns {'apple'|'gmail'|'outlook'|'custom'} Inferred provider key
 */
export function inferProviderFromEmail(email) {
  if (typeof email !== 'string') return 'custom';
  const trimmed = email.trim().toLowerCase();
  const atIndex = trimmed.lastIndexOf('@');
  if (atIndex === -1) return 'custom';

  const domain = trimmed.slice(atIndex + 1);

  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    return 'gmail';
  }
  if (domain === 'icloud.com' || domain === 'me.com' || domain === 'mac.com') {
    return 'apple';
  }
  if (
    domain === 'outlook.com' ||
    domain === 'hotmail.com' ||
    domain === 'live.com' ||
    domain === 'office365.com' ||
    domain.endsWith('.edu') ||
    domain.endsWith('.ac.uk')
  ) {
    return 'outlook';
  }

  return 'custom';
}
