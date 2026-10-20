/**
 * Presets Unit Test Suite
 * Validates provider presets accuracy, TLS flags, hostnames, ports, and deep immutability.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROVIDER_PRESETS,
  SUPPORTED_PROVIDERS,
  getPreset,
  isSupportedProvider,
  deepFreeze
} from '../../src/config/presets.js';

describe('Provider Presets (src/config/presets.js)', () => {
  describe('Apple Mail (iCloud) Preset', () => {
    it('defines accurate IMAP settings (imap.mail.me.com:993, SSL/TLS)', () => {
      const apple = PROVIDER_PRESETS.apple;
      assert.ok(apple, 'Apple preset must exist');
      assert.strictEqual(apple.id, 'apple');
      assert.strictEqual(apple.imap.host, 'imap.mail.me.com');
      assert.strictEqual(apple.imap.port, 993);
      assert.strictEqual(apple.imap.secure, true);
    });

    it('defines accurate SMTP settings (smtp.mail.me.com:587, STARTTLS)', () => {
      const apple = PROVIDER_PRESETS.apple;
      assert.strictEqual(apple.smtp.host, 'smtp.mail.me.com');
      assert.strictEqual(apple.smtp.port, 587);
      assert.strictEqual(apple.smtp.secure, false);
    });

    it('specifies app_password as default authentication mode for Apple Mail', () => {
      assert.strictEqual(PROVIDER_PRESETS.apple.defaultAuthType, 'app_password');
    });
  });

  describe('Google Mail (Gmail) Preset', () => {
    it('defines accurate IMAP settings (imap.gmail.com:993, SSL/TLS)', () => {
      const gmail = PROVIDER_PRESETS.gmail;
      assert.ok(gmail, 'Gmail preset must exist');
      assert.strictEqual(gmail.id, 'gmail');
      assert.strictEqual(gmail.imap.host, 'imap.gmail.com');
      assert.strictEqual(gmail.imap.port, 993);
      assert.strictEqual(gmail.imap.secure, true);
    });

    it('defines accurate SMTP settings (smtp.gmail.com:587 or 465)', () => {
      const gmail = PROVIDER_PRESETS.gmail;
      assert.strictEqual(gmail.smtp.host, 'smtp.gmail.com');
      assert.ok([587, 465].includes(gmail.smtp.port), 'Gmail SMTP port must be 587 or 465');
      if (gmail.smtp.port === 465) {
        assert.strictEqual(gmail.smtp.secure, true);
      } else {
        assert.strictEqual(gmail.smtp.secure, false);
      }
    });

    it('specifies app_password as default authentication mode for Gmail', () => {
      assert.strictEqual(PROVIDER_PRESETS.gmail.defaultAuthType, 'app_password');
    });
  });

  describe('Microsoft Outlook / Office 365 Preset', () => {
    it('defines accurate IMAP settings (outlook.office365.com:993, SSL/TLS)', () => {
      const outlook = PROVIDER_PRESETS.outlook;
      assert.ok(outlook, 'Outlook preset must exist');
      assert.strictEqual(outlook.id, 'outlook');
      assert.strictEqual(outlook.imap.host, 'outlook.office365.com');
      assert.strictEqual(outlook.imap.port, 993);
      assert.strictEqual(outlook.imap.secure, true);
    });

    it('defines accurate SMTP settings (smtp.office365.com:587, STARTTLS)', () => {
      const outlook = PROVIDER_PRESETS.outlook;
      assert.strictEqual(outlook.smtp.host, 'smtp.office365.com');
      assert.strictEqual(outlook.smtp.port, 587);
      assert.strictEqual(outlook.smtp.secure, false);
    });

    it('specifies valid authentication mode for Outlook', () => {
      assert.ok(
        ['password', 'app_password'].includes(PROVIDER_PRESETS.outlook.defaultAuthType),
        'Outlook auth type should default to password or app_password'
      );
    });
  });

  describe('Custom Preset', () => {
    it('defines custom provider template with configurable slots', () => {
      const custom = PROVIDER_PRESETS.custom;
      assert.ok(custom, 'Custom preset must exist');
      assert.strictEqual(custom.id, 'custom');
      assert.strictEqual(custom.imap.port, 993);
      assert.strictEqual(custom.imap.secure, true);
    });
  });

  describe('Immutability & Integrity', () => {
    it('freezes root PROVIDER_PRESETS object', () => {
      assert.ok(Object.isFrozen(PROVIDER_PRESETS), 'Root presets must be frozen');
    });

    it('freezes each provider preset object', () => {
      for (const provider of ['apple', 'gmail', 'outlook', 'custom']) {
        assert.ok(
          Object.isFrozen(PROVIDER_PRESETS[provider]),
          `${provider} preset object must be frozen`
        );
      }
    });

    it('deeply freezes nested imap and smtp configurations', () => {
      for (const provider of ['apple', 'gmail', 'outlook']) {
        assert.ok(
          Object.isFrozen(PROVIDER_PRESETS[provider].imap),
          `${provider}.imap must be frozen`
        );
        assert.ok(
          Object.isFrozen(PROVIDER_PRESETS[provider].smtp),
          `${provider}.smtp must be frozen`
        );
      }
    });

    it('throws TypeError when attempting to mutate top-level provider in strict mode', () => {
      assert.throws(
        () => {
          'use strict';
          PROVIDER_PRESETS.apple = null;
        },
        TypeError,
        'Mutating PROVIDER_PRESETS must throw TypeError'
      );
    });

    it('throws TypeError when attempting to mutate nested IMAP properties in strict mode', () => {
      assert.throws(
        () => {
          'use strict';
          PROVIDER_PRESETS.apple.imap.port = 143;
        },
        TypeError,
        'Mutating PROVIDER_PRESETS.apple.imap.port must throw TypeError'
      );
    });

    it('throws TypeError when attempting to add new properties to PROVIDER_PRESETS', () => {
      assert.throws(
        () => {
          'use strict';
          PROVIDER_PRESETS.yahoo = { id: 'yahoo' };
        },
        TypeError,
        'Adding properties to PROVIDER_PRESETS must throw TypeError'
      );
    });

    it('throws TypeError when attempting to delete properties from PROVIDER_PRESETS', () => {
      assert.throws(
        () => {
          'use strict';
          delete PROVIDER_PRESETS.apple;
        },
        TypeError,
        'Deleting properties from PROVIDER_PRESETS must throw TypeError'
      );
    });
  });

  describe('Helper Functions', () => {
    it('SUPPORTED_PROVIDERS contains apple, gmail, outlook, custom', () => {
      assert.deepStrictEqual(SUPPORTED_PROVIDERS, ['apple', 'gmail', 'outlook', 'custom']);
    });

    it('isSupportedProvider returns true for known providers and false for unknown', () => {
      assert.strictEqual(isSupportedProvider('apple'), true);
      assert.strictEqual(isSupportedProvider('gmail'), true);
      assert.strictEqual(isSupportedProvider('outlook'), true);
      assert.strictEqual(isSupportedProvider('custom'), true);
      assert.strictEqual(isSupportedProvider('yahoo'), false);
      assert.strictEqual(isSupportedProvider(''), false);
      assert.strictEqual(isSupportedProvider(null), false);
    });

    it('getPreset retrieves provider configuration case-insensitively', () => {
      const appleUpper = getPreset('APPLE');
      const appleLower = getPreset('apple');
      assert.strictEqual(appleUpper.id, 'apple');
      assert.strictEqual(appleUpper.imap.host, appleLower.imap.host);
    });

    it('getPreset returns undefined for unknown provider', () => {
      assert.strictEqual(getPreset('unknown_provider'), undefined);
      assert.strictEqual(getPreset(null), undefined);
    });

    it('getPreset returns undefined for Object prototype properties (Defect 3 regression)', () => {
      // Prototype property names must return undefined, not Object or prototype functions
      assert.strictEqual(getPreset('constructor'), undefined, 'getPreset("constructor") must be undefined');
      assert.strictEqual(getPreset('__proto__'), undefined, 'getPreset("__proto__") must be undefined');
      assert.strictEqual(getPreset('toString'), undefined, 'getPreset("toString") must be undefined');
      assert.strictEqual(getPreset('valueOf'), undefined, 'getPreset("valueOf") must be undefined');
      assert.strictEqual(getPreset('hasOwnProperty'), undefined, 'getPreset("hasOwnProperty") must be undefined');
      assert.strictEqual(getPreset('isPrototypeOf'), undefined, 'getPreset("isPrototypeOf") must be undefined');
    });

    it('isSupportedProvider returns false for Object prototype property names', () => {
      assert.strictEqual(isSupportedProvider('constructor'), false);
      assert.strictEqual(isSupportedProvider('__proto__'), false);
      assert.strictEqual(isSupportedProvider('toString'), false);
      assert.strictEqual(isSupportedProvider('valueOf'), false);
      assert.strictEqual(isSupportedProvider('hasOwnProperty'), false);
    });

    it('getPreset handles non-string, null, undefined, and symbol types safely', () => {
      assert.strictEqual(getPreset(null), undefined);
      assert.strictEqual(getPreset(undefined), undefined);
      assert.strictEqual(getPreset(123), undefined);
      assert.strictEqual(getPreset({}), undefined);
      assert.strictEqual(getPreset([]), undefined);
    });

    it('preserves deep immutability when object includes Symbol properties', () => {
      const sym = Symbol('test');
      const obj = { normal: 'val', [sym]: { nested: 'symbolVal' } };
      deepFreeze(obj);
      assert.ok(Object.isFrozen(obj));
      assert.ok(Object.isFrozen(obj[sym]));
    });
  });
});
