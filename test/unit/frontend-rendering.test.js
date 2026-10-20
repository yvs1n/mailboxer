/**
 * Unit Tests: Frontend UI Rendering & Escaping (test/unit/frontend-rendering.test.js)
 *
 * Verifies:
 * - escapeHtml utility resilience against null, undefined, primitives, and XSS injection vectors
 * - renderAccounts(accounts) defensive handling of null, undefined, and non-array inputs
 * - Provider badge rendering (Apple Mail, Google Mail, Microsoft Outlook, Custom IMAP)
 * - Safe inbox status unread counters and permanent session indicator
 * - Email Reader Modal (#modal-email-reader) DOM markup integrity in public/index.html
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');

describe('Frontend Rendering & Escaping Unit Tests', () => {
  let appJsContent;
  let indexHtmlContent;
  let escapeHtml;

  before(async () => {
    appJsContent = await fs.readFile(path.join(ROOT_DIR, 'public/app.js'), 'utf8');
    indexHtmlContent = await fs.readFile(path.join(ROOT_DIR, 'public/index.html'), 'utf8');

    // Extract escapeHtml function from public/app.js
    const match = appJsContent.match(/function escapeHtml\([\s\S]*?\n\}/);
    assert.ok(match, 'escapeHtml must be defined in public/app.js');
    const fnDecl = match[0];
    const extractFn = new Function(`${fnDecl}; return escapeHtml;`);
    escapeHtml = extractFn();
  });

  describe('1. escapeHtml Utility Resilience', () => {
    it('returns empty string for null and undefined', () => {
      assert.equal(escapeHtml(null), '');
      assert.equal(escapeHtml(undefined), '');
    });

    it('converts numbers and booleans safely to strings', () => {
      assert.equal(escapeHtml(0), '0');
      assert.equal(escapeHtml(42), '42');
      assert.equal(escapeHtml(-10.5), '-10.5');
      assert.equal(escapeHtml(NaN), 'NaN');
      assert.equal(escapeHtml(true), 'true');
      assert.equal(escapeHtml(false), 'false');
    });

    it('escapes standard HTML special characters (&, <, >, ", \')', () => {
      assert.equal(escapeHtml('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      assert.equal(escapeHtml("Tom & Jerry's"), 'Tom &amp; Jerry&#39;s');
      assert.equal(escapeHtml('"test"'), '&quot;test&quot;');
    });

    it('neutralizes attribute breakout attacks', () => {
      const maliciousId = 'acc" onmouseover="alert(1)" data-hack="';
      const escaped = escapeHtml(maliciousId);
      assert.ok(!escaped.includes('"'));
      assert.ok(escaped.includes('&quot;'));
    });

    it('is bound to window and globalThis in browser and testing environments', () => {
      assert.ok(appJsContent.includes('window.escapeHtml = escapeHtml'));
      assert.ok(appJsContent.includes('globalThis.escapeHtml = escapeHtml'));
    });
  });

  describe('2. renderAccounts Logic and Defensive Rendering', () => {
    // Helper to evaluate renderAccounts in a mock DOM environment
    function createMockAccountsEnvironment() {
      const container = { innerHTML: '' };
      const ctx = {
        accountsContainer: container,
        escapeHtml,
        window: {},
        globalThis: {}
      };

      // Extract renderAccounts function body
      const fnMatch = appJsContent.match(/function renderAccounts\(accounts\) \{([\s\S]*?)\n  \}/);
      assert.ok(fnMatch, 'renderAccounts must be declared in public/app.js');
      const fnBody = fnMatch[1];
      const renderFn = new Function('accounts', 'accountsContainer', 'escapeHtml', `
        ${fnBody}
      `);

      return {
        container,
        render: (accs) => renderFn(accs, container, escapeHtml)
      };
    }

    it('renders empty state when accounts is null, undefined, or empty array', () => {
      const { container, render } = createMockAccountsEnvironment();

      render(null);
      assert.ok(container.innerHTML.includes('No Connected Inboxes Yet'));

      render(undefined);
      assert.ok(container.innerHTML.includes('No Connected Inboxes Yet'));

      render([]);
      assert.ok(container.innerHTML.includes('No Connected Inboxes Yet'));
    });

    it('renders empty state safely when accounts is a non-array object (e.g. error payload)', () => {
      const { container, render } = createMockAccountsEnvironment();

      assert.doesNotThrow(() => {
        render({ error: 'Server unavailable' });
      });
      assert.ok(container.innerHTML.includes('No Connected Inboxes Yet'));
    });

    it('safely skips null or undefined elements within accounts array', () => {
      const { container, render } = createMockAccountsEnvironment();

      assert.doesNotThrow(() => {
        render([null, undefined, { id: 'acc_1', email: 'test@gmail.com', provider: 'gmail' }]);
      });
      assert.ok(container.innerHTML.includes('test@gmail.com'));
    });

    it('renders provider badges for all major providers and custom IMAP', () => {
      const { container, render } = createMockAccountsEnvironment();

      const accounts = [
        { id: 'acc_apple', email: 'user@icloud.com', provider: 'apple' },
        { id: 'acc_gmail', email: 'user@gmail.com', provider: 'gmail' },
        { id: 'acc_outlook', email: 'user@outlook.com', provider: 'outlook' },
        { id: 'acc_custom', email: 'student@university.edu', provider: 'custom' }
      ];

      render(accounts);

      assert.ok(container.innerHTML.includes('Apple Mail'));
      assert.ok(container.innerHTML.includes('Google Mail'));
      assert.ok(container.innerHTML.includes('Microsoft Outlook'));
      assert.ok(container.innerHTML.includes('Custom IMAP'));
      assert.ok(container.innerHTML.includes('avatar-apple'));
      assert.ok(container.innerHTML.includes('avatar-gmail'));
      assert.ok(container.innerHTML.includes('avatar-outlook'));
      assert.ok(container.innerHTML.includes('avatar-custom'));
    });

    it('renders permanent session badge on each account card', () => {
      const { container, render } = createMockAccountsEnvironment();

      render([
        { id: 'acc_1', email: 'one@test.com', provider: 'apple' },
        { id: 'acc_2', email: 'two@test.com', provider: 'gmail' }
      ]);

      const count = (container.innerHTML.match(/🔒 Permanent Session/g) || []).length;
      assert.equal(count, 2);
    });

    it('renders unread message counters safely when inboxStatus is provided', () => {
      const { container, render } = createMockAccountsEnvironment();

      const accounts = [
        {
          id: 'acc_with_status',
          email: 'unread@example.com',
          provider: 'gmail',
          inboxStatus: { totalMessages: 125, unseen: 7 }
        },
        {
          id: 'acc_no_status',
          email: 'empty@example.com',
          provider: 'outlook',
          inboxStatus: null
        }
      ];

      render(accounts);

      assert.ok(container.innerHTML.includes('📥 125 msgs (7 unread)'));
      assert.ok(!container.innerHTML.includes('empty@example.com</span><span>•</span><span style="color:#10b981;">📥'));
    });

    it('escapes error messages and data-id attributes to prevent template injection', () => {
      const { container, render } = createMockAccountsEnvironment();

      const maliciousAccount = {
        id: 'acc" onload="alert(1)"',
        label: '<b>Bold Label</b>',
        email: 'user<xss>@example.com',
        provider: 'custom'
      };

      render([maliciousAccount]);

      assert.ok(!container.innerHTML.includes('<xss>'));
      assert.ok(container.innerHTML.includes('&lt;xss&gt;'));
      assert.ok(!container.innerHTML.includes('<b>Bold Label</b>'));
      assert.ok(container.innerHTML.includes('&lt;b&gt;Bold Label&lt;/b&gt;'));
      assert.ok(container.innerHTML.includes('data-id="acc&quot; onload=&quot;alert(1)&quot;"'));
    });
  });

  describe('3. Email Reader Modal Markup Structure (index.html)', () => {
    it('contains modal-email-reader with hidden backdrop class', () => {
      assert.ok(indexHtmlContent.includes('id="modal-email-reader"'));
      assert.ok(indexHtmlContent.includes('class="modal-backdrop hidden"'));
    });

    it('contains reader-card and header elements', () => {
      assert.ok(indexHtmlContent.includes('class="modal-card reader-card"'));
      assert.ok(indexHtmlContent.includes('class="modal-header reader-header"'));
      assert.ok(indexHtmlContent.includes('id="reader-category-badge"'));
      assert.ok(indexHtmlContent.includes('id="reader-subject"'));
      assert.ok(indexHtmlContent.includes('id="btn-close-reader"'));
    });

    it('contains details grid for sender, recipient, and date', () => {
      assert.ok(indexHtmlContent.includes('class="reader-details-grid"'));
      assert.ok(indexHtmlContent.includes('id="reader-sender"'));
      assert.ok(indexHtmlContent.includes('id="reader-recipient"'));
      assert.ok(indexHtmlContent.includes('id="reader-timestamp"'));
    });

    it('contains read/unread toggle button and body container', () => {
      assert.ok(indexHtmlContent.includes('id="btn-reader-toggle-read"'));
      assert.ok(indexHtmlContent.includes('class="reader-body-container"'));
      assert.ok(indexHtmlContent.includes('id="reader-body-content"'));
    });
  });
});
