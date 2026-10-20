/**
 * Tier 5 Adversarial Challenge Suite: Milestone 3 Smart Anti-Noise Triage Engine
 *
 * Empirical verification & stress testing:
 * 1. Hostile & Adversarial Email Headers (null/undefined headers, circular references, conflicting headers)
 * 2. Homoglyphs & Spoofing Resilience (display name injection, Cyrillic TLDs, subdomains, keyword evasion)
 * 3. User Custom Rules Precedence & Engine Flaws (wildcard regex crash, pattern bypass, action overriding)
 * 4. Edge-Case Emails & Type Hardening (non-string senderEmail crash, non-array flags crash, massive payloads)
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { Classifier, defaultClassifier } from '../../src/triage/classifier.js';
import {
  TRIAGE_CATEGORIES,
  TRIAGE_ACTIONS,
  getHeaderValue,
  matchWildcard,
  evaluateUserRule,
  evaluateCondition,
  PROMOTIONAL_KEYWORDS_REGEX,
  URGENT_KEYWORDS_REGEX,
  ACADEMIC_TITLES_REGEX
} from '../../src/triage/rules.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

describe('Adversarial Challenge: Milestone 3 Triage Engine', () => {

  // ==========================================================================
  // VECTOR 1: Hostile & Adversarial Email Headers
  // ==========================================================================
  describe('Vector 1: Hostile & Adversarial Email Headers', () => {

    it('VERIFIED FIX: getHeaderValue returns null on null and undefined header values', () => {
      const headers = {
        'list-unsubscribe': null,
        'precedence': undefined
      };

      const unsubVal = getHeaderValue(headers, 'list-unsubscribe');
      const precVal = getHeaderValue(headers, 'precedence');

      assert.strictEqual(unsubVal, null, 'getHeaderValue returns null for null header');
      assert.strictEqual(precVal, null, 'getHeaderValue returns null for undefined header');
    });

    it('DEFECT 1 REMEDIATED: message with list-unsubscribe: null is correctly classified as NORMAL', () => {
      const benignEmail = {
        sender: 'Alice Colleague',
        senderEmail: 'alice@company.com',
        subject: 'Quarterly Project Sync',
        bodySnippet: 'Looking forward to our sync tomorrow morning.',
        headers: {
          'list-unsubscribe': null // Parsed header property with null value
        }
      };

      const result = defaultClassifier.classify(benignEmail);

      assert.strictEqual(
        result.category,
        TRIAGE_CATEGORIES.NORMAL,
        'Remediated: list-unsubscribe: null does not cause false positive NOISE'
      );
      assert.strictEqual(result.shouldNotify, false);
      assert.strictEqual(result.isNoise, false);
    });

    it('DEFECT 2 REMEDIATED: circular reference in headers.rawHeaders is handled safely without RangeError', () => {
      const circularHeaders = {};
      circularHeaders.rawHeaders = circularHeaders;

      const email = {
        sender: 'Bob',
        senderEmail: 'bob@example.com',
        subject: 'Hello',
        headers: circularHeaders
      };

      // Must not throw RangeError; cycle detection returns null
      const result = defaultClassifier.classify(email);
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(result.shouldNotify, false);
    });

    it('AUDIT: Conflicting headers - Professor VIP vs List-Unsubscribe (Faculty precedes bulk NOISE)', () => {
      // Academic faculty sending via a university discussion list that includes List-Unsubscribe
      const courseEmail = {
        sender: 'Prof. Robert Sedgewick',
        senderEmail: 'rs@cs.princeton.edu',
        subject: 'URGENT: Midterm Exam Room Change',
        bodySnippet: 'The midterm has been relocated to Hall B.',
        headers: {
          'list-unsubscribe': '<https://lists.princeton.edu/unsub/cs126>'
        }
      };

      const result = defaultClassifier.classify(courseEmail);

      // Educational / faculty senders are not blanket-muted as NOISE, proceeding to VIP
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.VIP);
      assert.strictEqual(result.action, TRIAGE_ACTIONS.NOTIFY);
      assert.strictEqual(result.shouldNotify, true);
      assert.strictEqual(result.isNoise, false);
    });

    it('AUDIT: Conflicting headers - Starred email (isFlagged: true) vs List-Unsubscribe', () => {
      const starredNewsletter = {
        sender: 'Important Digest',
        senderEmail: 'digest@tech.org',
        subject: 'Must-read weekly analysis',
        isFlagged: true,
        headers: {
          'list-unsubscribe': '<https://tech.org/unsub>'
        }
      };

      const result = defaultClassifier.classify(starredNewsletter);

      // In default heuristics, NOISE takes precedence over isFlagged
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.strictEqual(result.shouldNotify, false);
    });

    it('AUDIT: Conflicting headers - X-Priority: 1 vs Precedence: bulk', () => {
      const email = {
        sender: 'Alert Bot',
        senderEmail: 'bot@monitor.com',
        subject: 'Database Server Warning',
        headers: {
          'x-priority': '1',
          'precedence': 'bulk'
        }
      };

      const result = defaultClassifier.classify(email);
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.strictEqual(result.shouldNotify, false);
    });

    it('verifies case-insensitivity of noise headers (LIST-UNSUBSCRIBE, PRECEDENCE: BULK)', () => {
      const email = {
        sender: 'Sales Team',
        senderEmail: 'sales@shop.com',
        subject: 'New arrivals',
        headers: {
          'LIST-UNSUBSCRIBE': '<mailto:unsub@shop.com>',
          'PRECEDENCE': 'BULK'
        }
      };

      const result = defaultClassifier.classify(email);
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.strictEqual(result.isNoise, true);
    });

    it('handles array header representations cleanly', () => {
      const email = {
        sender: 'Boss',
        senderEmail: 'boss@company.com',
        subject: 'Review',
        headers: {
          'x-priority': ['1'] // Array representation
        }
      };

      const result = defaultClassifier.classify(email);
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.VIP);
      assert.strictEqual(result.shouldNotify, true);
    });
  });

  // ==========================================================================
  // VECTOR 2: Homoglyphs and Spoofing Resilience
  // ==========================================================================
  describe('Vector 2: Homoglyphs and Spoofing Resilience', () => {

    it('rejects Cyrillic homoglyphs in educational TLD (.еdu using U+0435)', () => {
      // Cyrillic small letter ie (U+0435) looks identical to ASCII 'e'
      const cyrillicEduEmail = {
        sender: 'Prof. Ivan',
        senderEmail: 'ivan@university.\u0435du', // Cyrillic .еdu
        subject: 'Exam Guidelines',
        bodySnippet: 'Please read the syllabus.'
      };

      const result = defaultClassifier.classify(cyrillicEduEmail);

      // Must NOT be classified as VIP because senderDomain does not end with ASCII '.edu'
      assert.notStrictEqual(result.category, TRIAGE_CATEGORIES.VIP);
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(result.shouldNotify, false);
    });

    it('rejects subdomain spoofing attempting to mimic .edu (.edu.evil.com)', () => {
      const spoofedEmail = {
        sender: 'Prof. Phishing',
        senderEmail: 'phish@stanford.edu.attacker.com',
        subject: 'Urgent: Verify your university credentials',
        bodySnippet: 'Click here to confirm password.'
      };

      const result = defaultClassifier.classify(spoofedEmail);

      // While subject contains "Urgent", sender is NOT academic faculty
      // Wait: subject contains "Urgent", which triggers URGENT_KEYWORDS_REGEX!
      // But let's test without urgent subject:
      const nonUrgentSpoofed = {
        sender: 'Prof. Phishing',
        senderEmail: 'phish@stanford.edu.attacker.com',
        subject: 'University Guidelines Update',
        bodySnippet: 'Click here to review.'
      };

      const res2 = defaultClassifier.classify(nonUrgentSpoofed);
      assert.strictEqual(res2.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(res2.shouldNotify, false);
    });

    it('AUDIT: Display name injection by arbitrary .edu address elevates to VIP on non-coursework subjects', () => {
      // Anyone with any .edu account (e.g. student on an open .edu domain)
      // can spoof the sender display name to "Prof. X" and become VIP if subject lacks coursework tokens
      const studentEmail = {
        sender: 'Prof. Severus Snape',
        senderEmail: 'random-student-99@community-college.edu',
        subject: 'Quick question about the department',
        bodySnippet: 'Hey checkout this link lol'
      };

      const result = defaultClassifier.classify(studentEmail);

      // Built-in rule: isEduDomain && ACADEMIC_TITLES_REGEX.test(sender)
      // Elevates this to VIP!
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.VIP);
      assert.strictEqual(result.shouldNotify, true);
    });

    it('AUDIT: Professor correspondence demoted to UPDATE (silent) if subject contains coursework keywords', () => {
      // When a genuine professor writes about exams, office hours, or homework:
      // Section 3 (Coursework) executes BEFORE Section 4 (Academic VIP),
      // demoting the professor's email from VIP to UPDATE (shouldNotify: false)!
      const profEmail = {
        sender: 'Prof. Robert Sedgewick',
        senderEmail: 'rs@cs.princeton.edu',
        subject: 'Office hours moved to 4pm & Midterm review schedule',
        bodySnippet: 'Please check the updated schedule.'
      };

      const result = defaultClassifier.classify(profEmail);

      assert.strictEqual(result.category, TRIAGE_CATEGORIES.UPDATE);
      assert.strictEqual(result.shouldNotify, false, 'Professor email muted because Coursework precedes VIP');
    });

    it('probes Cyrillic homoglyph evasion in promotional keywords', () => {
      // Cyrillic 'о' (U+043E) in "50% оff"
      const cyrillicPromoEmail = {
        sender: 'Spam Store',
        senderEmail: 'deals@store.com',
        subject: 'Get 50%\u043Eff everything today!',
        bodySnippet: 'Special sale just for you.'
      };

      const result = defaultClassifier.classify(cyrillicPromoEmail);

      // ASCII regex /\b(\d+%\s*(?:off|discount)...)/i does NOT match Cyrillic \u043Eff
      // So promotional evasion succeeds and bypasses noise detection!
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NORMAL);
    });

    it('probes Cyrillic homoglyph evasion in urgent keywords', () => {
      // Cyrillic 'Е' (U+0415) in "URGЕNT"
      const cyrillicUrgentEmail = {
        sender: 'Colleague',
        senderEmail: 'colleague@company.com',
        subject: 'URG\u0415NT: Server status update'
      };

      const result = defaultClassifier.classify(cyrillicUrgentEmail);

      // ASCII regex does not match Cyrillic URGЕNT, falling back to NORMAL
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(result.shouldNotify, false);
    });
  });

  // ==========================================================================
  // VECTOR 3: User Custom Rules vs Default Rules Precedence & Engine Flaws
  // ==========================================================================
  describe('Vector 3: User Custom Rules vs Default Rules Precedence & Engine Flaws', () => {

    it('DEFECT 3 REMEDIATED: matchWildcard handles leading question mark / glob chars safely without throwing SyntaxError', () => {
      // With regex escaping, glob translation, and try/catch guard, matchWildcard never throws SyntaxError
      assert.doesNotThrow(() => matchWildcard('user@test.com', '?admin*'));
      assert.strictEqual(matchWildcard('test', '?est'), true);
      assert.strictEqual(matchWildcard('test', '?abc'), false);

      const rule = {
        name: 'Faulty Rule',
        pattern: '?admin*'
      };

      const email = {
        senderEmail: 'admin@company.com',
        subject: 'Hello'
      };

      // classify() must not throw
      assert.doesNotThrow(() => {
        const res = defaultClassifier.classify(email, { userRules: [rule] });
        assert.ok(res);
      });
    });

    it('DEFECT 4 REMEDIATED: rule.pattern and rule.conditions enforce AND semantics', () => {
      // User creates a rule intended to match from *@boss.com ONLY IF subject contains 'emergency'
      const rule = {
        name: 'Boss Emergency Only',
        pattern: '*@boss.com',
        header: 'from',
        conditions: [
          { field: 'subject', operator: 'contains', value: 'emergency' }
        ],
        category: 'VIP',
        action: 'notify'
      };

      const routineEmail = {
        senderEmail: 'ceo@boss.com',
        subject: 'Have a good weekend everyone' // Does NOT contain 'emergency'
      };

      // Both pattern AND conditions must match
      const matched = evaluateUserRule(rule, routineEmail);
      assert.strictEqual(matched, false, 'rule.conditions must be evaluated when pattern matches');

      const classified = defaultClassifier.classify(routineEmail, { userRules: [rule] });
      assert.strictEqual(classified.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(classified.shouldNotify, false);

      const emergencyEmail = {
        senderEmail: 'ceo@boss.com',
        subject: 'emergency in datacenter'
      };
      assert.strictEqual(evaluateUserRule(rule, emergencyEmail), true);
      const classifiedEmergency = defaultClassifier.classify(emergencyEmail, { userRules: [rule] });
      assert.strictEqual(classifiedEmergency.category, TRIAGE_CATEGORIES.VIP);
      assert.strictEqual(classifiedEmergency.shouldNotify, true);
    });

    it('DEFECT 5 REMEDIATED: user rule with action: "mute" and category: "VIP" respects action (shouldNotify: false)', () => {
      // User classifies a VIP alert feed but explicitly wants notifications MUTED
      const rule = {
        name: 'Muted VIP Feed',
        pattern: '*@vip-feed.com',
        category: 'VIP',
        action: 'mute' // Explicit user intent: MUTE!
      };

      const email = {
        senderEmail: 'alerts@vip-feed.com',
        subject: 'VIP Digest'
      };

      const result = defaultClassifier.classify(email, { userRules: [rule] });

      assert.strictEqual(result.action, 'mute');
      assert.strictEqual(
        result.shouldNotify,
        false,
        'Explicit user action "mute" must suppress notifications'
      );
    });

    it('DEFECT 6 REMEDIATED: account-scoped rule does not fire on messages without matching accountId', () => {
      const scopedRule = {
        name: 'Work Only Rule',
        accountId: 'work_acc_123',
        pattern: '*@partner.com',
        category: 'VIP'
      };

      // Message has NO accountId specified
      const unassignedMessage = {
        senderEmail: 'sales@partner.com',
        subject: 'Pitch'
      };

      const matches = evaluateUserRule(scopedRule, unassignedMessage);
      assert.strictEqual(
        matches,
        false,
        'Account-scoped rule must not match message without accountId'
      );

      // Message with matching accountId matches
      const matchingMessage = {
        accountId: 'work_acc_123',
        senderEmail: 'sales@partner.com',
        subject: 'Pitch'
      };
      assert.strictEqual(evaluateUserRule(scopedRule, matchingMessage), true);
    });

    it('verifies user custom rules override default NOISE heuristics', () => {
      const whitelistRule = {
        name: 'Allowed Newsletter',
        pattern: '*@newsletter.com',
        category: 'VIP',
        action: 'notify'
      };

      const emailWithUnsubscribe = {
        senderEmail: 'daily@newsletter.com',
        subject: 'Tech News',
        headers: {
          'list-unsubscribe': '<https://newsletter.com/unsub>'
        }
      };

      const result = defaultClassifier.classify(emailWithUnsubscribe, { userRules: [whitelistRule] });
      assert.strictEqual(result.category, 'VIP');
      assert.strictEqual(result.shouldNotify, true);
      assert.match(result.matchedRule, /Allowed Newsletter/);
    });

    it('verifies user custom rules override default VIP heuristics', () => {
      const muteProfessorRule = {
        name: 'Mute Old Professor',
        pattern: '*sedgewick@princeton.edu',
        category: 'NOISE',
        action: 'mute'
      };

      const profEmail = {
        sender: 'Prof. Robert Sedgewick',
        senderEmail: 'rsedgewick@princeton.edu',
        subject: 'URGENT: Meeting',
        headers: {
          'x-priority': '1'
        }
      };

      const result = defaultClassifier.classify(profEmail, { userRules: [muteProfessorRule] });
      assert.strictEqual(result.category, 'NOISE');
      assert.strictEqual(result.shouldNotify, false);
      assert.strictEqual(result.isNoise, true);
    });

    it('verifies disabled user rule is skipped completely', () => {
      const disabledRule = {
        name: 'Disabled Rule',
        pattern: '*@company.com',
        category: 'VIP',
        isEnabled: false
      };

      const email = {
        senderEmail: 'user@company.com',
        subject: 'General check-in'
      };

      const result = defaultClassifier.classify(email, { userRules: [disabledRule] });
      assert.strictEqual(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(result.matchedRule, 'SYSTEM_NORMAL');
    });

    it('verifies user rule evaluation with multi-condition AND semantics', () => {
      const rule = {
        name: 'High Value Deal',
        conditions: [
          { field: 'subject', operator: 'contains', value: 'contract' },
          { field: 'body', operator: 'contains', value: 'signed' }
        ],
        category: 'VIP',
        action: 'notify'
      };

      const partialMatch = {
        senderEmail: 'legal@law.com',
        subject: 'Your contract draft',
        bodySnippet: 'Please review and comment.' // Missing 'signed'
      };

      assert.strictEqual(evaluateUserRule(rule, partialMatch), false);

      const fullMatch = {
        senderEmail: 'legal@law.com',
        subject: 'Your contract final',
        bodySnippet: 'Attached is the signed document.'
      };

      assert.strictEqual(evaluateUserRule(rule, fullMatch), true);
    });
  });

  // ==========================================================================
  // VECTOR 4: Edge-Case Emails & Type Hardening
  // ==========================================================================
  describe('Vector 4: Edge-Case Emails & Type Hardening', () => {

    it('DEFECT 7 REMEDIATED: non-string senderEmail is safely coerced without throwing TypeError', () => {
      const hostileEmailNumber = {
        senderEmail: 12345,
        subject: 'Test'
      };

      assert.doesNotThrow(() => {
        const res = defaultClassifier.classify(hostileEmailNumber);
        assert.ok(res);
      });

      const hostileEmailObj = {
        senderEmail: { address: 'admin@test.com' },
        subject: 'Test'
      };

      assert.doesNotThrow(() => {
        const res = defaultClassifier.classify(hostileEmailObj);
        assert.ok(res);
      });
    });

    it('DEFECT 8 REMEDIATED: non-array/non-string flags is safely handled without throwing TypeError', () => {
      const hostileFlagsNumber = {
        sender: 'Bob',
        senderEmail: 'bob@test.com',
        subject: 'Hello',
        flags: 123 // Non-string, non-array
      };

      assert.doesNotThrow(() => {
        const res = defaultClassifier.classify(hostileFlagsNumber);
        assert.ok(res);
      });

      const hostileFlagsBool = {
        sender: 'Bob',
        senderEmail: 'bob@test.com',
        subject: 'Hello',
        flags: true
      };

      assert.doesNotThrow(() => {
        const res = defaultClassifier.classify(hostileFlagsBool);
        assert.ok(res);
      });
    });

    it('handles empty, null, undefined, and non-object message payloads cleanly', () => {
      const nullRes = defaultClassifier.classify(null);
      assert.strictEqual(nullRes.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(nullRes.matchedRule, 'DEFAULT_FALLBACK');

      const undefRes = defaultClassifier.classify(undefined);
      assert.strictEqual(undefRes.category, TRIAGE_CATEGORIES.NORMAL);

      const emptyObjRes = defaultClassifier.classify({});
      assert.strictEqual(emptyObjRes.category, TRIAGE_CATEGORIES.NORMAL);

      const primitiveRes = defaultClassifier.classify('not an object');
      assert.strictEqual(primitiveRes.category, TRIAGE_CATEGORIES.NORMAL);
    });

    it('handles emails with empty strings for all fields without error', () => {
      const emptyEmail = {
        sender: '',
        senderEmail: '',
        subject: '',
        bodySnippet: '',
        headers: {}
      };

      const res = defaultClassifier.classify(emptyEmail);
      assert.strictEqual(res.category, TRIAGE_CATEGORIES.NORMAL);
      assert.strictEqual(res.shouldNotify, false);
      assert.strictEqual(res.isNoise, false);
    });

    it('processes massive bodySnippet (1,000,000 chars) in under 50ms without catastrophic backtracking', () => {
      const massiveBody = 'Important project notes. '.repeat(40000); // 1,000,000 chars
      const email = {
        sender: 'colleague@work.com',
        senderEmail: 'colleague@work.com',
        subject: 'Big project dump',
        bodySnippet: massiveBody
      };

      const start = performance.now();
      const res = defaultClassifier.classify(email);
      const elapsed = performance.now() - start;

      assert.ok(elapsed < 50, `1M body took ${elapsed}ms (expected < 50ms)`);
      assert.strictEqual(res.category, TRIAGE_CATEGORIES.NORMAL);
    });

    it('processes massive subject line (100,000 chars) in under 50ms', () => {
      const massiveSubject = 'Announcement '.repeat(7700); // 100k chars
      const email = {
        sender: 'colleague@work.com',
        senderEmail: 'colleague@work.com',
        subject: massiveSubject
      };

      const start = performance.now();
      const res = defaultClassifier.classify(email);
      const elapsed = performance.now() - start;

      assert.ok(elapsed < 50, `100k subject took ${elapsed}ms (expected < 50ms)`);
      assert.strictEqual(res.category, TRIAGE_CATEGORIES.NORMAL);
    });

    it('handles malformed date fields gracefully', () => {
      const email = {
        sender: 'Colleague',
        senderEmail: 'colleague@work.com',
        subject: 'Meeting',
        date: '9999-99-99T99:99:99Z' // Malformed date
      };

      const res = defaultClassifier.classify(email);
      assert.strictEqual(res.category, TRIAGE_CATEGORIES.NORMAL);
    });
  });
});
