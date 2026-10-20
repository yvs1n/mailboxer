/**
 * Anti-Noise Email Triage & Rules Unit Test Suite
 *
 * Verifies classification accuracy across VIP / Urgent, Coursework / LMS Updates,
 * Promotional Newsletters / Noise, Custom SQLite User Rules Precedence, and SqliteStore metadata integration.
 *
 * Zero-dependency native Node.js 22 test runner.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Classifier } from '../../src/triage/classifier.js';
import {
  TRIAGE_CATEGORIES,
  TRIAGE_ACTIONS,
  evaluateUserRule,
  evaluateCondition,
  matchWildcard,
  getHeaderValue,
  ACADEMIC_TITLES_REGEX
} from '../../src/triage/rules.js';
import { SqliteStore } from '../../src/storage/sqlite-store.js';

describe('Smart Anti-Noise Triage Classifier (src/triage/classifier.js)', () => {
  let classifier;
  let store;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
    classifier = new Classifier({ store });
  });

  afterEach(() => {
    store?.close();
  });

  describe('1. VIP & Urgent Email Classification', () => {
    it('classifies academic instructor / professor from .edu as VIP with instant notification', () => {
      const email = {
        sender: 'Prof. Robert Sedgewick',
        senderEmail: 'rs@cs.princeton.edu',
        subject: 'Algorithms Lecture Notes & Clarifications',
        bodySnippet: 'Please review the lecture notes on graph traversal before our next class.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(result.action, TRIAGE_ACTIONS.NOTIFY);
      assert.equal(result.shouldNotify, true);
      assert.equal(result.isNoise, false);
      assert.ok(result.score >= 90, `Expected score >= 90, got ${result.score}`);
      assert.match(result.reason, /professor|instructor|faculty/i);
    });

    it('classifies academic Dr. from .ac.uk as VIP', () => {
      const email = {
        sender: 'Dr. Jane Watson',
        senderEmail: 'j.watson@oxford.ac.uk',
        subject: 'Thesis Committee Review Meeting',
        bodySnippet: 'We have reviewed your latest draft and would like to meet.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(result.shouldNotify, true);
    });

    it('classifies flagged / starred emails as VIP regardless of sender', () => {
      const email = {
        sender: 'Colleague Bob',
        senderEmail: 'bob@example.com',
        subject: 'Lunch next week?',
        isFlagged: true
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(result.shouldNotify, true);
      assert.match(result.reason, /flagged|starred/i);
    });

    it('classifies emails with X-Priority: 1 as VIP', () => {
      const email = {
        sender: 'Security Alert',
        senderEmail: 'security@company.com',
        subject: 'Access credential expiration',
        headers: {
          'x-priority': '1'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(result.shouldNotify, true);
      assert.match(result.reason, /high priority/i);
    });

    it('classifies emails with Importance: High as VIP', () => {
      const email = {
        sender: 'Executive Officer',
        senderEmail: 'exec@company.com',
        subject: 'Quarterly review',
        headers: {
          importance: 'High'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(result.shouldNotify, true);
    });

    it('classifies urgent subject keywords (ASAP, URGENT, DEADLINE, EMERGENCY) as VIP', () => {
      const urgentSubjects = [
        'URGENT: Server outage in production',
        'Please review ASAP: Client contract',
        'Action Required: Final Notice regarding enrollment',
        'Emergency: Campus facility closure',
        'Exam room change for CS101 final',
        'Class cancelled today due to weather'
      ];

      for (const subj of urgentSubjects) {
        const res = classifier.classify({
          sender: 'Campus Staff',
          senderEmail: 'staff@university.edu',
          subject: subj
        });
        assert.equal(res.category, TRIAGE_CATEGORIES.VIP, `Expected VIP for subject: ${subj}`);
        assert.equal(res.shouldNotify, true);
      }
    });
  });

  describe('2. Coursework & Educational LMS Updates Classification', () => {
    it('classifies Canvas / Instructure notifications as UPDATE with silent badging', () => {
      const email = {
        sender: 'Canvas Notifications',
        senderEmail: 'notifications@instructure.com',
        subject: '[CS61A] Grade Posted for Homework 4',
        bodySnippet: 'A new grade has been posted for your recent submission.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.UPDATE);
      assert.equal(result.action, TRIAGE_ACTIONS.BADGE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isDigest, true);
      assert.equal(result.isNoise, false);
      assert.ok(result.score >= 50 && result.score <= 70, `Expected score 50-70, got ${result.score}`);
    });

    it('classifies Blackboard notifications as UPDATE', () => {
      const email = {
        sender: 'Blackboard Learn',
        senderEmail: 'do-not-reply@blackboard.com',
        subject: 'New announcement in MATH 201',
        bodySnippet: 'The syllabus for next week has been uploaded.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.UPDATE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isDigest, true);
    });

    it('classifies Gradescope and Piazza notifications as UPDATE', () => {
      const email1 = {
        sender: 'Gradescope',
        senderEmail: 'no-reply@gradescope.com',
        subject: 'Midterm 1 Submissions Graded',
        bodySnippet: 'Your regrade request period is open until Friday.'
      };
      assert.equal(classifier.classify(email1).category, TRIAGE_CATEGORIES.UPDATE);

      const email2 = {
        sender: 'Piazza Team',
        senderEmail: 'updates@piazza.com',
        subject: 'New question posted on CS 189',
        bodySnippet: 'An instructor answered the question on regression.'
      };
      assert.equal(classifier.classify(email2).category, TRIAGE_CATEGORIES.UPDATE);
    });

    it('classifies university administrative bulletins and registrar notices as UPDATE', () => {
      const email = {
        sender: 'Office of the Registrar',
        senderEmail: 'registrar@stanford.edu',
        subject: 'Spring Semester Registration Window Schedule',
        bodySnippet: 'Please find the schedule for registration windows below.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.UPDATE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isDigest, true);
    });
  });

  describe('3. Promotional Newsletters & Noise Detection', () => {
    it('detects marketing emails with List-Unsubscribe header and mutes them', () => {
      const email = {
        sender: 'Retail Deals',
        senderEmail: 'deals@retailshop.com',
        subject: 'Huge Savings This Weekend Only!',
        headers: {
          'list-unsubscribe': '<https://retailshop.com/unsub?id=123>, <mailto:unsub@retailshop.com>'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(result.action, TRIAGE_ACTIONS.MUTE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isNoise, true);
      assert.ok(result.score <= 30, `Expected score <= 30, got ${result.score}`);
      assert.match(result.reason, /list-unsubscribe/i);
    });

    it('detects Precedence: bulk or list and mutes them', () => {
      const email = {
        sender: 'Community Weekly',
        senderEmail: 'news@community.org',
        subject: 'Weekly Community Newsletter #42',
        headers: {
          precedence: 'bulk'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isNoise, true);
    });

    it('detects Auto-Submitted headers as automated noise', () => {
      const email = {
        sender: 'System Bot',
        senderEmail: 'noreply@ci-system.net',
        subject: 'Daily build artifact digest',
        headers: {
          'auto-submitted': 'auto-generated'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(result.isNoise, true);
    });

    it('detects promotional keywords (discount, % off, promo code, free shipping)', () => {
      const email = {
        sender: 'Online Store',
        senderEmail: 'info@store.com',
        subject: 'Get 50% off everything with coupon code FLASH50!',
        bodySnippet: 'Limited time offer! Free shipping on all orders over $25.'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isNoise, true);
    });

    it('prioritizes noise detection over generic urgent tokens in commercial blasts', () => {
      // Commercial blasts often use "URGENT SALE ENDS TODAY"
      const email = {
        sender: 'Marketing Blaster',
        senderEmail: 'promos@store.com',
        subject: 'URGENT: Flash sale ends today with 40% discount!',
        headers: {
          'list-unsubscribe': '<https://store.com/unsub>'
        }
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(result.shouldNotify, false);
    });
  });

  describe('4. Standard / Normal Correspondence', () => {
    it('classifies ordinary 1-to-1 conversation as NORMAL', () => {
      const email = {
        sender: 'Alex Friend',
        senderEmail: 'alex@gmail.com',
        subject: 'Coffee catch-up on Thursday',
        bodySnippet: 'Hey! Are you free to grab coffee this Thursday afternoon around 3pm?'
      };

      const result = classifier.classify(email);
      assert.equal(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.equal(result.action, TRIAGE_ACTIONS.NONE);
      assert.equal(result.shouldNotify, false);
      assert.equal(result.isNoise, false);
    });
  });

  describe('5. Custom User Rules & SQLite Precedence', () => {
    it('custom user rule overrides default noise classification', () => {
      // User explicitly wants notifications from a specific newsletter
      const rule = {
        name: 'Tech Crunch Daily Priority',
        pattern: '*@techcrunch.com',
        header: 'from',
        category: 'VIP',
        action: 'notify',
        priority: 10
      };

      store.upsertTriageRule(rule);

      const email = {
        sender: 'Tech Crunch Daily',
        senderEmail: 'daily@techcrunch.com',
        subject: 'Today in AI & Venture Capital',
        headers: {
          'list-unsubscribe': '<https://techcrunch.com/unsub>'
        }
      };

      const result = classifier.classifyMessage(email);
      assert.equal(result.category, 'VIP');
      assert.equal(result.shouldNotify, true);
      assert.match(result.matchedRule, /Tech Crunch Daily Priority/i);
    });

    it('evaluates multiple user rules respecting priority ascending', () => {
      const ruleLowPriority = {
        name: 'General Edu Mute',
        pattern: '*@mit.edu',
        category: 'NOISE',
        action: 'mute',
        priority: 100
      };

      const ruleHighPriority = {
        name: 'Advisor VIP',
        conditions: [
          { field: 'from', operator: 'contains', value: 'advisor@mit.edu' }
        ],
        category: 'VIP',
        action: 'notify',
        priority: 10
      };

      store.upsertTriageRule(ruleLowPriority);
      store.upsertTriageRule(ruleHighPriority);

      const email = {
        sender: 'My Academic Advisor',
        senderEmail: 'advisor@mit.edu',
        subject: 'Dissertation committee selection'
      };

      const result = classifier.classifyMessage(email);
      assert.equal(result.category, 'VIP');
      assert.equal(result.shouldNotify, true);
      assert.match(result.matchedRule, /Advisor VIP/i);
    });

    it('supports conditions with regex operator', () => {
      const rule = {
        name: 'Course Code Tag VIP',
        conditions: [
          { field: 'subject', operator: 'regex', value: '\\[CS\\s*\\d+\\]' }
        ],
        category: 'VIP',
        action: 'notify',
        priority: 50
      };

      store.upsertTriageRule(rule);

      const matchEmail = {
        sender: 'Class Discussion',
        senderEmail: 'discuss@forum.org',
        subject: '[CS 162] Operating Systems Homework 3 Errata'
      };

      const res = classifier.classifyMessage(matchEmail);
      assert.equal(res.category, 'VIP');
      assert.equal(res.shouldNotify, true);
    });
  });

  describe('6. SqliteStore Metadata Tagging Integration', () => {
    it('persists category, triage_score, is_noise, and triage_reason upon message ingestion', () => {
      // Create test account and folder
      store.upsertAccount({ id: 'acc1', email: 'user@test.com', provider: 'gmail' });
      store.upsertFolder({ id: 'fld1', accountId: 'acc1', name: 'INBOX', path: 'INBOX' });

      const email = {
        accountId: 'acc1',
        folderId: 'fld1',
        uid: 1001,
        sender: 'Prof. Turing',
        senderEmail: 'turing@cambridge.edu',
        subject: 'Computation & Logic',
        bodySnippet: 'Please read section 3.',
        category: 'VIP',
        triageScore: 98.5,
        isNoise: false,
        triageReason: 'Academic instructor from .edu domain'
      };

      store.upsertMessages([email]);

      const stored = store.getMessageByUid('fld1', 1001);
      assert.ok(stored, 'Message should be persisted');
      assert.equal(stored.category, 'VIP');
      assert.equal(stored.triageScore, 98.5);
      assert.equal(stored.isNoise, false);
      assert.equal(stored.triageReason, 'Academic instructor from .edu domain');
    });

    it('filters messages by category in getMessages()', () => {
      store.upsertAccount({ id: 'acc1', email: 'user@test.com', provider: 'gmail' });
      store.upsertFolder({ id: 'fld1', accountId: 'acc1', name: 'INBOX', path: 'INBOX' });

      store.upsertMessages([
        { accountId: 'acc1', folderId: 'fld1', uid: 1, sender: 'Prof A', senderEmail: 'a@uni.edu', subject: 'A', category: 'VIP', triageScore: 95, isNoise: 0 },
        { accountId: 'acc1', folderId: 'fld1', uid: 2, sender: 'Store B', senderEmail: 'b@deals.com', subject: 'B', category: 'NOISE', triageScore: 20, isNoise: 1 },
        { accountId: 'acc1', folderId: 'fld1', uid: 3, sender: 'Canvas', senderEmail: 'canvas@instructure.com', subject: 'C', category: 'UPDATE', triageScore: 65, isNoise: 0 }
      ]);

      const vipMessages = store.getMessages({ accountId: 'acc1', category: 'VIP' });
      assert.equal(vipMessages.length, 1);
      assert.equal(vipMessages[0].uid, 1);

      const noiseMessages = store.getMessages({ accountId: 'acc1', category: 'NOISE' });
      assert.equal(noiseMessages.length, 1);
      assert.equal(noiseMessages[0].uid, 2);

      const updateMessages = store.getMessages({ accountId: 'acc1', category: 'UPDATE' });
      assert.equal(updateMessages.length, 1);
      assert.equal(updateMessages[0].uid, 3);
    });
  });

  describe('7. Hardening & Remediation Suite (10 Critical Defects)', () => {
    it('Fix 1: matchWildcard handles ?, +, (, ) safely without unhandled SyntaxError', () => {
      assert.equal(matchWildcard('test', '?est'), true);
      assert.equal(matchWildcard('test', '?abc'), false);
      assert.equal(matchWildcard('prefix+suffix', 'prefix+*'), true);
      assert.equal(matchWildcard('calc(1)', 'calc(*)'), true);
      assert.equal(matchWildcard('user@test.com', '?admin*'), false);
      // Malformed patterns returning false instead of throwing
      assert.doesNotThrow(() => {
        assert.equal(matchWildcard('sample', '[unclosed'), false);
      });
    });

    it('Fix 2: getHeaderValue returns null on null, undefined, or empty array header values', () => {
      assert.equal(getHeaderValue({ 'list-unsubscribe': null }, 'list-unsubscribe'), null);
      assert.equal(getHeaderValue({ 'list-unsubscribe': undefined }, 'list-unsubscribe'), null);
      assert.equal(getHeaderValue({ 'list-unsubscribe': [] }, 'list-unsubscribe'), null);

      // Verify null list-unsubscribe header does not trigger false positive NOISE
      const result = classifier.classify({
        sender: 'Colleague Bob',
        senderEmail: 'bob@example.com',
        subject: 'Project check-in',
        bodySnippet: 'See you tomorrow at the standup.',
        headers: { 'list-unsubscribe': null }
      });
      assert.equal(result.category, TRIAGE_CATEGORIES.NORMAL);
      assert.equal(result.isNoise, false);
    });

    it('Fix 3: getHeaderValue detects cycles in rawHeaders and avoids RangeError stack overflow', () => {
      const circular = {};
      circular.rawHeaders = circular;

      assert.doesNotThrow(() => {
        const val = getHeaderValue(circular, 'x-test');
        assert.equal(val, null);
      });

      const email = {
        sender: 'User',
        senderEmail: 'user@example.com',
        subject: 'Cycle test',
        headers: circular
      };
      const res = classifier.classify(email);
      assert.equal(res.category, TRIAGE_CATEGORIES.NORMAL);
    });

    it('Fix 4: safely coerces senderEmail from primitives/objects and extracts from sender string', () => {
      // Non-string senderEmail (number)
      const numEmail = { senderEmail: 99999, subject: 'Numeric sender' };
      assert.doesNotThrow(() => {
        const res = classifier.classify(numEmail);
        assert.ok(res);
      });

      // Sender object with address
      const objEmail = { senderEmail: { address: 'admin@edu.org' }, subject: 'Obj sender' };
      assert.doesNotThrow(() => {
        const res = classifier.classify(objEmail);
        assert.ok(res);
      });

      // Fallback extraction from RFC 5322 formatted sender string
      const rfcEmail = {
        sender: 'Prof. Robert Sedgewick <rs@cs.princeton.edu>',
        subject: 'Exam Room Relocation Notice'
      };
      const resRfc = classifier.classify(rfcEmail);
      assert.equal(resRfc.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(resRfc.shouldNotify, true);
    });

    it('Fix 5: safely normalizes non-array flags without crashing flags.some', () => {
      const hostileFlags = [123, true, false, null, { flag: '\\Flagged' }];
      for (const flags of hostileFlags) {
        assert.doesNotThrow(() => {
          const res = classifier.classify({
            sender: 'Test',
            senderEmail: 'test@example.com',
            subject: 'Flags test',
            flags
          });
          assert.ok(res);
        });
      }
    });

    it('Fix 6: enforces AND semantics when both pattern and conditions are defined in evaluateUserRule', () => {
      const rule = {
        pattern: '*@company.com',
        header: 'from',
        conditions: [
          { field: 'subject', operator: 'contains', value: 'critical' }
        ]
      };

      // Matches pattern but fails condition
      const failCondition = {
        senderEmail: 'boss@company.com',
        subject: 'General status update'
      };
      assert.equal(evaluateUserRule(rule, failCondition), false);

      // Matches condition but fails pattern
      const failPattern = {
        senderEmail: 'outsider@other.com',
        subject: 'critical security update'
      };
      assert.equal(evaluateUserRule(rule, failPattern), false);

      // Matches both
      const matchBoth = {
        senderEmail: 'boss@company.com',
        subject: 'critical security alert'
      };
      assert.equal(evaluateUserRule(rule, matchBoth), true);
    });

    it('Fix 7: respects explicit rule.action for shouldNotify even when category is VIP', () => {
      const muteVipRule = {
        name: 'Silent VIP',
        pattern: '*@vip-feed.org',
        category: 'VIP',
        action: 'mute'
      };

      const email = {
        senderEmail: 'bulletin@vip-feed.org',
        subject: 'Executive Briefing'
      };

      const res = classifier.classify(email, { userRules: [muteVipRule] });
      assert.equal(res.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(res.action, TRIAGE_ACTIONS.MUTE);
      assert.equal(res.shouldNotify, false, 'shouldNotify must be false when action is mute');
    });

    it('Fix 8: enforces strict account scoping when rule.accountId is specified', () => {
      const accountRule = {
        accountId: 'acc_school',
        pattern: '*@advisor.edu',
        category: 'VIP'
      };

      // Message with missing accountId
      const unassigned = {
        senderEmail: 'advisor@advisor.edu',
        subject: 'Appointment'
      };
      assert.equal(evaluateUserRule(accountRule, unassigned), false);

      // Message with different accountId
      const differentAcc = {
        accountId: 'acc_personal',
        senderEmail: 'advisor@advisor.edu',
        subject: 'Appointment'
      };
      assert.equal(evaluateUserRule(accountRule, differentAcc), false);

      // Message with matching accountId
      const matchingAcc = {
        accountId: 'acc_school',
        senderEmail: 'advisor@advisor.edu',
        subject: 'Appointment'
      };
      assert.equal(evaluateUserRule(accountRule, matchingAcc), true);
    });

    it('Fix 9: does not blanket-mute LMS or faculty senders as NOISE when List-Unsubscribe is present', () => {
      // Piazza notification with List-Unsubscribe -> UPDATE
      const piazzaEmail = {
        sender: 'Piazza Notifications',
        senderEmail: 'updates@piazza.com',
        subject: '[CS189] Midterm solutions posted',
        bodySnippet: 'The instructor has posted midterm solutions.',
        headers: {
          'list-unsubscribe': '<https://piazza.com/unsub>'
        }
      };
      const piazzaRes = classifier.classify(piazzaEmail);
      assert.equal(piazzaRes.category, TRIAGE_CATEGORIES.UPDATE);
      assert.equal(piazzaRes.action, TRIAGE_ACTIONS.BADGE);
      assert.equal(piazzaRes.shouldNotify, false);

      // Faculty listserv announcement -> VIP
      const facultyEmail = {
        sender: 'Prof. Robert Sedgewick',
        senderEmail: 'rs@cs.princeton.edu',
        subject: 'URGENT: Exam room change',
        bodySnippet: 'The exam will be held in McCosh 50.',
        headers: {
          'list-unsubscribe': '<mailto:unsub@princeton.edu>',
          'precedence': 'list'
        }
      };
      const facultyRes = classifier.classify(facultyEmail);
      assert.equal(facultyRes.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(facultyRes.action, TRIAGE_ACTIONS.NOTIFY);
      assert.equal(facultyRes.shouldNotify, true);

      // Explicit promotional keywords still muted as NOISE
      const spamPromo = {
        sender: 'Prof. Marketer',
        senderEmail: 'marketer@stanford.edu',
        subject: '50% off textbook clearance sale today only!',
        bodySnippet: 'Flash sale with coupon code SAVE50.',
        headers: {
          'list-unsubscribe': '<https://store.stanford.edu/unsub>'
        }
      };
      const promoRes = classifier.classify(spamPromo);
      assert.equal(promoRes.category, TRIAGE_CATEGORIES.NOISE);
      assert.equal(promoRes.shouldNotify, false);
    });

    it('Fix 10: ACADEMIC_TITLES_REGEX matches Commonwealth / UK Dr without period', () => {
      assert.equal(ACADEMIC_TITLES_REGEX.test('Dr Jane Watson'), true);
      assert.equal(ACADEMIC_TITLES_REGEX.test('Dr. Jane Watson'), true);
      assert.equal(ACADEMIC_TITLES_REGEX.test('Professor Alan Turing'), true);
      // Non-titles containing 'dr'
      assert.equal(ACADEMIC_TITLES_REGEX.test('drive'), false);
      assert.equal(ACADEMIC_TITLES_REGEX.test('draft email'), false);

      const ukDrEmail = {
        sender: 'Dr Jane Watson',
        senderEmail: 'j.watson@oxford.ac.uk',
        subject: 'Research Fellowship Interview Schedule'
      };
      const res = classifier.classify(ukDrEmail);
      assert.equal(res.category, TRIAGE_CATEGORIES.VIP);
      assert.equal(res.shouldNotify, true);
    });
  });
});
