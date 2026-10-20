/**
 * Mailboxer Anti-Noise Smart Triage Classifier
 *
 * Classifies email messages into VIP / Urgent, Updates / Coursework, Noise, and Normal
 * using RFC headers, domain heuristics, keyword pattern matching, and customizable user rules.
 *
 * @module triage/classifier
 */

import {
  TRIAGE_CATEGORIES,
  TRIAGE_ACTIONS,
  PROMOTIONAL_KEYWORDS_REGEX,
  URGENT_KEYWORDS_REGEX,
  ACADEMIC_TITLES_REGEX,
  COURSEWORK_KEYWORDS_REGEX,
  LMS_DOMAINS,
  BULK_MAILER_HEADERS,
  getHeaderValue,
  matchWildcard,
  evaluateUserRule
} from './rules.js';

/**
 * Smart Anti-Noise Email Classifier.
 */
export class Classifier {
  /**
   * @param {object} [options={}]
   * @param {import('../storage/sqlite-store.js').SqliteStore} [options.store] - Optional SQLite store for user rules
   * @param {object[]} [options.rules] - Pre-loaded user rules
   */
  constructor(options = {}) {
    this.store = options.store || null;
    this.customRules = options.rules || [];
  }

  /**
   * Classifies an email message synchronously using in-memory or passed rules.
   *
   * @param {object} message - Message record
   * @param {object} [options={}] - Evaluation options
   * @param {object[]} [options.userRules] - Explicit user rules override
   * @returns {object} Triage result
   */
  classify(message, options = {}) {
    if (!message || typeof message !== 'object') {
      return {
        category: TRIAGE_CATEGORIES.NORMAL,
        action: TRIAGE_ACTIONS.NONE,
        shouldNotify: false,
        isNoise: false,
        isDigest: false,
        score: 50,
        matchedRule: 'DEFAULT_FALLBACK',
        reason: 'Empty or invalid message'
      };
    }

    const rules = options.userRules || this.customRules || [];

    // 1. Evaluate User Custom Rules (User rules take precedence)
    for (const rule of rules) {
      if (rule.isEnabled === false || rule.is_enabled === 0) continue;
      if (evaluateUserRule(rule, message)) {
        const category = (rule.category || rule.targetCategory || rule.target_category || TRIAGE_CATEGORIES.VIP).toUpperCase();
        const action = rule.action || (category === TRIAGE_CATEGORIES.VIP ? TRIAGE_ACTIONS.NOTIFY : (category === TRIAGE_CATEGORIES.NOISE ? TRIAGE_ACTIONS.MUTE : TRIAGE_ACTIONS.BADGE));
        const shouldNotify = rule.action ? rule.action === TRIAGE_ACTIONS.NOTIFY : category === TRIAGE_CATEGORIES.VIP;
        const isNoise = category === TRIAGE_CATEGORIES.NOISE;
        const isDigest = category === TRIAGE_CATEGORIES.UPDATE;
        const score = category === TRIAGE_CATEGORIES.VIP ? 95 : (isNoise ? 15 : (isDigest ? 65 : 50));

        return {
          category,
          action,
          shouldNotify,
          isNoise,
          isDigest,
          score,
          matchedRule: `USER_RULE:${rule.name || rule.id}`,
          reason: `Matched custom rule: "${rule.name || rule.id}"`
        };
      }
    }

    const subject = typeof message.subject === 'string' ? message.subject : String(message.subject || '');
    const bodySnippet = message.bodySnippet || message.body_snippet || message.body || '';
    const sender = typeof (message.sender || message.from) === 'string' ? (message.sender || message.from) : String(message.sender || message.from || '');

    // Safely coerce and extract senderEmail
    let senderEmail = '';
    if (typeof message.senderEmail === 'string') {
      senderEmail = message.senderEmail;
    } else if (typeof message.sender_email === 'string') {
      senderEmail = message.sender_email;
    } else if (message.senderEmail && typeof message.senderEmail.address === 'string') {
      senderEmail = message.senderEmail.address;
    } else if (message.sender_email && typeof message.sender_email.address === 'string') {
      senderEmail = message.sender_email.address;
    } else if (message.senderEmail || message.sender_email) {
      senderEmail = String(message.senderEmail || message.sender_email);
      if (senderEmail === '[object Object]') senderEmail = '';
    }
    senderEmail = senderEmail.toLowerCase().trim();

    // Fallback extraction from sender string
    if (!senderEmail && sender) {
      const angleMatch = sender.match(/<([^>]+)>/);
      if (angleMatch && angleMatch[1]) {
        senderEmail = angleMatch[1].trim().toLowerCase();
      } else {
        const emailMatch = sender.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
        if (emailMatch) {
          senderEmail = emailMatch[0].trim().toLowerCase();
        }
      }
    }

    const headers = message.headers || message.rawHeaders || message;

    // Helper to extract email domain
    const senderDomain = senderEmail.includes('@') ? senderEmail.split('@').pop() : '';

    // Educational sender heuristics (LMS, university admin, academic faculty)
    const isEduDomain = senderDomain.endsWith('.edu') || senderDomain.endsWith('.ac.uk');
    const isLmsDomain = LMS_DOMAINS.some(d => senderDomain === d || senderDomain.endsWith(`.${d}`));
    const isUniAdminSender = matchWildcard(senderEmail, 'registrar@*.edu') ||
                             matchWildcard(senderEmail, 'bursar@*.edu') ||
                             matchWildcard(senderEmail, 'advising@*.edu') ||
                             matchWildcard(senderEmail, 'bulletin@*.edu') ||
                             matchWildcard(senderEmail, 'canvas@*.edu') ||
                             matchWildcard(senderEmail, 'announcement@*.edu');
    const isAcademicFaculty = isEduDomain && (ACADEMIC_TITLES_REGEX.test(sender) || ACADEMIC_TITLES_REGEX.test(senderEmail));
    const isEducationalSender = isLmsDomain || isUniAdminSender || isAcademicFaculty;

    // 2. Built-in NOISE Heuristics
    // Check RFC 2369 / RFC 8058 List-Unsubscribe
    const listUnsubscribe = getHeaderValue(headers, 'list-unsubscribe') || message.listUnsubscribe;
    const precedence = (getHeaderValue(headers, 'precedence') || message.precedence || '').toLowerCase();
    const autoSubmitted = (getHeaderValue(headers, 'auto-submitted') || '').toLowerCase();
    const autoResponseSuppress = getHeaderValue(headers, 'x-auto-response-suppress');

    let hasBulkMailerHeader = false;
    for (const h of BULK_MAILER_HEADERS) {
      if (getHeaderValue(headers, h)) {
        hasBulkMailerHeader = true;
        break;
      }
    }

    const isPrecedenceBulk = precedence === 'bulk' || precedence === 'list' || precedence === 'junk';
    const isAutoSubmitted = autoSubmitted.includes('auto-generated') || autoSubmitted.includes('auto-replied');
    const matchesPromotionalKeywords = PROMOTIONAL_KEYWORDS_REGEX.test(subject) || PROMOTIONAL_KEYWORDS_REGEX.test(bodySnippet);
    const hasBulkIndicators = Boolean(listUnsubscribe || isPrecedenceBulk || isAutoSubmitted || autoResponseSuppress || hasBulkMailerHeader);

    // If educational sender (LMS, university admin, academic faculty), do not blanket-classify as NOISE
    // based on bulk/list headers alone unless explicit promotional keywords are present.
    if (hasBulkIndicators && (!isEducationalSender || matchesPromotionalKeywords)) {
      let noiseReason = 'Bulk or automated mailing detected';
      if (listUnsubscribe) noiseReason = 'Promotional newsletter with List-Unsubscribe header';
      else if (isPrecedenceBulk) noiseReason = `Precedence: ${precedence} header`;
      else if (isAutoSubmitted) noiseReason = `Auto-Submitted: ${autoSubmitted} header`;
      else if (autoResponseSuppress) noiseReason = 'Exchange automation suppression header';
      else noiseReason = 'Bulk marketing campaign headers detected';

      return {
        category: TRIAGE_CATEGORIES.NOISE,
        action: TRIAGE_ACTIONS.MUTE,
        shouldNotify: false,
        isNoise: true,
        isDigest: false,
        score: 20,
        matchedRule: 'SYSTEM_NOISE',
        reason: noiseReason
      };
    }

    if (matchesPromotionalKeywords) {
      return {
        category: TRIAGE_CATEGORIES.NOISE,
        action: TRIAGE_ACTIONS.MUTE,
        shouldNotify: false,
        isNoise: true,
        isDigest: false,
        score: 25,
        matchedRule: 'SYSTEM_NOISE:PROMOTIONAL_KEYWORDS',
        reason: 'Promotional marketing keywords matched in subject or body'
      };
    }

    // VIP / Urgent indicators
    let flags = message.flags || [];
    if (typeof flags === 'string') {
      try { flags = JSON.parse(flags); } catch { flags = [flags]; }
    }
    const flagArr = Array.isArray(flags) ? flags : [];
    const isFlagged = Boolean(message.isFlagged ?? message.is_flagged ?? flagArr.some(f => String(f).toLowerCase() === '\\flagged'));

    const xPriority = String(getHeaderValue(headers, 'x-priority') || '').trim();
    const importance = (getHeaderValue(headers, 'importance') || '').toLowerCase();
    const priority = (getHeaderValue(headers, 'priority') || '').toLowerCase();
    const hasHighPriorityHeader = xPriority === '1' || xPriority === '2' || importance === 'high' || priority === 'urgent';
    const isUrgentSubject = URGENT_KEYWORDS_REGEX.test(subject);

    const isUrgentOrVipIndicator = isFlagged || hasHighPriorityHeader || isUrgentSubject;

    // 3. Built-in UPDATE / Coursework Heuristics
    const isCourseworkKeyword = COURSEWORK_KEYWORDS_REGEX.test(subject) || COURSEWORK_KEYWORDS_REGEX.test(bodySnippet);

    if (!isUrgentOrVipIndicator && (isLmsDomain || isUniAdminSender || (isEduDomain && isCourseworkKeyword))) {
      let updateReason = 'Coursework / university update detected';
      if (isLmsDomain) updateReason = `Educational LMS platform (${senderDomain})`;
      else if (isUniAdminSender) updateReason = 'University administration announcement';
      else updateReason = 'Coursework / academic keywords from university address';

      return {
        category: TRIAGE_CATEGORIES.UPDATE,
        action: TRIAGE_ACTIONS.BADGE,
        shouldNotify: false,
        isNoise: false,
        isDigest: true,
        score: 65,
        matchedRule: 'SYSTEM_UPDATE',
        reason: updateReason
      };
    }

    // 4. Built-in VIP / Urgent Heuristics
    if (isFlagged || hasHighPriorityHeader || isAcademicFaculty || isUrgentSubject) {
      let vipReason = 'Urgent or VIP communication';
      if (isFlagged) vipReason = 'Starred / flagged email';
      else if (hasHighPriorityHeader) vipReason = `High priority headers (${importance || priority || `X-Priority: ${xPriority}`})`;
      else if (isAcademicFaculty) vipReason = 'Academic instructor / faculty professor communication';
      else if (isUrgentSubject) vipReason = 'Urgent subject token detected';

      return {
        category: TRIAGE_CATEGORIES.VIP,
        action: TRIAGE_ACTIONS.NOTIFY,
        shouldNotify: true,
        isNoise: false,
        isDigest: false,
        score: 95,
        matchedRule: 'SYSTEM_VIP',
        reason: vipReason
      };
    }

    // 5. Default NORMAL fallback
    return {
      category: TRIAGE_CATEGORIES.NORMAL,
      action: TRIAGE_ACTIONS.NONE,
      shouldNotify: false,
      isNoise: false,
      isDigest: false,
      score: 50,
      matchedRule: 'SYSTEM_NORMAL',
      reason: 'Standard personal or direct correspondence'
    };
  }

  /**
   * Convenience method to classify with automatic SQLite user rules loading.
   *
   * @param {object} message
   * @returns {object}
   */
  classifyMessage(message) {
    if (this.store && this.store.getTriageRules) {
      try {
        const userRules = this.store.getTriageRules({ enabledOnly: true });
        return this.classify(message, { userRules });
      } catch {
        // Fall back to in-memory rules
      }
    }
    return this.classify(message);
  }
}

/**
 * Singleton default classifier instance.
 */
export const defaultClassifier = new Classifier();
