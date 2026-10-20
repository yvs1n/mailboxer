/**
 * Mailboxer Anti-Noise Triage Rules & Detection Heuristics
 *
 * Defines default regex patterns, header inspection rules, academic domain matchers,
 * and user rule evaluation engines for classifying emails into VIP, UPDATE, NOISE, and NORMAL.
 *
 * @module triage/rules
 */

/**
 * Triage categories supported by the engine.
 */
export const TRIAGE_CATEGORIES = Object.freeze({
  VIP: 'VIP',
  UPDATE: 'UPDATE',
  NOISE: 'NOISE',
  NORMAL: 'NORMAL'
});

/**
 * Notification actions supported by the engine.
 */
export const TRIAGE_ACTIONS = Object.freeze({
  NOTIFY: 'notify',
  BADGE: 'badge',
  MUTE: 'mute',
  NONE: 'none'
});

/**
 * Promotional and noise keywords regex.
 */
export const PROMOTIONAL_KEYWORDS_REGEX = /\b(\d+%\s*(?:off|discount)|exclusive deal|flash sale|limited time offer|coupon code|promo code|free shipping|newsletter|weekly digest|order confirmed|receipt for your|track your package|special savings|sale ends|clearance)\b/i;

/**
 * Urgent and high-priority keywords regex.
 */
export const URGENT_KEYWORDS_REGEX = /\b(urgent|asap|action required|emergency|immediate attention|deadline today|final notice|exam room change|class cancelled|class canceled)\b/i;

/**
 * Academic faculty titles regex for sender names.
 */
export const ACADEMIC_TITLES_REGEX = /\b(prof\b|professor|dr\b|dr\.|dean|faculty|instructor|lecturer|teaching assistant|ta\b)/i;

/**
 * Educational Learning Management System (LMS) domain matchers.
 */
export const LMS_DOMAINS = [
  'instructure.com',
  'canvas.net',
  'blackboard.com',
  'piazza.com',
  'gradescope.com',
  'edx.org',
  'coursera.org',
  'moodle.org'
];

/**
 * Coursework and university academic subject keywords regex.
 */
export const COURSEWORK_KEYWORDS_REGEX = /\b(assignment|announcement|grade posted|graded|submission receipt|syllabus|coursework|lecture slides|quiz reminder|exam schedule|office hours|homework|term paper|midterm|final exam)\b/i;

/**
 * Known bulk mailer and campaign headers indicating automated newsletters or promotions.
 */
export const BULK_MAILER_HEADERS = [
  'list-unsubscribe',
  'list-unsubscribe-post',
  'x-campaign',
  'x-mailgun-tag',
  'x-sendgrid-eid',
  'x-mc-user',
  'x-marketoid',
  'x-newsletter',
  'x-bounce-to'
];

/**
 * Checks if a string matches a wildcard pattern (e.g. '*@instructure.com' or 'registrar@*.edu').
 *
 * @param {string} text - Text to test
 * @param {string} pattern - Pattern containing '*' or exact string
 * @returns {boolean}
 */
export function matchWildcard(text, pattern) {
  if (!text || !pattern || typeof text !== 'string' || typeof pattern !== 'string') return false;
  try {
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    const regex = new RegExp(`^${escaped}$`, 'i');
    return regex.test(text);
  } catch {
    return false;
  }
}

/**
 * Extracts a normalized header value from various header representations.
 *
 * @param {object} headers - Headers object or message object
 * @param {string} headerName - Name of the header to retrieve (case-insensitive)
 * @param {Set} [visited=new Set()] - Set of visited objects for cycle detection
 * @returns {string|null}
 */
export function getHeaderValue(headers, headerName, visited = new Set()) {
  if (!headers || typeof headers !== 'object') return null;
  if (visited.has(headers)) return null;
  visited.add(headers);

  const target = (headerName || '').toLowerCase();

  // Direct property check
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      if (val === null || val === undefined) return null;
      if (Array.isArray(val)) {
        const filtered = val.filter(v => v !== null && v !== undefined);
        return filtered.length > 0 ? filtered.join(', ') : null;
      }
      return String(val);
    }
  }

  // Check rawHeaders if present
  if (headers.rawHeaders && typeof headers.rawHeaders === 'object') {
    return getHeaderValue(headers.rawHeaders, headerName, visited);
  }

  return null;
}

/**
 * Evaluates a single condition against a message.
 *
 * @param {object} condition - Condition definition { field, operator, value }
 * @param {object} message - Message record
 * @returns {boolean}
 */
export function evaluateCondition(condition, message) {
  if (!condition || !message) return false;

  const field = (condition.field || '').toLowerCase();
  const operator = (condition.operator || 'equals').toLowerCase();
  const expectedValue = condition.value !== undefined ? String(condition.value).toLowerCase() : '';

  let actualValue = '';

  if (field === 'from' || field === 'sender') {
    actualValue = `${message.sender || ''} ${message.senderEmail || message.sender_email || ''}`.trim();
  } else if (field === 'senderemail' || field === 'sender_email') {
    actualValue = message.senderEmail || message.sender_email || '';
  } else if (field === 'to' || field === 'recipients') {
    const r = message.recipients;
    actualValue = Array.isArray(r) ? r.join(' ') : String(r || '');
  } else if (field === 'subject') {
    actualValue = message.subject || '';
  } else if (field === 'body' || field === 'snippet' || field === 'bodysnippet' || field === 'body_snippet') {
    actualValue = message.bodySnippet || message.body_snippet || '';
  } else {
    // Header lookup
    actualValue = getHeaderValue(message.headers || message.rawHeaders || message, field) || '';
  }

  const actualLower = actualValue.toLowerCase();

  switch (operator) {
    case 'equals':
      return actualLower === expectedValue;
    case 'contains':
      return actualLower.includes(expectedValue);
    case 'startswith':
      return actualLower.startsWith(expectedValue);
    case 'endswith':
      return actualLower.endsWith(expectedValue);
    case 'regex':
      try {
        const re = new RegExp(condition.value, 'i');
        return re.test(actualValue);
      } catch {
        return false;
      }
    case 'exists':
      return actualValue.length > 0;
    default:
      return actualLower.includes(expectedValue);
  }
}

/**
 * Evaluates whether a user-defined rule matches a message.
 *
 * @param {object} rule - Rule record from triage_rules table
 * @param {object} message - Message record
 * @returns {boolean}
 */
export function evaluateUserRule(rule, message) {
  if (!rule || !message) return false;

  // Account scope check: if rule is account-specific, accountId must match
  if (rule.accountId && message.accountId !== rule.accountId) {
    return false;
  }

  let hasCriteria = false;

  // Shorthand pattern + header rule
  if (rule.pattern) {
    hasCriteria = true;
    const headerName = rule.header || 'from';
    let targetVal = '';
    if (headerName === 'from' || headerName === 'sender') {
      targetVal = message.senderEmail || message.sender_email || message.sender || '';
    } else if (headerName === 'subject') {
      targetVal = message.subject || '';
    } else {
      targetVal = getHeaderValue(message.headers || message, headerName) || '';
    }

    if (!matchWildcard(String(targetVal), rule.pattern)) {
      return false;
    }
  }

  // JSON conditions array
  if (Array.isArray(rule.conditions) && rule.conditions.length > 0) {
    hasCriteria = true;
    // All conditions must match (AND semantics)
    if (!rule.conditions.every(c => evaluateCondition(c, message))) {
      return false;
    }
  }

  return hasCriteria;
}
