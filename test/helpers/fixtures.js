/**
 * Shared Test Fixtures Helper (test/helpers/fixtures.js)
 * Provides valid mock configurations, malformed mutations, and mock environments.
 */

export function getMockAccountConfig(provider = 'apple', overrides = {}) {
  const baseConfigs = {
    apple: {
      id: 'apple-test',
      label: 'Apple Mail (user@icloud.com)',
      provider: 'apple',
      email: 'user@icloud.com',
      enabled: true,
      auth: {
        type: 'app_password',
        user: 'user@icloud.com',
        pass: 'abcdefghijklmnop'
      },
      imap: {
        host: 'imap.mail.me.com',
        port: 993,
        secure: true,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      },
      smtp: {
        host: 'smtp.mail.me.com',
        port: 587,
        secure: false,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      }
    },
    gmail: {
      id: 'gmail-test',
      label: 'Google Mail (user@gmail.com)',
      provider: 'gmail',
      email: 'user@gmail.com',
      enabled: true,
      auth: {
        type: 'app_password',
        user: 'user@gmail.com',
        pass: 'abcdefghijklmnop'
      },
      imap: {
        host: 'imap.gmail.com',
        port: 993,
        secure: true,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      },
      smtp: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      }
    },
    outlook: {
      id: 'outlook-test',
      label: 'Microsoft Outlook (user@university.edu)',
      provider: 'outlook',
      email: 'user@university.edu',
      enabled: true,
      auth: {
        type: 'password',
        user: 'user@university.edu',
        pass: 'StrongStudentPassword2026!'
      },
      imap: {
        host: 'outlook.office365.com',
        port: 993,
        secure: true,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      },
      smtp: {
        host: 'smtp.office365.com',
        port: 587,
        secure: false,
        connectionTimeoutMs: 10000,
        authTimeoutMs: 10000,
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' }
      }
    }
  };

  return { ...baseConfigs[provider], ...overrides };
}
