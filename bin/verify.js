#!/usr/bin/env node
/**
 * Mailboxer Standalone Account Diagnostics & Verification CLI
 *
 * Runs diagnostic tests against configured email accounts (Apple Mail, Gmail, Outlook, Custom).
 * Tests TLS handshake, authentication, server capabilities, and INBOX status.
 *
 * Usage:
 *   npm run verify
 *   node bin/verify.js [--env <path>] [--account <provider|id>] [--json] [--help]
 *
 * Zero-dependency native Node.js 22 implementation.
 */

import path from 'node:path';
import process from 'node:process';
import {
  loadEnvironmentAccounts,
  maskEmail,
  maskSecret,
  ImapClient
} from '../src/index.js';

// ANSI color helpers with NO_COLOR & TTY support
const isColorSupported = !process.env.NO_COLOR && (process.stdout.isTTY ?? false);
const c = {
  reset: isColorSupported ? '\x1b[0m' : '',
  bold: isColorSupported ? '\x1b[1m' : '',
  dim: isColorSupported ? '\x1b[2m' : '',
  green: isColorSupported ? '\x1b[32m' : '',
  red: isColorSupported ? '\x1b[31m' : '',
  yellow: isColorSupported ? '\x1b[33m' : '',
  cyan: isColorSupported ? '\x1b[36m' : '',
  blue: isColorSupported ? '\x1b[34m' : '',
  magenta: isColorSupported ? '\x1b[35m' : '',
  gray: isColorSupported ? '\x1b[90m' : ''
};

function parseArgs(args) {
  const options = {
    envPath: '.env',
    accountFilter: null,
    json: false,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--env' || arg === '-e') {
      if (i + 1 < args.length) {
        options.envPath = args[++i];
      }
    } else if (arg.startsWith('--env=')) {
      options.envPath = arg.slice(6);
    } else if (arg === '--account' || arg === '-a') {
      if (i + 1 < args.length) {
        options.accountFilter = args[++i].toLowerCase();
      }
    } else if (arg.startsWith('--account=')) {
      options.accountFilter = arg.slice(10).toLowerCase();
    }
  }

  return options;
}

function printHelp() {
  console.log(`
${c.bold}Mailboxer Account Diagnostics & Verification Tool${c.reset}

${c.bold}USAGE:${c.reset}
  npm run verify
  node bin/verify.js [options]

${c.bold}OPTIONS:${c.reset}
  -e, --env <path>        Path to environment file (default: .env)
  -a, --account <name>    Test only a specific account by provider or ID (apple, gmail, outlook)
  --json                  Output raw machine-readable JSON results
  -h, --help              Display this help message

${c.bold}PROVIDERS SUPPORTED:${c.reset}
  • ${c.cyan}Apple Mail (iCloud)${c.reset}   imap.mail.me.com:993 (requires App-Specific Password)
  • ${c.cyan}Google Mail (Gmail)${c.reset}   imap.gmail.com:993 (requires 2FA App Password)
  • ${c.cyan}Microsoft Outlook${c.reset}     outlook.office365.com:993 (University / Personal)
`);
}

function printBanner() {
  console.log(`${c.bold}${c.cyan}=================================================================${c.reset}`);
  console.log(`${c.bold}${c.cyan}                 MAILBOXER ACCOUNT DIAGNOSTICS                   ${c.reset}`);
  console.log(`${c.bold}${c.cyan}=================================================================${c.reset}\n`);
}

function printUnconfiguredGuidance(unconfigured, envPath) {
  console.log(`${c.yellow}${c.bold}Notice: No active email accounts configured for verification.${c.reset}`);
  console.log(`${c.gray}Environment file inspected: ${path.resolve(envPath)}${c.reset}\n`);

  if (unconfigured.length > 0) {
    console.log(`${c.bold}Account Status Checklist:${c.reset}`);
    for (const item of unconfigured) {
      const reasonLabel = item.reason === 'PLACEHOLDER_CREDENTIALS'
        ? `${c.yellow}[ PLACEHOLDER ]${c.reset}`
        : `${c.gray}[ NOT SET ]${c.reset}`;

      console.log(`  ${reasonLabel} ${c.bold}${item.message}${c.reset}`);
      if (item.advice) {
        console.log(`     ${c.dim}→ ${item.advice}${c.reset}`);
      }
    }
  }

  console.log(`\n${c.bold}How to configure your accounts in 3 steps:${c.reset}`);
  console.log(`  1. Copy the template:  ${c.cyan}cp .env.example .env${c.reset}`);
  console.log(`  2. Open ${c.cyan}.env${c.reset} in your editor and enter your real email addresses and passwords.`);
  console.log(`  3. Run verification:   ${c.cyan}npm run verify${c.reset}\n`);

  console.log(`${c.bold}Quick Reference for Credentials:${c.reset}`);
  console.log(`  • ${c.bold}Apple Mail:${c.reset} Generate an App-Specific Password at ${c.blue}https://appleid.apple.com${c.reset}`);
  console.log(`  • ${c.bold}Gmail:${c.reset} Enable 2FA, then generate an App Password at ${c.blue}https://myaccount.google.com/apppasswords${c.reset}`);
  console.log(`  • ${c.bold}Outlook/Uni:${c.reset} Use university/M365 credentials or create an App Password in Account Security.`);
}

export async function runDiagnostics(cliArgs = process.argv.slice(2)) {
  const options = parseArgs(cliArgs);

  if (options.help) {
    printHelp();
    return { exitCode: 0, results: [] };
  }

  // Load environment accounts
  const { accounts, unconfigured } = loadEnvironmentAccounts({
    envPath: options.envPath
  });

  // Filter accounts if requested
  const targetAccounts = options.accountFilter
    ? accounts.filter((acc) => {
        const idMatch = (acc.id || '').toLowerCase() === options.accountFilter;
        const providerMatch = (acc.provider || '').toLowerCase() === options.accountFilter;
        return idMatch || providerMatch;
      })
    : accounts;

  // Handle case where no accounts are configured
  if (targetAccounts.length === 0) {
    if (options.json) {
      console.log(JSON.stringify({
        status: 'unconfigured',
        totalConfigured: 0,
        unconfigured,
        message: 'No active accounts configured with genuine credentials.'
      }, null, 2));
      return { exitCode: 0, results: [] };
    }

    printBanner();
    printUnconfiguredGuidance(unconfigured, options.envPath);
    return { exitCode: 0, results: [] };
  }

  if (!options.json) {
    printBanner();
    console.log(`Found ${c.bold}${targetAccounts.length}${c.reset} configured account(s) to verify in ${c.cyan}${options.envPath}${c.reset}:\n`);
  }

  const results = [];
  let allPassed = true;

  for (const account of targetAccounts) {
    const providerName = account.provider?.toUpperCase() || 'CUSTOM';
    const maskedAddr = maskEmail(account.email || account.auth?.user || '');
    const accountLabel = account.label || `${providerName} (${maskedAddr})`;

    if (!options.json) {
      process.stdout.write(`• Testing ${c.bold}${accountLabel}${c.reset} ... `);
    }

    const client = new ImapClient({ accountConfig: account });
    const result = await client.verify(account);

    results.push(result);

    if (result.success) {
      if (!options.json) {
        console.log(`${c.green}${c.bold}[ PASS ]${c.reset}`);
        if (result.tlsDetails) {
          console.log(`  ${c.gray}TLS Protocol:${c.reset} ${result.tlsDetails.protocol} (${result.tlsDetails.cipherName})`);
        }
        if (result.inboxStatus) {
          console.log(`  ${c.gray}INBOX Status:${c.reset} ${c.bold}${result.inboxStatus.totalMessages}${c.reset} total messages (${result.inboxStatus.unseen} unread)`);
        }
        if (result.capabilities && result.capabilities.length > 0) {
          const capSnippet = result.capabilities.slice(0, 8).join(', ') + (result.capabilities.length > 8 ? ' ...' : '');
          console.log(`  ${c.gray}Capabilities:${c.reset} ${capSnippet}`);
        }
        if (result.metrics) {
          console.log(`  ${c.gray}Latency:${c.reset} Handshake ${result.metrics.connectDurationMs}ms | Auth ${result.metrics.authDurationMs}ms | Query ${result.metrics.mailboxQueryDurationMs}ms (Total: ${result.metrics.totalDurationMs}ms)\n`);
        }
      }
    } else {
      allPassed = false;
      if (!options.json) {
        console.log(`${c.red}${c.bold}[ FAIL ]${c.reset}`);
        console.log(`  ${c.red}Error Code:${c.reset} ${result.error?.code || 'UNKNOWN_ERROR'}`);
        console.log(`  ${c.red}Message:${c.reset}    ${result.error?.message || 'Connection or authentication failed'}`);
        if (result.error?.remediationAdvice) {
          console.log(`  ${c.yellow}Remediation:${c.reset} ${result.error.remediationAdvice}`);
        }
        console.log('');
      }
    }
  }

  if (options.json) {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      allPassed,
      totalTested: results.length,
      passedCount: results.filter((r) => r.success).length,
      failedCount: results.filter((r) => !r.success).length,
      results
    }, null, 2));
  } else {
    const passedCount = results.filter((r) => r.success).length;
    const failedCount = results.filter((r) => !r.success).length;

    console.log(`${c.bold}=================================================================${c.reset}`);
    if (allPassed) {
      console.log(`${c.green}${c.bold}RESULT: ALL ACCOUNTS PASSED VERIFICATION (${passedCount}/${results.length})${c.reset}`);
    } else {
      console.log(`${c.red}${c.bold}RESULT: VERIFICATION FAILED (${failedCount}/${results.length} account(s) encountered errors)${c.reset}`);
    }
    console.log(`${c.bold}=================================================================${c.reset}\n`);
  }

  const exitCode = allPassed ? 0 : 1;
  return { exitCode, results };
}

// Execute when invoked directly from CLI
if (process.argv[1] && (process.argv[1].endsWith('verify.js') || process.argv[1].endsWith('verify'))) {
  runDiagnostics(process.argv.slice(2)).then(({ exitCode }) => {
    process.exit(exitCode);
  }).catch((err) => {
    console.error(`\nUnexpected fatal error: ${err.message}`);
    process.exit(1);
  });
}
