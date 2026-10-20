#!/usr/bin/env node
/**
 * Mailboxer Web Server Launcher
 *
 * Starts the local Mailboxer onboarding gateway and REST API server.
 *
 * Usage:
 *   npm start
 *   node bin/server.js [--port 3000]
 */

import { WebServer } from '../src/index.js';

const args = process.argv.slice(2);
const portFlagIndex = args.findIndex((a) => a === '--port' || a === '-p');
const parsedPort = portFlagIndex !== -1 && args[portFlagIndex + 1] !== undefined && !Number.isNaN(Number(args[portFlagIndex + 1])) ? Number(args[portFlagIndex + 1]) : null;
const port = parsedPort ?? (process.env.PORT !== undefined && !Number.isNaN(Number(process.env.PORT)) ? Number(process.env.PORT) : (Number(process.env.PORT) || 3000));

const hostFlagIndex = args.findIndex((a) => a === '--host');
const parsedHost = hostFlagIndex !== -1 && args[hostFlagIndex + 1] ? args[hostFlagIndex + 1] : null;
const host = parsedHost || process.env.HOST || '0.0.0.0';

const server = new WebServer({ port, host });

let isShuttingDown = false;
const shutdown = async (signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\nReceived ${signal}. Shutting down Mailboxer gracefully...`);
  try {
    await server.stop();
    console.log('Mailboxer server stopped cleanly.');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.start().then((url) => {
  console.log(`\n=================================================================`);
  console.log(`          MAILBOXER CONSUMER ONBOARDING GATEWAY IS LIVE          `);
  console.log(`=================================================================`);
  console.log(`\n  ➜ Web Client:     ${url}`);
  console.log(`  ➜ Local API:      ${url}/api/accounts`);
  console.log(`  ➜ Health Check:   ${url}/health`);
  console.log(`  ➜ Host Binding:   ${host}:${port}`);
  console.log(`  ➜ Encrypted Vault: Active & Ready (AES-256-GCM)`);
  console.log(`\nPress Ctrl+C to stop the server.\n`);
}).catch((err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[Mailboxer Server Error] Port ${port} is already in use.`);
    console.error(`Try starting with a different port: node bin/server.js --port <port> or set PORT=<port>\n`);
  } else {
    console.error('Failed to start server:', err.message || err);
  }
  process.exit(1);
});
