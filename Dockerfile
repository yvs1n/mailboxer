# Production Dockerfile for Mailboxer on Botkeep Cloud
# Node.js 22 LTS base image with minimal footprint
FROM node:22-bookworm-slim

# Setup directories with permissions for non-root user node
RUN mkdir -p /app /data && chown -R node:node /app /data

# Switch to non-root user for container security
USER node

# Set application working directory
WORKDIR /app

# Copy application files with proper ownership
COPY --chown=node:node package.json ./
COPY --chown=node:node bin/ ./bin/
COPY --chown=node:node src/ ./src/
COPY --chown=node:node public/ ./public/

# Environment variable defaults
ENV PORT=3000 NODE_ENV=production DATA_DIR=/data

# Persistent storage volume for SQLite caching database and AES-256-GCM vault
VOLUME ["/data"]

# Default web ingress port
EXPOSE 3000

# Native Node 22 health check against /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD node -e "fetch('http://localhost:' + (process.env.PORT || 3000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Start Mailboxer web server
CMD ["node", "bin/server.js"]
