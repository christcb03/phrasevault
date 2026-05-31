FROM node:22-slim AS builder

# Build tools needed for any packages that fall back to source compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build && cp src/forest/schema.sql dist/forest/

# Build frontend
COPY client/package*.json ./client/
RUN cd client && npm ci
COPY client/ ./client/
RUN cd client && npm run build
# Output lands in dist/client/ (per vite.config.ts outDir)

# ── Runtime ────────────────────────────────────────────────────────────────
FROM node:22-slim

LABEL org.opencontainers.image.title="PhraseVault"
LABEL org.opencontainers.image.source="https://github.com/christcb03/phrasevault"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app
COPY package*.json ./

# node:22-slim is Debian/glibc — sodium-native and argon2 prebuilt linux-x64
# binaries work without compilation. No build tools needed here.
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

VOLUME ["/data"]

# node:22-slim ships with a 'node' user at UID/GID 1000 — use it
# so the container user matches the Ansible-created host data directory (1000:1000).
RUN mkdir -p /data && chown node:node /data
USER node

EXPOSE 8080

ENV PV_DATA_DIR=/data \
    PV_PORT=8080 \
    PV_HOST=0.0.0.0 \
    PV_LOG_LEVEL=info

# Use node for the health check — no wget needed in the slim image
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "dist/server/index.js"]
