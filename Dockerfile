FROM node:22-alpine AS builder

# Native module build deps (argon2, sodium-native)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Install all deps (including native compilation via postinstall)
COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Build frontend
COPY client/package*.json ./client/
RUN cd client && npm ci
COPY client/ ./client/
RUN cd client && npm run build
# Output lands in dist/client/ (per vite.config.ts outDir)

# ── Runtime ────────────────────────────────────────────────────────────────
FROM node:22-alpine

LABEL org.opencontainers.image.title="PhraseVault"
LABEL org.opencontainers.image.source="https://github.com/christcb03/phrasevault"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app
COPY package*.json ./

# Install prod deps with build tools available, then remove tools to keep image lean
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
 && npm ci --omit=dev \
 && apk del .build-deps

COPY --from=builder /app/dist ./dist

VOLUME ["/data"]

RUN addgroup -S phrasevault && adduser -S -G phrasevault phrasevault \
 && mkdir -p /data && chown phrasevault:phrasevault /data
USER phrasevault

EXPOSE 8080

ENV PV_DATA_DIR=/data \
    PV_PORT=8080 \
    PV_HOST=0.0.0.0 \
    PV_LOG_LEVEL=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["node", "dist/server/index.js"]
