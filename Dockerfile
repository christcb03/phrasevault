FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Runtime image ──────────────────────────────────────────────────────────
FROM node:22-alpine

LABEL org.opencontainers.image.title="PhraseVault"
LABEL org.opencontainers.image.source="https://github.com/christcb03/phrasevault"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm ci --ignore-scripts --omit=dev

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
