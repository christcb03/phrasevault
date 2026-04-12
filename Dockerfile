FROM python:3.11-slim

LABEL org.opencontainers.image.title="PhraseVault"
LABEL org.opencontainers.image.source="https://github.com/christcb03/phrasevault"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

# System deps for argon2-cffi and PyNaCl native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libsodium-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir fastapi uvicorn[standard]

# Install the package
COPY pyproject.toml .
COPY phrasevault/ phrasevault/
RUN pip install --no-cache-dir -e .

# Data volume — SQLite DB lives here
VOLUME ["/data"]

# Non-root user
RUN useradd -r -u 1000 -s /sbin/nologin phrasevault \
 && mkdir -p /data \
 && chown phrasevault:phrasevault /data
USER phrasevault

EXPOSE 8080

# PV_API_KEY must be set at runtime — server refuses all requests if unset
ENV PV_DB_PATH=/data/phrasevault.db \
    PV_LOG_LEVEL=INFO \
    PV_DOCS=0

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["uvicorn", "phrasevault.server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
