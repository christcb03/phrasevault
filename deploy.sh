#!/bin/bash
# deploy.sh — One-command deploy for PhraseVault

set -e

echo "🚀 Deploying PhraseVault to remote server..."

# Pull latest code
git pull origin main

# Rebuild and restart
docker compose down --remove-orphans
docker compose build --no-cache
docker compose up -d

echo "✅ Deployment complete!"
echo "   Server running on http://YOUR_SERVER_IP:8080"
echo "   Logs: docker compose logs -f"