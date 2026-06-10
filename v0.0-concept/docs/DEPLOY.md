# PhraseVault deployment (test server)

## Test host

**presubuntu** — `192.168.0.184` (public: `95.216.117.242`)

| Item | Value |
|------|--------|
| URL | https://pvtest.turnernetworking.com |
| Compose on server | `/home/chris/phrasevault/docker-compose.yml` |
| Data | `/opt/phrasevault/data` → container `/data` |
| Media (ro) | `/mnt/unionfs/Media` → `/media` |

MediaForest stack and shared notes: [mediaforest deploy/DEPLOYMENT.md](https://github.com/christcb03/mediaforest/blob/main/deploy/DEPLOYMENT.md).

## CI/CD

```
git push origin main
  → .github/workflows/docker.yml
  → ghcr.io/christcb03/phrasevault:latest (+ sha-… tag)
  → Watchtower on presubuntu (label: com.centurylinklabs.watchtower.enable=true)
  → pull + restart phrasevault container (~5 min poll)
  → optional Telegram notification
```

## Requirements for MediaForest

- Run **without** `PV_PASSPHRASE` (service mode) so MF can `POST /auth/register` its secp256k1 key.
- `PV_DATA_DIR=/data` — forest DB and `pvfs_scan_jobs` live under this path.

## Admin factory reset

| Method | Path |
|--------|------|
| GET | `/admin/factory-reset/preview` |
| POST | `/admin/factory-reset` |

Body for POST: `{ "confirmation_phrase": "DELETE ALL MEDIA DATA", "acknowledge_irreversible": true }`.

Clears all nodes, links, scan jobs, and `pvfs/` store files; re-bootstraps an empty forest. **Does not remove `file://` media on disk.** Full detail: [ADMIN-FACTORY-RESET.md](ADMIN-FACTORY-RESET.md).

MediaForest owner reset depends on this endpoint — deploy PhraseVault before testing MF factory reset.

## Manual redeploy

If Watchtower did not pick up a new image (private GHCR may need host credentials):

```bash
cd /home/chris/phrasevault
docker compose pull && docker compose up -d
docker ps   # phrasevault should be (healthy)
curl -s https://pvtest.turnernetworking.com/health
```

## Local dev image

```bash
docker compose build && docker compose up -d
# API: http://localhost:8080 (see repo docker-compose.yml)
```