# Admin factory reset

Clears **all forest and PVFS data** in this PhraseVault instance. Intended to be called by **MediaForest** during an owner-initiated server factory reset, or by a authenticated client with the service token.

**Does not delete `file://` media on the host** — only SQLite rows (`truth_nodes`, `truth_links`, `pvfs_scan_jobs`) and files under `PV_DATA_DIR/pvfs/` (copied blobs). NAS/library paths registered as `file://` locations remain on disk.

---

## Endpoints

| Method | Path | Auth |
|--------|------|------|
| GET | `/admin/factory-reset/preview` | Bearer |
| POST | `/admin/factory-reset` | Bearer |

---

## POST body

```json
{
  "confirmation_phrase": "DELETE ALL MEDIA DATA",
  "acknowledge_irreversible": true
}
```

Both fields are required. Wrong phrase → `400`.

---

## What runs

1. `DELETE` all rows from `link_sibling_order`, `truth_links`, `truth_nodes`, `pvfs_scan_jobs`.
2. Remove all files in `PV_DATA_DIR/pvfs/`.
3. Re-run forest bootstrap (`forest.root`, Configuration tree, TMDB provider stub if `PV_TMDB_KEY` set).
4. Ensure `pvfs:primary` tree root exists (empty inventory).

---

## MediaForest integration

MediaForest owner reset (`POST /admin/factory-reset` on MF) calls this endpoint **first**. If PhraseVault reset fails, MediaForest aborts and leaves its catalog unchanged.

See [mediaforest docs/FACTORY-RESET.md](https://github.com/christcb03/mediaforest/blob/main/docs/FACTORY-RESET.md).

---

## Service mode

Requires PhraseVault without `PV_PASSPHRASE` and a registered MediaForest auth key (`POST /auth/register`), same as other `/forest` and `/pvfs` routes.