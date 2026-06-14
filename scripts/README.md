# CTI Platform — Operations Scripts

Utility scripts for managing the feed catalog (`rss_sources`). Run everything
from the **project root** so the package imports resolve, and with the project
virtualenv active so `config.py` picks up `.env`.

```powershell
# from C:\Users\USER\PycharmProjects\pythonProject
.\.venv\Scripts\Activate.ps1
```

All scripts read credentials (`SUPABASE_URL`, `SUPABASE_KEY`, …) from `.env` via
`config.py`. No secrets are ever passed on the command line.

---

## 1. Seed the 100 feeds — `sql/seed_all_feeds.sql`

The full catalog lives in `master_feeds_100.csv`; `sql/seed_all_feeds.sql` is the
idempotent loader generated from it.

**Apply it via the Supabase SQL Editor:**

1. Open your project at <https://supabase.com/dashboard> → **SQL Editor** → **New query**.
2. Paste the entire contents of `sql/seed_all_feeds.sql`.
3. Click **Run**.

What it does (safe to re-run any number of times):

- `ADD COLUMN IF NOT EXISTS notes jsonb` and `ingest_method text` on `rss_sources`.
- Creates a unique index on `rss_sources.url`.
- Inserts all 100 sources with `INSERT … ON CONFLICT (url) DO NOTHING`, so feeds
  you already have are never touched or duplicated.

Mapping from the CSV:

| CSV column | rss_sources |
|---|---|
| `source_name` | `name` |
| `feed_url` | `url` |
| `ingest_method` | `ingest_method` (`rss` / `scrape`) |
| `category` | `category` |
| `trust_score` | `trust_score` |
| `region`, `translate_first`, `native_lang` | `notes` (jsonb) |

> Regenerate the SQL after editing the CSV — see "Add new feeds" below.

---

## 2. Validate feeds — `scripts/validate_feeds.py`

Checks that every **active `rss`** source is reachable. Scrape sources are
skipped (they need a browser, not a plain HTTP check).

```powershell
python -m scripts.validate_feeds
```

- Sends a fast `HEAD` (falls back to a streamed `GET`, 5s timeout).
- Polite: 1 request/second, descriptive `User-Agent: CTIPlatform/1.0 (feed validator)`.
- Classifies each feed: `healthy` / `dead` / `redirected` / `auth_required` / `scrape_needed`.
- Writes **`dead_feeds.csv`** (`source_name, url, status_code, error_reason, recommendation`)
  and prints an `X healthy, Y dead, Z need scraping` summary.

It is read-only — it never writes to the database and never bypasses auth.

You can also hit the live service endpoint `GET /feeds/health` (auth not
required) for a quick reachability check of the currently-active sources.

---

## 3. Update a broken feed

After a validation run, open `dead_feeds.csv` and act on the `recommendation`:

- **redirected** → update the URL to the redirect target:
  ```sql
  UPDATE rss_sources SET url = 'https://new-url/feed/' WHERE url = 'https://old-url/feed/';
  ```
- **auth_required / scrape_needed** → either switch it to the browser path or retire it:
  ```sql
  UPDATE rss_sources SET ingest_method = 'scrape' WHERE name = 'Some Source';
  -- or disable it entirely:
  UPDATE rss_sources SET active = false WHERE name = 'Some Source';
  ```
- **dead** (DNS/TLS/4xx with no fix) → disable or replace it:
  ```sql
  UPDATE rss_sources SET active = false WHERE url = 'https://dead-url/feed/';
  ```

> The ingestion pipeline also auto-disables a source after
> `MAX_SOURCE_FAILURES` (5) consecutive fetch failures (see
> `database/supabase_client.record_source_failure`).

---

## 4. Add new feeds

1. Append rows to `master_feeds_100.csv` (keep the column order:
   `source_name,region,feed_url,ingest_method,translate_first,native_lang,category,trust_score`).
2. Regenerate the seed SQL:
   ```powershell
   python - <<'PY'
   import csv, json
   rows = list(csv.DictReader(open('master_feeds_100.csv', encoding='utf-8')))
   def q(s): return "'" + str(s).replace("'", "''") + "'"
   vals = []
   for r in rows:
       notes = {"region": r["region"],
                "translate_first": r["translate_first"].strip().lower() == "true",
                "native_lang": r["native_lang"]}
       vals.append(f"  ({q(r['source_name'])}, {q(r['feed_url'])}, {q(r['category'])}, "
                   f"{float(r['trust_score'])}, true, {q(r['ingest_method'])}, "
                   f"{q(json.dumps(notes, ensure_ascii=False))}::jsonb, 0)")
   print("Regenerated", len(vals), "rows — paste into sql/seed_all_feeds.sql VALUES block")
   PY
   ```
   (Or just edit the `VALUES` block by hand for a one-off addition.)
3. Re-run `sql/seed_all_feeds.sql` in the Supabase SQL Editor — `ON CONFLICT (url)
   DO NOTHING` means only the genuinely new rows get inserted.
4. Run `python -m scripts.validate_feeds` to confirm the new URLs are healthy.

---

## 5. Apply the data-retention cron — `sql/data_retention_cron.sql`

Rolling 2-month retention (current month + previous full month), run **daily at
00:00 UTC** via `pg_cron`. Apply once in the Supabase SQL Editor:

1. (First time only) enable pg_cron: `CREATE EXTENSION IF NOT EXISTS pg_cron;`
2. Paste + run `sql/data_retention_cron.sql`. It creates
   `cleanup_old_data_rolling()` and schedules two idempotent jobs:
   `daily-retention-cleanup` (00:00, deletes/archives) and
   `daily-retention-vacuum` (00:15, `VACUUM ANALYZE`).

Never deleted: `iocs`, `cves`, `threat_actors`, `monthly_reports`,
`contradiction_checks`. Manual run:
```sql
SELECT cleanup_old_data_rolling();
VACUUM ANALYZE raw_items, intelligence_items, processing_jobs, ingestion_logs;
```

## 6. (Optional) normalized feed catalog — `sql/create_feed_sources.sql`

Creates the stricter `feed_sources` table (CHECK constraints on
`ingest_method`/`native_lang`). Forward-looking; the live pipeline still reads
`rss_sources`. Apply it in the SQL Editor if you intend to migrate ingestion.

---

## 7. Semantic RAG vector store — `sql/enable_pgvector.sql` + `scripts/index_vectors.py`

Enables pgvector semantic retrieval for `/ask` (Pillar 3). `/ask` uses vector
search first (top-3 chunks, cosine ≥ 0.82) and falls back to full-text search
when the store is empty/unavailable — so this is optional but improves answers.

1. Apply `sql/enable_pgvector.sql` in the Supabase SQL Editor (creates the
   `vector` extension, `intel_chunks`, the ivfflat index, and
   `match_intel_chunks()`).
2. Ensure `GEMINI_API_KEY` is set (embeddings via `gemini-embedding-001`, 768-dim).
3. Populate / refresh the store (opt-in batch — not run inline with enrichment so
   it doesn't burn the Gemini quota):
   ```powershell
   python -m scripts.index_vectors --days 14 --limit 500
   ```
   Re-running only re-embeds changed chunks. Old chunks are pruned automatically
   when their parent `intelligence_items` row is removed (ON DELETE CASCADE).

---

## Other scripts

- `scripts/migrate_cisa_kev.py` — one-off: switch CISA from its RSS advisories
  feed to the official KEV JSON catalog. `python -m scripts.migrate_cisa_kev`.
