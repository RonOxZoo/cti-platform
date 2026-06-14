# Make.com Scenario Updates

How the Make automation scenarios should call the CTI platform HTTP API. Every
call is an **HTTP → Make a request** module with:

- Method/URL as listed below (base = your Render service URL).
- Header `X-API-Key: <API_SECRET_KEY>` on all protected endpoints.
- "Parse response" = Yes; set a generous timeout (the enrich/report calls do real
  work) and add error handling so one failed step doesn't abort the whole run.

> **Endpoint status legend:** ✅ live today · 🟡 folded into another endpoint ·
> 🔵 planned (not yet implemented). Build the scenario against the ✅/🟡 reality
> now; wire the 🔵 steps when those routes land.

---

## Scenario 03 — Daily Automation (runs every morning)

| Step | Method | Endpoint | Status | Notes |
|---|---|---|---|---|
| 1 | POST | `/ingest` | ✅ | Pull all active RSS/scrape sources into `raw_items` + queue jobs. |
| 2 | POST | `/enrich` | ✅ | Claude (primary) enriches pending jobs. Body `{"limit": 50}`. Re-run 2–4× if `skipped > 0`. |
| 3 | POST | `/search/proactive` | 🔵 | Proactive Perplexity/web search to fill intel gaps. **Not yet implemented** — skip until the route exists. |
| 4 | POST | `/report/daily` | ✅ | Generates + emails the daily brief **and** posts the Telegram daily summary. |
| 5 | POST | `/notify/daily` | 🟡 | Standalone Telegram daily summary. Only add this if you do **not** run step 4 (step 4 already sends the Telegram summary — running both double-posts). |

**Recommended chain:** 1 → 2 (loop on `skipped`) → 4. Add 3 once `/search/proactive`
ships; use 5 only in a notify-only variant that skips step 4.

Handle the credit-stop signal: if `/enrich` returns `credits_exhausted: true`,
stop the scenario and alert — the jobs stay **pending** for Claude to finish once
credits are topped up (never fall back to Gemini in that case).

---

## Scenario 04 — Weekly (runs once a week)

| Step | Method | Endpoint | Status | Notes |
|---|---|---|---|---|
| 1 | POST | `/report/weekly` | ✅ | Body `{"days": 7}`. Builds the 7-day brief, emails it, **and** posts the Telegram weekly summary. |
| 2 | POST | `/notify/weekly` | 🔵 | Standalone weekly Telegram summary. **Not yet a separate route** — currently sent by step 1. Add only if a notify-only route is implemented. |

**Recommended chain:** just step 1 today (it already delivers email + Telegram).

---

## Scenario 05 — Monthly (runs on the 1st)

| Step | Method | Endpoint | Status | Notes |
|---|---|---|---|---|
| 1 | POST | `/report/monthly` | ✅ | Body `{"month": "YYYY-MM"}` (optional; defaults to previous month). Builds + emails the strategic brief **and** posts the Telegram monthly summary. |
| 2 | POST | `/notify/monthly` | 🔵 | Standalone monthly Telegram summary. **Not yet a separate route** — currently sent by step 1. |

**Recommended chain:** just step 1 today.

---

## Implementation notes for the 🔵 routes

To make the scenarios match this document 1:1, these routes would need to be
added to `main.py`:

- `POST /search/proactive` — run `rag`/web search to surface items the feeds
  missed, queue them as `raw_items`. (New module.)
- `POST /notify/weekly` and `POST /notify/monthly` — thin wrappers that compute
  the window stats and call `notifier.telegram.send_weekly_summary` /
  `send_monthly_summary` **without** regenerating/emailing the full report
  (so a scenario can notify without re-emailing).

Until then, keep the daily/weekly/monthly Telegram delivery inside the
`/report/*` endpoints (steps 4 / 1 / 1 above), which already call the matching
`send_*_summary` helpers.
