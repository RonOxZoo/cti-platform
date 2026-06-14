# CTI Platform — Security Checklist

Status of the security controls for the HTTP API (`main.py`) and the external
services it depends on. Reviewed against Section 8 of the production upgrade.

Legend: ✅ in place · ⚠️ partial / recommended follow-up · ❌ missing.

---

## 1. Endpoint auth status

`verify_key()` does a **constant-time** (`hmac.compare_digest`) compare of the
`X-API-Key` header against `API_SECRET_KEY`. The key material is **never logged**
(only the boolean match is). A request with no/empty configured key fails closed.

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/` | GET | ❌ none | Public service banner — no data. Intentional. |
| `/health` | GET | ❌ none | Liveness probe — no data. Intentional. |
| `/status` | GET | ❌ none | ⚠️ Exposes retention counts. Consider auth if counts are sensitive. |
| `/feeds/health` | GET | ❌ none | ⚠️ Lists source URLs + reachability. Public by design; auth optional. |
| `/trending` | GET | ❌ none | ⚠️ Public dashboard (trending IOCs/actors/CVEs). Intentional. |
| `/ingest` | POST | ✅ key | |
| `/enrich` | POST | ✅ key | `limit` clamped to 1–100. |
| `/cleanup` | POST | ✅ key | Calls the Supabase `cleanup_old_data()` RPC. |
| `/ask` | POST | ✅ key | Rate-limited 10/min (free Gemini tier). |
| `/search` | POST | ✅ key | `type` whitelisted (text/ioc/actor/cve); `limit` clamped 1–50. |
| `/notify/test` | POST | ✅ key | |
| `/notify/daily` | POST | ✅ key | |
| `/report/daily` | POST | ✅ key | |
| `/report/preview` | GET | ✅ key | |
| `/report/weekly` | POST | ✅ key | `days` parsed/defaulted. |
| `/report/weekly/preview` | GET | ✅ key | |
| `/report/monthly` | POST | ✅ key | `month` optional. |
| `/report/monthly/preview` | GET | ✅ key | |

---

## 2. Input sanitization

- ✅ **No SQL injection surface**: all DB access goes through the Supabase
  PostgREST client (`database/supabase_client`) with parameterized
  `.eq()/.in_()/.gte()` filters — no string-built SQL in the request path.
- ✅ **Type/range clamping**: `/enrich` `limit` → 1–100; `/search` `limit` → 1–50
  and `type` whitelisted; `/report/*` numeric params parsed with safe defaults.
- ✅ **HTML output escaping**: report builders escape every interpolated value
  (`reporting/daily._esc`), and Telegram messages escape + `<code>`-wrap IOCs.
- ⚠️ `/report/preview?date=` and `/report/*` `date/month` are passed to
  `datetime.strptime`/bounded parsers; malformed values fall back to the default
  window (no crash, no injection).

---

## 3. Response size limits

- ✅ Report fetches are bounded (`_FETCH_LIMIT = 1000` items; top-N tables).
- ✅ `/search` results capped at `limit` (≤50); `/ask` answers are model-bounded.
- ⚠️ `/feeds/health` returns one row per active source (~100). Acceptable; if the
  catalog grows large, paginate.
- ⚠️ `/status` returns the single most recent ingestion log row only.

---

## 4. External-call timeouts (max 30s policy)

| Service | Where | Timeout | Status |
|---|---|---|---|
| Anthropic (Claude) | `enrichment/claude_agent` (SDK) | SDK default + explicit 429/5xx backoff | ✅ |
| Gemini | `enrichment/gemini` (SDK) | SDK default; no retry on quota | ✅ |
| Telegram | `notifier/telegram` | `_SEND_TIMEOUT = 15s` | ✅ |
| Feed validator | `scripts/validate_feeds` | `5s` HEAD/GET | ✅ |
| Feeds health | `main.feeds_health` | `10s` | ✅ |
| RSS ingestion | `ingestion/rss` | `FEED_TIMEOUT = 25s` | ✅ |
| Browser service | `BROWSER_SERVICE_URL` calls | per-call timeout | ✅ |
| Gmail SMTP | `notifier/gmail` | SMTP default | ⚠️ confirm an explicit timeout is set |

---

## 5. Exception handling (never leak internals)

- ✅ All endpoints catch exceptions and return JSON (no stack traces to clients).
- ✅ Secrets are never logged: API key (match-only), Telegram token/chat ID, and
  Anthropic/Gmail credentials are kept out of logs and responses.
- ⚠️ **Follow-up**: several endpoints still return `str(e)` in the JSON `message`
  (e.g. `/ingest`, `/enrich`, `/search`, `/ask`, `/status`). These are operator
  endpoints behind the API key, but for defense-in-depth replace the body with a
  generic message and log the detail server-side only.

---

## 6. Required environment variables

All secrets come from the environment (`.env` locally, Render env vars in prod) —
none are hardcoded.

| Variable | Used by | Secret | If missing |
|---|---|---|---|
| `SUPABASE_URL` | DB client | no | **Fatal** — client cannot initialize; app won't serve. |
| `SUPABASE_KEY` | DB client | **yes** | **Fatal** — all DB access fails. |
| `API_SECRET_KEY` | auth | **yes** | Defaults to a dev value; **set a strong value in prod** or every protected route is guessable. With the hardened `verify_key`, an empty key fails closed. |
| `ANTHROPIC_API_KEY` | Claude (primary) | **yes** | Enrichment falls back to **Gemini**; if Gemini key also absent, the run is **skipped** with a warning. |
| `ANTHROPIC_MODEL` | Claude | no | Defaults to `claude-sonnet-4-6`. |
| `GEMINI_API_KEY` | Gemini (fallback) + RAG | **yes** | Fallback enrichment and `/ask` disabled; primary Claude path unaffected. |
| `GEMINI_MODEL` | Gemini | no | Defaults to `gemini-2.0-flash`. |
| `TELEGRAM_BOT_TOKEN` | notifier | **yes** | Telegram sends are skipped (logged), pipeline continues. |
| `TELEGRAM_CHAT_ID` | notifier | no* | Same as above (both required to send). |
| `GMAIL_SENDER` / `GMAIL_APP_PASSWORD` / `GMAIL_RECIPIENT` | email reports | **yes** (password) | Report email skipped; report still generated and Telegram summary still sent. |
| `BROWSER_SERVICE_URL` | full-article fetch | no | Falls back to RSS excerpt only. |
| `PORT` | Flask | no | Defaults to 5000. |

\* `TELEGRAM_CHAT_ID` is not a credential but must be present for any send.

---

## 7. Recommended follow-ups (prioritized)

1. Replace remaining `str(e)` response bodies with generic messages (§5).
2. Set an explicit timeout on the Gmail SMTP connection (§4).
3. Decide whether `/status`, `/trending`, `/feeds/health` should require the API
   key (currently public by design).
4. Ensure `API_SECRET_KEY` is a strong, unique value in the Render environment
   (do not ship the dev default).
