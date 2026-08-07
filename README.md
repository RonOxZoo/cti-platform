# CTI Platform

Automated cyber threat intelligence pipeline. Collects from ~100 open sources,
analyses each item with an LLM, cross-references CISA's exploited-vulnerability
catalog, and delivers a bilingual (English/Hebrew) daily brief to Telegram.

Built to solve a real problem: too many feeds to read by hand, most of them
noise. The platform does the first-pass triage — grading severity, extracting
indicators, and surfacing what actually needs attention.

---

## Architecture

```
Make.com  ──HTTP POST──►  Render (Flask)  ──►  Supabase (Postgres)
scheduling                 all logic            all state
                              │
                              ├──►  Groq API          (analysis)
                              ├──►  CISA KEV          (severity grounding)
                              ├──►  Browser service   (Playwright fallback)
                              └──►  Telegram Bot API  (delivery)
```

Make never touches the database. Every write goes through the API, so
authentication and validation have one choke point.

## Pipeline

Four stages, following the classic intelligence cycle:

| Stage | What happens |
|---|---|
| **Collection** | Poll ~100 feeds across 8 categories. Sources that block plain HTTP fall back to a headless-browser service. |
| **Processing** | SHA-256 content hash, deduplicate against what's already stored, queue a job. |
| **Analysis** | One LLM call per item returns structured JSON: severity, confidence, IOCs, CVEs, actors, MITRE techniques, bilingual summary. |
| **Dissemination** | Daily brief to Telegram, each story a button into the interactive bot. |

## Severity is grounded, not guessed

The model grades severity from the article text. That inference is then checked
against **CISA KEV** — the US government's catalog of vulnerabilities confirmed
to be under active exploitation, carrying federal remediation deadlines.

A CVE in the catalog raises the grade to `high`, or `critical` when tied to a
known ransomware campaign. Severity is only ever raised, never lowered: a model
judgement about blast radius still stands on its own.

## Stack

| Component | Role |
|---|---|
| **Python 3 / Flask** | API, served by gunicorn |
| **Supabase (Postgres)** | All persistent state; 23 tables |
| **Make.com** | Scheduling — daily, weekly, monthly, plus a 2-hourly enrichment worker |
| **Groq** | Analysis, rotating across three open-weight models |
| **Playwright** | Headless-browser fallback for feeds that block HTTP |
| **Telegram Bot API** | Delivery and interactive navigation |

Runs entirely on free tiers.

## Layout

| Path | Contents |
|---|---|
| `main.py` | Flask API — every HTTP route |
| `config.py` | Environment configuration |
| `ingestion/` | Feed fetching, deduplication, browser fallback |
| `enrichment/` | LLM agents, KEV cross-reference, contradiction detection |
| `reporting/` | Daily, weekly and monthly report generation |
| `notifier/` | Telegram delivery and the interactive bot |
| `rag/` | Full-text and typed search over collected intelligence |
| `database/` | The single Supabase client |
| `utils/` | Text compression, hashing, IOC defanging |
| `sql/` | Schema migrations, run manually against Supabase |
| `scripts/` | One-off maintenance tasks |
| `browser_service/` | Separate Dockerised Playwright service |

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `SUPABASE_URL` / `SUPABASE_KEY` | yes | Database (service-role key) |
| `API_SECRET_KEY` | yes | Shared secret for protected endpoints |
| `GROQ_API_KEY` | yes | Analysis engine |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | yes | Delivery |
| `BROWSER_SERVICE_URL` | yes | Playwright fallback service |
| `GROQ_MODELS` | no | Comma-separated rotation order |
| `ENRICHMENT_AGENT` | no | Force `groq` / `claude` / `gemini` |
| `ANTHROPIC_API_KEY` | no | Claude, as a fallback engine |
| `TELEGRAM_WEBHOOK_SECRET` | no | Verifies inbound Telegram webhooks |

## Running locally

```bash
pip install -r requirements.txt
cp .env.example .env      # then fill in the values above
python main.py            # dev server on :5000
```

Production runs under gunicorn; see `DEPLOY.md`.

## Design notes

**Deduplication** — content hashing, so one story covered by ten outlets counts
once rather than ten times.

**Source reliability** — every source carries a trust score, and one that fails
five polls in a row is disabled automatically.

**Defanging** — indicators are neutralised before display (`hxxp://`) so a live
URL can never be clicked by accident.

**Retention** — current month plus the previous one, enforced by a Postgres
cron job.

**Stateless bot** — navigation state is encoded in Telegram's `callback_data`,
not held in memory, so a restart never leaves dead buttons behind.

**Chunked ingestion** — feeds are polled in batches with a size cap on each
response, after a single oversized feed repeatedly exhausted the instance's
memory mid-run.
