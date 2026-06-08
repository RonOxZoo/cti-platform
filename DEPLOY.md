# Deployment Guide (Internal Ops)

CTI platform consists of two services on Render:

1. **cti-platform** — main Flask app (RSS ingestion, enrichment, API).
2. **cti-browser-service** — Playwright/Chromium microservice used as a fallback to fetch feeds that block direct HTTP (HTTP 403/429/timeout).

---

## 1. Prerequisites

- A Render account with access to the project's GitHub repo.
- Basic Docker knowledge (the browser service ships as a Docker image).
- Supabase project URL + service-role key.
- Shared `API_SECRET_KEY` used to authenticate calls between the two services.

---

## 2. Deploy the main Flask service (cti-platform)

Already deployed at: **https://cti-platform-zk3k.onrender.com**

To redeploy:
- Push to the tracked branch; Render auto-builds, or trigger a manual deploy from the Render dashboard.
- Required environment variables: `SUPABASE_URL`, `SUPABASE_KEY`, `API_SECRET_KEY`, `PORT` (5000), `GEMINI_API_KEY`, `BROWSER_SERVICE_URL` (see step 4).

---

## 3. Deploy the browser microservice (new Docker service)

Create a new **Web Service** on Render from the same repo:

- **Runtime:** Docker
- **Dockerfile path:** `./browser_service/Dockerfile`
- **Docker context:** `./browser_service`
- **Health check path:** `/health`
- **Port:** 5001

The repo includes `browser_service/render.yaml` describing this service (Blueprint deploy also works).

**Environment variables to set (mark each as not-synced / secret):**

| Key            | Value                                  |
|----------------|----------------------------------------|
| `API_SECRET_KEY` | same value as the main service        |
| `SUPABASE_URL`   | Supabase project URL                  |
| `SUPABASE_KEY`   | Supabase service-role key             |

First build is slow: it installs Chromium + system libs via `playwright install`.

---

## 4. Link the two services

On the **main** service (cti-platform), set:

```
BROWSER_SERVICE_URL = https://cti-browser-service.onrender.com
```

(Replace with the actual URL Render assigns the browser service.)

The main service calls `POST {BROWSER_SERVICE_URL}/fetch` with header `X-API-Key: <API_SECRET_KEY>` whenever a feed returns 403/429 or times out. Both services must share the same `API_SECRET_KEY`.

---

## 5. Health checks

- Main:    `https://cti-platform-zk3k.onrender.com/health`
- Browser: `https://cti-browser-service.onrender.com/health`

The browser `/health` returns `{"status": "ok", "service": "cti-browser-service", ...}` and requires no auth.

---

## 6. Troubleshooting

- **Cold start delays:** Render free/standard instances spin down when idle. The first `/fetch` after idle can take 30-60s (container wake + Chromium launch). The main service uses a 60s timeout on browser calls to absorb this. If fallbacks fail right after deploy, retry once the service is warm.
- **Playwright memory usage:** Chromium is memory-heavy. If the service OOMs/restarts, bump the Render instance size. Launch args already include `--disable-dev-shm-usage` and `--no-sandbox` to reduce footprint in containers. Browsers are always closed in a `finally` block to avoid leaks.
- **SSRF protection errors (HTTP 400 "SSRF protection"):** the browser service resolves each target hostname and rejects private/loopback ranges (10/8, 172.16/12, 192.168/16, 127/8, ::1). If a legitimate fetch is blocked, confirm the target resolves to a public IP. Also note: only http/https schemes are allowed and URLs are capped at 2048 chars.
- **401 Unauthorized on /fetch:** `API_SECRET_KEY` mismatch between the two services. Confirm both env vars are identical.
- **429 Rate limit exceeded:** the browser service allows 10 requests / 60s per IP. Stagger ingestion or reduce concurrent fallbacks.
