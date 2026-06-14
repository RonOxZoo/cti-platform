import os
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
API_SECRET_KEY = os.getenv('API_SECRET_KEY', 'cti-platform-secret-2024')
PORT = int(os.getenv('PORT', 5000))
BROWSER_SERVICE_URL = os.getenv('BROWSER_SERVICE_URL', '')
RENDER_SERVICE_URL = os.getenv('RENDER_SERVICE_URL', '')

# ── Agent priority (PRIORITY ZERO — Claude is the primary enrichment agent) ──
# 1. Claude  (PRIMARY)        — always tried first when ANTHROPIC_API_KEY is set.
# 2. Gemini  (FALLBACK ONLY)  — used only when ANTHROPIC_API_KEY is absent.
# 3. Skip with a warning      — last resort when neither key is configured.
# This order is enforced in enrichment/gemini.py run_enrichment()/_select_agent()
# and must not be changed: Claude is never bypassed for Gemini while its key is
# present, even on a transient Claude error (the job stays pending instead).
PRIMARY_AGENT = "claude"
FALLBACK_AGENT = "gemini"

# Claude (Anthropic) enrichment agent — primary enrichment engine.
# ANTHROPIC_API_KEY is a secret; never log it or return it in an API response.
# Model is env-overridable. Default is claude-sonnet-4-6 (current Sonnet); the
# previous snapshot claude-sonnet-4-20250514 is deprecated and retires 2026-06-15.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

# Gemini fallback model (free tier). Env-overridable.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Playwright full-article fetch: when an RSS excerpt is shorter than this many
# characters, fetch the full article via the browser service instead.
FULL_FETCH_THRESHOLD = int(os.getenv("FULL_FETCH_THRESHOLD", 500))

# Telegram notifications. Both must be set for notifications to be sent.
# NOTE: the bot token is a secret — never log it or return it in an API response.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Gmail SMTP for the daily/weekly intelligence reports.
# GMAIL_APP_PASSWORD is a Google app password (16 chars), NOT the account
# password — it is a secret and must never be logged or returned in a response.
GMAIL_SENDER = os.getenv("GMAIL_SENDER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
GMAIL_RECIPIENT = os.getenv("GMAIL_RECIPIENT")
