"""
Gmail notification system for the CTI platform.

Sends the daily / weekly HTML intelligence reports (and plain-text error
alerts) over Gmail's SMTP server using `smtplib` from the standard library —
no extra dependency.

All sends are best-effort: a failed send is logged and returns False, but is
never raised, so an email failure can never crash the ingestion / enrichment /
reporting pipeline.

Security:
- GMAIL_APP_PASSWORD is a secret — it is never logged, never echoed, and never
  returned to a caller. Only a redacted "configured / not configured" state is
  ever surfaced.
- Connections use implicit TLS (SMTP over SSL, port 465).
"""
import ssl
import smtplib
import logging
from email.utils import formataddr, formatdate, make_msgid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

from config import GMAIL_SENDER, GMAIL_APP_PASSWORD, GMAIL_RECIPIENT

log = logging.getLogger(__name__)

# Gmail's implicit-TLS SMTP endpoint.
_SMTP_HOST = "smtp.gmail.com"
_SMTP_PORT = 465
_SMTP_TIMEOUT = 30

_FROM_NAME = "CTI Platform"


# ── Helpers ──────────────────────────────────────────────────
def _configured() -> bool:
    """True only if sender, app password, and recipient are all present."""
    return bool(GMAIL_SENDER and GMAIL_APP_PASSWORD and GMAIL_RECIPIENT)


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _send(subject: str, *, html: str = None, text: str = None) -> bool:
    """Build and send a message to GMAIL_RECIPIENT. Never raises.

    If both html and text are given the message is multipart/alternative so
    clients that can't render HTML still see a plain-text body. Returns True
    only when the SMTP server accepted the message.
    """
    if not _configured():
        log.warning("[GMAIL] Not configured (sender/app-password/recipient missing) — skipping send")
        return False

    try:
        if html and text:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(text, "plain", "utf-8"))
            # Last part is the preferred one for multipart/alternative.
            msg.attach(MIMEText(html, "html", "utf-8"))
        elif html:
            msg = MIMEText(html, "html", "utf-8")
        else:
            msg = MIMEText(text or "", "plain", "utf-8")

        msg["Subject"] = subject
        msg["From"] = formataddr((_FROM_NAME, GMAIL_SENDER))
        msg["To"] = GMAIL_RECIPIENT
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain="cti-platform")

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(_SMTP_HOST, _SMTP_PORT, timeout=_SMTP_TIMEOUT, context=context) as server:
            server.login(GMAIL_SENDER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_SENDER, [GMAIL_RECIPIENT], msg.as_string())
        log.info(f"[GMAIL] Sent — subject={subject!r}")
        return True
    except smtplib.SMTPAuthenticationError:
        # Do NOT log the exception body — it can echo the credentials back.
        log.error("[GMAIL] Authentication failed — check GMAIL_SENDER / app password")
        return False
    except Exception as e:
        log.error(f"[GMAIL] Send error: {str(e)[:200]}")
        return False


def _sev(stats: dict, key: str) -> int:
    """Read a severity count from a stats dict, defaulting to 0."""
    try:
        return int((stats or {}).get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


# ── Public API ───────────────────────────────────────────────
def send_daily_report(report_html: str, stats: dict) -> bool:
    """Send the daily CTI intelligence report as an HTML email.

    Subject: CTI Daily Brief — [DATE] — [N] Critical / [N] High Items
    """
    stats = stats or {}
    date = stats.get("date") or _today_str()
    critical = _sev(stats, "critical")
    high = _sev(stats, "high")
    subject = f"CTI Daily Brief — {date} — {critical} Critical / {high} High Items"

    text = (
        f"CTI Daily Brief — {date}\n"
        f"Critical: {critical} | High: {high} | Medium: {_sev(stats, 'medium')}\n"
        f"Total items: {stats.get('total', 0)}\n\n"
        "This report is best viewed in an HTML-capable mail client."
    )
    return _send(subject, html=report_html, text=text)


def send_weekly_report(report_html: str, stats: dict) -> bool:
    """Send the 5-day intelligence pattern report as an HTML email.

    Subject: CTI 5-Day Intelligence Brief — [DATE RANGE]
    """
    stats = stats or {}
    start = stats.get("start_date", "")
    end = stats.get("end_date", "")
    if start or end:
        date_range = f"{start} → {end}"
    else:
        date_range = "last 5 days"
    subject = f"CTI 5-Day Intelligence Brief — {date_range}"

    text = (
        f"CTI 5-Day Intelligence Brief — {date_range}\n"
        f"Critical: {_sev(stats, 'critical')} | High: {_sev(stats, 'high')} | "
        f"Medium: {_sev(stats, 'medium')}\n\n"
        "This report is best viewed in an HTML-capable mail client."
    )
    return _send(subject, html=report_html, text=text)


def send_monthly_report(report_html: str, stats: dict) -> bool:
    """Send the monthly strategic intelligence report as an HTML email.

    Subject: CTI Monthly Strategic Brief — [MONTH]
    """
    stats = stats or {}
    month = stats.get("report_month") or _today_str()[:7]
    subject = f"CTI Monthly Strategic Brief — {month}"

    text = (
        f"CTI Monthly Strategic Brief — {month}\n"
        f"Items: {stats.get('total', 0)} | Critical: {_sev(stats, 'critical')} | "
        f"High: {_sev(stats, 'high')}\n"
        f"Israel-relevant: {_sev(stats, 'israel')} | Iran-nexus: {_sev(stats, 'iran_nexus')}\n\n"
        "This report is best viewed in an HTML-capable mail client."
    )
    return _send(subject, html=report_html, text=text)


def send_error_alert(service: str, error: str) -> bool:
    """Send a plain-text error alert email.

    Subject: ⚠️ CTI Platform Error — [SERVICE]
    """
    service = str(service or "unknown")
    subject = f"⚠️ CTI Platform Error — {service}"
    body = (
        f"CTI Platform error alert\n"
        f"{'=' * 40}\n"
        f"Service : {service}\n"
        f"Time    : {_now_str()}\n\n"
        f"Error:\n{str(error)[:1000]}\n"
    )
    return _send(subject, text=body)
