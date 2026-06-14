"""
IOC defanging for safe output (Pillar 7 — security hardening).

Every indicator rendered into an outbound channel (Gmail report, Telegram alert)
MUST be defanged so recipients can't accidentally click a live malicious URL or
auto-resolve a malicious host:

    http://evil.com/x  -> hxxp://evil[.]com/x
    https://bad.net     -> hxxps://bad[.]net
    1.2.3.4             -> 1.2.3[.]4
    energy-update.com   -> energy-update[.]com

Design: `defang_all()` (a.k.a. `defang_for_output`) defangs only IOC-SHAPED
tokens — URLs, IPv4 addresses, and FQDN-like hostnames — and leaves ordinary
prose punctuation untouched, so it is safe to run over a whole summary string,
not just a bare indicator value. Idempotent: running it on already-defanged text
is a no-op (it never double-brackets `[.]` or re-mangles `hxxp`).
"""
import re

# ── Patterns (compiled once) ─────────────────────────────────
# Protocol schemes to neutralize. Ordered so https is handled before http.
_RE_HTTPS = re.compile(r"https://", re.IGNORECASE)
_RE_HTTP = re.compile(r"http://", re.IGNORECASE)
_RE_FTP = re.compile(r"ftp://", re.IGNORECASE)

# IPv4 (with normal dots) — we defang the dots only.
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# FQDN: 2+ dot-separated labels ending in a 2-24 char alphabetic TLD. Anchored on
# word boundaries; the trailing TLD must be alphabetic so we don't hit version
# numbers like 7.0.2 or sentence fragments like "end.Next".
_RE_FQDN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)


def defang_ip(ip: str) -> str:
    """Defang an IPv4 address: 1.2.3.4 -> 1.2.3[.]4. Idempotent."""
    if not ip:
        return ip
    return ip.replace("[.]", ".").replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defang a domain/host: evil.com -> evil[.]com. Idempotent."""
    if not domain:
        return domain
    return domain.replace("[.]", ".").replace(".", "[.]")


def _defang_schemes(text: str) -> str:
    text = _RE_HTTPS.sub("hxxps://", text)
    text = _RE_HTTP.sub("hxxp://", text)
    text = _RE_FTP.sub("fxp://", text)
    return text


def defang_url(url: str) -> str:
    """Defang a full URL: scheme + host dots.

    http://evil.com/a.b -> hxxp://evil[.]com/a.b  (only the HOST is bracketed;
    path dots are left alone so the indicator stays readable/reversible).
    """
    if not url:
        return url
    out = _defang_schemes(url)
    # Defang the host portion only (between scheme and the first / ? #).
    m = re.match(r"^(hxxps?://|fxp://)([^/?#]+)(.*)$", out, re.IGNORECASE)
    if m:
        scheme, host, rest = m.groups()
        host = defang_ip(host) if _RE_IPV4.fullmatch(host) else defang_domain(host)
        return f"{scheme}{host}{rest}"
    # No scheme — treat the whole thing as a host/IP.
    if _RE_IPV4.fullmatch(out):
        return defang_ip(out)
    return defang_domain(out)


def defang_all(text: str) -> str:
    """Defang every IOC-shaped token in a string; leave prose intact. Idempotent.

    Order matters: neutralize schemes first, then bracket IPv4 dots, then FQDN
    dots. FQDN defang runs last and skips tokens already containing `[.]`.
    """
    if not text:
        return text
    out = _defang_schemes(text)
    out = _RE_IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), out)

    def _fqdn_sub(m):
        tok = m.group(0)
        if "[.]" in tok:  # already defanged
            return tok
        return tok.replace(".", "[.]")

    out = _RE_FQDN.sub(_fqdn_sub, out)
    return out


# Alias matching the spec's naming in text_compressor / output functions.
def defang_for_output(text: str) -> str:
    """Alias for defang_all() — defang all IOCs before Gmail/Telegram output."""
    return defang_all(text)
