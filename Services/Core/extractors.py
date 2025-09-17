import re
from typing import Dict, Any

EMAIL_RE   = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)
IP_RE      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE  = re.compile(r"\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
BTC_RE     = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
URL_RE     = re.compile(r"https?://[^\s\"'>)]{4,}", re.I)

KEYWORDS = ("combo", "credentials", "leak", "dump", "pass:", "login", "api_key", "token", "wallet", "db_dump")

def count_signals(text: str) -> Dict[str, int]:
    text_low = text.lower()
    return dict(
        emails   = len(EMAIL_RE.findall(text)),
        ips      = len(IP_RE.findall(text)),
        domains  = len(DOMAIN_RE.findall(text)),
        passwords= text_low.count("pass:") + text_low.count("password"),
        btc      = len(BTC_RE.findall(text)),
        urls     = len(URL_RE.findall(text)),
        keywords = sum(k in text_low for k in KEYWORDS),
    )