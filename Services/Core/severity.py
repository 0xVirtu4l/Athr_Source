from dataclasses import dataclass
from typing import List, Dict

@dataclass
class SignalCounts:
    emails: int = 0
    ips: int = 0
    domains: int = 0
    passwords: int = 0
    btc: int = 0
    urls: int = 0
    keywords: int = 0   
    watchlist_hits: int = 0
    size_bytes: int = 0

@dataclass
class SeverityResult:
    score: int
    label: str  # "low" | "medium" | "high"
    reasons: List[str]

DEFAULT_THRESHOLDS = dict(low=0, medium=6, high=10)

def score_severity(sig: SignalCounts,
                   thresholds: Dict[str, int] = DEFAULT_THRESHOLDS) -> SeverityResult:
    score, reasons = 0, []

    # Core signals
    if sig.emails >= 1:  score += 1; reasons.append(f"{sig.emails} email(s)")
    if sig.emails >= 10: score += 2; reasons.append("email list")

    if sig.passwords >= 1: score += 3; reasons.append("password token(s) present")
    if sig.passwords >= 10: score += 2; reasons.append("bulk passwords")

    if sig.ips >= 1: score += 1; reasons.append("IP(s)")
    if sig.domains >= 1: score += 1; reasons.append("domain(s)")
    if sig.btc >= 1: score += 1; reasons.append("BTC address")
    if sig.urls >= 5: score += 1; reasons.append("many URLs")

    if sig.emails >= 1 and sig.passwords >= 1:
        score += 3; reasons.append("email+password combo")

    if sig.keywords >= 1: score += 1; reasons.append("keywords")
    if sig.keywords >= 3: score += 1; reasons.append("many keywords")

    if sig.size_bytes > 50_000: score += 1; reasons.append(">50KB")

    if sig.watchlist_hits > 0:
        score += 4; reasons.append("watchlist match")

    label = "low"
    if score >= thresholds["high"]:
        label = "high"
    elif score >= thresholds["medium"]:
        label = "medium"

    return SeverityResult(score=score, label=label, reasons=reasons)
