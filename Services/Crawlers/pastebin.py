import time, random, requests, hashlib
from bs4 import BeautifulSoup
from Services.Core.extractors import count_signals
from Services.Core.severity import score_severity, SignalCounts
from Services.Core.storage_guard import can_download, GuardConfig

BASE = "https://pastebin.com"
ARCHIVE_URL = f"{BASE}/archive"

session = requests.Session()
session.headers.update({"User-Agent":"Mozilla/5.0 AthrCrawler/1.0"})

def list_recent_ids():
    r = session.get(ARCHIVE_URL, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    table = soup.select_one("div.archive-table table.maintable")
    ids = []
    if table:
        for a in table.select("a[href^='/']"):
            href = a.get("href","")
            if len(href)==9 and href[0]=="/":
                ids.append(href[1:])
    # unique preserve order
    seen=set(); out=[]
    for i in ids:
        if i not in seen:
            seen.add(i); out.append(i)
    return out

def fetch_peek(raw_url, peek_bytes=65536):
    h = hashlib.sha256()
    total=0; chunks=[]
    with session.get(raw_url, stream=True, timeout=20) as r:
        r.raise_for_status()
        for c in r.iter_content(8192):
            if not c: break
            h.update(c)
            if total<peek_bytes:
                take = min(len(c), peek_bytes-total)
                chunks.append(c[:take]); total+=take
            if total>=peek_bytes: break
    peek_text = b"".join(chunks).decode("utf-8", errors="replace")
    return peek_text, h.hexdigest(), total

def fetch_full(raw_url, max_size=20*1024*1024):
    h=hashlib.sha256(); parts=[]; total=0
    with session.get(raw_url, stream=True, timeout=30) as r:
        r.raise_for_status()
        for c in r.iter_content(8192):
            if not c: break
            total+=len(c)
            if total>max_size: raise RuntimeError("too big")
            h.update(c); parts.append(c)
    return b"".join(parts).decode("utf-8", errors="replace"), h.hexdigest(), total

def run(limit=40, guard=GuardConfig()):
    for pid in list_recent_ids()[:limit]:
        raw = f"{BASE}/raw/{pid}"
        try:
            peek, stream_hash, peek_len = fetch_peek(raw)
        except Exception as e:
            print(f"[{pid}] peek error: {e}"); continue

        sig = count_signals(peek)
        sev = score_severity(SignalCounts(**sig, size_bytes=peek_len))


        if sev.label == "low":
            print(f"[{pid}] skip low ({sev.score} | {sev.reasons})")
            time.sleep(random.uniform(0.3,0.8))
            continue

        if not can_download(guard):
            print(f"[{pid}] paused by guard (disk/cpu)"); break

        try:
            full_text, full_hash, total = fetch_full(raw)
        except Exception as e:
            print(f"[{pid}] deep error: {e}"); continue

        sig_full = count_signals(full_text)
        sev_full = score_severity(SignalCounts(**sig_full, size_bytes=total))

        print(f"[{pid}] deep ok {sev_full.label} ({sev_full.score} | size={total})")
        time.sleep(random.uniform(0.3,1.0))
