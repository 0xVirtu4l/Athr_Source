import requests, time
from bs4 import BeautifulSoup
from Services.Core.extractors import count_signals
from Services.Core.severity import score_severity, SignalCounts

TOR_PROXIES = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}

def check_forum(url: str):
    r = requests.get(url, timeout=20, proxies=TOR_PROXIES, headers={"User-Agent":"AthrTor/1.0"})
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    items = []
    for a in soup.select("a"): 
        title = a.get_text(strip=True)
        href  = a.get("href","")
        if not title or not href: continue
        text = title.lower()
        if any(k in text for k in ("dump","database","combo","vpn access","ransom","shell","leak")):
            items.append((title, href))
    return items

# def run(forums: list[str]):
#     for f in forums:
#         try:
#             items = check_forum(f)
#         except Exception as e:
#             print(f"[tor] err {f}: {e}"); continue
#         for title, link in items:
#             sig = count_signals(title)
#             sev = score_severity(SignalCounts(**sig, size_bytes=len(title)))
#             if sev.label != "low":
#                 # POST event to dashboard ("suspicious_post"), include title+link
#                 print(f"[tor] suspicious: {title} -> {link} ({sev.label})")
#         time.sleep(5)