# crawler.py
import requests
from bs4 import BeautifulSoup
import json
import os
import time
from urllib.parse import urljoin

# ================= CONFIG =================
URL = "https://breach.house/all_breaches" 
LIMIT = 20                            
JSON_PATH = "../../Web-APIs/dashboard/leaks.json"
FETCH_EVERY_SECONDS = 60 * 60          
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# ==========================================


def fetch_latest_leaks(url: str, limit: int = 20):
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    rows = soup.select("tr.data-row")

    leaks = []

    for row in rows[:limit]:
        # leak_name
        leak_name = row.get("data-target")
        if not leak_name:
            target_el = row.select_one("strong.target")
            leak_name = target_el.get_text(strip=True) if target_el else None

        # discovered
        time_el = row.select_one('td[data-title="Discovered"] time')
        if time_el:
            discovered = time_el.get("datetime") or time_el.get_text(strip=True)
        else:
            discovered = None

        # country
        country_el = row.select_one('td[data-title="Country"] .badge__text')
        if country_el:
            country = country_el.get_text(strip=True) or None
        else:
            country = row.get("data-country") or None

        # source_group
        source_el = row.select_one('td[data-title="Source"] a')
        if source_el:
            source_group = source_el.get_text(strip=True)
        else:
            source_group = row.get("data-group") or None

        # link_source (absolute URL)
        post_el = row.select_one('td[data-title="Post"] a')
        if post_el:
            href = post_el.get("href")
            link_source = urljoin(url, href) if href else None
        else:
            link_source = None

        leaks.append({
            "leak_name": leak_name,
            "discovered": discovered,
            "country": country,
            "source_group": source_group,
            "link_source": link_source,
        })

    return leaks


def load_existing():
    if not os.path.exists(JSON_PATH):
        return []
    try:
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_all(data):
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def make_key(item: dict) -> str:
    """
    Unique key for a leak item.
    You can change logic (e.g. use link_source only).
    """
    return f"{item.get('link_source','')}|{item.get('leak_name','')}|{item.get('discovered','')}"


def run_once():
    print("Fetching latest leaks...")
    fetched = fetch_latest_leaks(URL, LIMIT)
    existing = load_existing()

    existing_keys = {make_key(item) for item in existing}

    new_items = []
    for item in fetched:
        key = make_key(item)
        if key not in existing_keys:
            existing_keys.add(key)
            new_items.append(item)

    if not new_items:
        print("No new leaks found. JSON file unchanged.")
        return

    updated = new_items + existing
    save_all(updated)
    print(f"Added {len(new_items)} new leaks. Total now: {len(updated)}")


def run_forever():
    while True:
        try:
            run_once()
        except Exception as e:
            print("Error while fetching:", e)
        print(f"Sleeping for {FETCH_EVERY_SECONDS} seconds...")
        time.sleep(FETCH_EVERY_SECONDS)


if __name__ == "__main__":
    # run_once()
    run_forever()
