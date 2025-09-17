import os, asyncio, hashlib
from telethon import TelegramClient, events
from Services.Core.extractors import count_signals
from Services.Core.severity import score_severity, SignalCounts
from Services.Core.storage_guard import can_download, GuardConfig

API_ID = 25193239        
API_HASH = "c510656fac88db8040fc1ef74095cv3b"
SESSION = "athr_session"
SAVE_DIR = "/data/athr/raw/telegram"
ALLOWED = {".txt",".csv",".json",".log",".zip",".7z",".rar"}
MAX_SIZE = 200*1024*1024  # 200MB cap

async def handle_message(event):
    if not event.message.file: return
    name = event.message.file.name or "noname"
    ext = os.path.splitext(name)[1].lower()
    size = event.message.file.size or 0
    if ext not in ALLOWED or size>MAX_SIZE:
        return

    if not can_download(GuardConfig()):
        print("[tg] paused by guard"); return

    path = os.path.join(SAVE_DIR, name)
    os.makedirs(SAVE_DIR, exist_ok=True)
    await event.message.download_media(file=path)
    # Hash
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    sha = h.hexdigest()

    if ext in {".txt",".csv",".json",".log"}:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(100_000)   # peek 100KB
        except Exception:
            text = ""
        sig = count_signals(text)
        sev = score_severity(SignalCounts(**sig, size_bytes=min(size,100_000)))

        if sev.label == "low":
            try: os.remove(path)
            except: pass
        print(f"[tg] {name} -> {sev.label} ({sev.score}) sha={sha[:10]} size={size}")

async def run(channels: list[str]):
    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.start()
    for ch in channels:
        await client.get_entity(ch)

    @client.on(events.NewMessage(chats=channels))
    async def handler(event):
        await handle_message(event)

    print("[tg] listening...")
    await client.run_until_disconnected()