import time, threading
from Services.Crawlers import pastebin, telegram_dl, tor_monitor
from Services.Cr_control.main import STATE  

sched = BackgroundScheduler()

def job_pastebin():
    if not STATE["pastebin_enabled"]: return
    pastebin.run(limit=40)

def job_tor():
    if not STATE["tor_enabled"]: return
    tor_monitor.run(forums=["test.onion"])

def start():
    sched.add_job(job_pastebin, "interval", minutes=2, id="pastebin")
    sched.add_job(job_tor, "interval", minutes=5, id="tor")
    sched.start()
    print("[scheduler] started")
    # Telegram runs as a long-lived listener in its own thread/process
    if STATE["telegram_enabled"]:
        t = threading.Thread(target=lambda: asyncio.run(telegram_dl.run(["@testchannel"])),
                             daemon=True)
        t.start()

if __name__ == "__main__":
    start()
    try:
        while True: time.sleep(10)
    except KeyboardInterrupt:
        sched.shutdown()
