from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional, List
import shutil, os, datetime

app = FastAPI(title="Athr Control")

STATE = {
    "pastebin_enabled": True,
    "telegram_enabled": True,
    "tor_enabled": True,
    "events": [],     # in-memory; replace with DB
    "jobs": []        # list of dicts: {source, status, reason, ts}
}

class TogglePayload(BaseModel):
    enabled: bool

@app.post("/toggle/{source}")
def toggle_source(source: str, body: TogglePayload):
    key = f"{source}_enabled"
    if key not in STATE: return {"ok": False, "error":"unknown source"}
    STATE[key] = body.enabled
    return {"ok": True, "source": source, "enabled": STATE[key]}

@app.get("/status")
def status():
    return {
        "pastebin_enabled": STATE["pastebin_enabled"],
        "telegram_enabled": STATE["telegram_enabled"],
        "tor_enabled": STATE["tor_enabled"],
        "jobs": STATE["jobs"][-200:],
        "events": STATE["events"][-200:]
    }

class ManualMeta(BaseModel):
    category: str
    name: str
    posted_at: Optional[str] = None
    source: Optional[str] = "manual"
    url: Optional[str] = None

@app.post("/manual/add")
def manual_add(meta: ManualMeta, file: UploadFile | None = File(default=None)):
    # save file if present
    storage_path = None
    if file:
        os.makedirs("/data/athr/raw/manual", exist_ok=True)
        storage_path = f"/data/athr/raw/manual/{file.filename}"
        with open(storage_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
    # insert artifact row in DB here (meta + storage_path)
    return {"ok": True, "storage_path": storage_path}

class Event(BaseModel):
    source: str
    kind: str         # e.g., "suspicious_post"
    title: str
    link: str
    severity: str

@app.post("/events")
def push_event(ev: Event):
    evd = ev.dict()
    evd["ts"] = datetime.datetime.utcnow().isoformat()
    STATE["events"].append(evd)
    # also write to DB
    return {"ok": True}
