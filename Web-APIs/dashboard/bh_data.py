# api.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(BASE_DIR, "leaks.json")

app = FastAPI(
    title="Athr Leaks API",
    version="1.0.0",
)

# Allow frontend (React/Next.js/etc.) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # in production: put your domain(s)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_data():
    if not os.path.exists(JSON_PATH):
        return []
    try:
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


@app.get("/leaks")
def get_leaks(limit: int = 50, offset: int = 0):
    """
    Get leaks from JSON file with pagination.
    Newest leaks are at the top (because crawler prepends).
    """
    data = load_data()
    return data[offset: offset + limit]


@app.get("/leaks/latest")
def get_latest(limit: int = 20):
    """
    Quick endpoint for the latest N leaks.
    """
    data = load_data()
    return data[:limit]


@app.get("/leaks/{index}")
def get_leak_by_index(index: int):
    """
    Get a single leak by its index in the JSON array.
    (You can later change this to use an ID field.)
    """
    data = load_data()
    if index < 0 or index >= len(data):
        raise HTTPException(status_code=404, detail="Leak not found")
    return data[index]

if __name__ == "__main__":
    uvicorn.run("bh_data:app", host="0.0.0.0", port=8005, reload=True)