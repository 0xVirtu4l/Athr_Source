import os
import httpx
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import firebase_admin
from firebase_admin import auth
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
load_dotenv()


# --- CONFIGURATION ---
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY")
YOUR_APP_SECRET_KEY = os.environ.get("YOUR_APP_SECRET_KEY")
if not firebase_admin._apps: firebase_admin.initialize_app()

# --- FASTAPI APP SETUP ---
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "https://athr-78dc5.web.app",
    "https://athr.pages.dev",
    "https://athr.mohamedayman.org",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- SECURITY DEPENDENCIES ---
async def verify_app_secret(request: Request):
    api_key = request.headers.get("x-api-key")
    if not api_key or api_key != YOUR_APP_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid API Key")
    return True

async def verify_firebase_token(request: Request) -> Optional[dict]:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    id_token = auth_header.split("Bearer ")[1]
    if not id_token or id_token == 'null':
        return None
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Unauthorized: Invalid token: {e}")


# --- API ENDPOINT ---
@app.get("/check-ip")
@limiter.limit("15/minute")
async def get_ip_info(
    request: Request,
    is_app_verified: bool = Depends(verify_app_secret),
    user_token: Optional[dict] = Depends(verify_firebase_token),
):
    """
    Acts as a gatekeeper. Checks the client's IP and returns an access decision.
    """
    client_ip = request.client.host

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"https://ipinfo.io/{client_ip}?token={IPINFO_API_KEY}")
            response.raise_for_status()
            data = response.json()

            is_vpn = data.get("privacy", {}).get("vpn", False)
            is_proxy = data.get("privacy", {}).get("proxy", False)
            is_hosting = data.get("privacy", {}).get("hosting", False)

            # THE DECISION LOGIC
            if is_vpn or is_proxy or is_hosting:
                return {
                    "access_granted": False,
                    "reason": "For security reasons, access from VPNs, proxies, or hosting providers is not permitted."
                }
            else:
                return {"access_granted": True}

        except httpx.RequestError as e:
            # Failsafe: If the IP check service fails, we allow access but log the error.
            print(f"CRITICAL: IPinfo API call failed: {e}. Allowing access as a failsafe.")
            return {"access_granted": True, "warning": "IP check service unavailable."}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001)