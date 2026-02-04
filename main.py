from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import uuid
import json
import time

from app.security import verify_api_key

load_dotenv()
app = FastAPI()

@app.post("/honeypot")
async def honeypot(request: Request, ok: bool = Depends(verify_api_key)):
    raw = await request.body()
    headers = dict(request.headers)

    print("\n========== GUVI REQUEST RECEIVED ==========")
    print("HEADERS:", headers)
    print("RAW BODY BYTES:", raw)
    try:
        print("RAW BODY TEXT:", raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    print("==========================================\n")

    # always return valid json
    return JSONResponse(
        status_code=200,
        content={
            "status": True,
            "message": "working",
            "conversation_id": str(uuid.uuid4()),
            "scam_detected": False,
            "risk_score": 0.0,
            "scam_type": "unknown",
            "agent_reply": "Hello"
        }
    )

@app.get("/honeypot")
def honeypot_get(ok: bool = Depends(verify_api_key)):
    return {"status": True, "message": "GET working"}
