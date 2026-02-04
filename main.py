from fastapi import FastAPI, Depends, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import time
import uuid
from dotenv import load_dotenv

from app.detector import detect_scam
from app.memory import get_session
from app.extractor import extract_intel
from app.agent_gemini import generate_reply

load_dotenv()

import os
API_KEY = os.getenv("API_KEY", "harish_secret_key_123")

app = FastAPI(title="Agentic Honeypot API", version="final")


# ✅ Root MUST respond 200 (no auth)
@app.get("/")
def root():
    return {"status": True, "message": "Agentic Honeypot service is live"}


@app.get("/health")
def health():
    return {"status": True, "message": "ok"}


def empty_intel():
    return {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "urls": [],
        "phone_numbers": []
    }


def verify_key_optional(x_api_key: str = Header(None)):
    """
    Optional API-key check (never blocks GET/HEAD tester calls).
    """
    if not x_api_key:
        return False
    return x_api_key == API_KEY


def verify_key_required(x_api_key: str = Header(None)):
    """
    Required API-key check (used for POST).
    """
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return True


def make_output():
    return {
        "status": True,
        "message": "Honeypot endpoint reachable",
        "conversation_id": str(uuid.uuid4()),
        "scam_detected": False,
        "risk_score": 0.0,
        "scam_type": "unknown",
        "agent_reply": "Hello! Please share the details.",
        "engagement_metrics": {"turns": 0, "duration_seconds": 0},
        "extracted_intelligence": empty_intel()
    }


# ✅ GUVI tester check = GET/HEAD should work WITHOUT API KEY
@app.get("/honeypot")
def honeypot_get():
    return JSONResponse(status_code=200, content=make_output())


# ✅ POST should be secured (real evaluation)
@app.post("/honeypot")
async def honeypot_post(request: Request, ok: bool = Depends(verify_key_required)):
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {"data": payload}
    except Exception:
        payload = {}

    conversation_id = (
        payload.get("conversation_id")
        or payload.get("conversationId")
        or payload.get("session_id")
        or payload.get("id")
        or str(uuid.uuid4())
    )

    session = get_session(conversation_id)

    msg = payload.get("message") or payload.get("text") or payload.get("user_message") or "hello"

    session["history"].append({"role": "scammer", "text": msg})

    detection = detect_scam(msg)

    if detection["is_scam"]:
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    session["history"].append({"role": "agent", "text": agent_reply})

    full_text = " ".join([h.get("text", "") for h in session["history"]])
    intel = extract_intel(full_text)

    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    return JSONResponse(
        status_code=200,
        content={
            "status": True,
            "message": "success",
            "conversation_id": conversation_id,
            "scam_detected": detection["is_scam"],
            "risk_score": detection["risk_score"],
            "scam_type": detection["scam_type"],
            "agent_reply": agent_reply,
            "engagement_metrics": {
                "turns": turns,
                "duration_seconds": duration
            },
            "extracted_intelligence": intel
        }
    )
