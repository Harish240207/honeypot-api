from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import os
import uuid
import time
import json

from app.detector import detect_scam
from app.memory import get_session
from app.extractor import extract_intel
from app.agent_gemini import generate_reply

load_dotenv()

API_KEY = os.getenv("API_KEY", "harish_secret_key_123")

app = FastAPI(title="Agentic Honeypot API", version="1.0")


# ---------------------------
# Helpers
# ---------------------------
def empty_intel():
    return {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "urls": [],
        "phone_numbers": []
    }


def verify_key_required(x_api_key: str = Header(None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return True


def normalize_text(value) -> str:
    """Always return a safe string"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    # if dict/list/number etc => convert to string
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def pick_message(payload: dict) -> str:
    if not payload:
        return ""

    # common keys
    for k in ["message", "text", "user_message", "msg", "input", "content"]:
        if k in payload:
            v = payload.get(k)
            v = normalize_text(v)
            if v:
                return v

    # nested event
    evt = payload.get("event")
    if isinstance(evt, dict):
        for k in ["message", "text", "content"]:
            if k in evt:
                v = normalize_text(evt.get(k))
                if v:
                    return v

    return ""


async def safe_payload(request: Request):
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {"data": data}
    except Exception:
        pass

    try:
        b = await request.body()
        if b:
            return {"raw_text": b.decode("utf-8", errors="ignore")}
    except Exception:
        pass

    return {}


def make_basic_output():
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


# ---------------------------
# Root endpoints (GUVI tester hits '/')
# ---------------------------
@app.head("/")
def root_head():
    return JSONResponse(status_code=200, content={})


@app.get("/")
def root_get(ok: bool = Depends(verify_key_required)):
    return JSONResponse(status_code=200, content=make_basic_output())


@app.get("/health")
def health():
    return {"status": True, "message": "ok"}


# ---------------------------
# Honeypot endpoints
# ---------------------------
@app.head("/honeypot")
def honeypot_head():
    return JSONResponse(status_code=200, content={})


@app.get("/honeypot")
def honeypot_get(ok: bool = Depends(verify_key_required)):
    return JSONResponse(status_code=200, content=make_basic_output())


@app.post("/honeypot")
async def honeypot_post(request: Request, ok: bool = Depends(verify_key_required)):
    payload = await safe_payload(request)

    # conversation id
    conversation_id = (
        payload.get("conversation_id")
        or payload.get("conversationId")
        or payload.get("session_id")
        or payload.get("sessionId")
        or payload.get("id")
        or str(uuid.uuid4())
    )

    session = get_session(conversation_id)

    msg = pick_message(payload)
    if not msg:
        msg = "hello"

    # ensure msg is always string
    msg = normalize_text(msg)

    session["history"].append({"role": "scammer", "text": msg})

    # ✅ Now detect_scam always receives string
    detection = detect_scam(msg)

    if detection.get("is_scam"):
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    session["history"].append({"role": "agent", "text": agent_reply})

    full_text = " ".join([normalize_text(h.get("text", "")) for h in session["history"]])
    intel = extract_intel(full_text) if full_text else empty_intel()

    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    return JSONResponse(
        status_code=200,
        content={
            "status": True,
            "message": "success",
            "conversation_id": conversation_id,
            "scam_detected": detection.get("is_scam", False),
            "risk_score": detection.get("risk_score", 0.0),
            "scam_type": detection.get("scam_type", "unknown"),
            "agent_reply": agent_reply,
            "engagement_metrics": {"turns": turns, "duration_seconds": duration},
            "extracted_intelligence": intel
        }
    )


# ✅ Bonus: accept POST / too (sometimes evaluation sends root)
@app.post("/")
async def root_post(request: Request, ok: bool = Depends(verify_key_required)):
    return await honeypot_post(request, ok)
