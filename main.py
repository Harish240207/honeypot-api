from fastapi import FastAPI, Depends, Request
import time
import uuid
import json
from dotenv import load_dotenv

from app.security import verify_api_key
from app.detector import detect_scam
from app.memory import get_session
from app.extractor import extract_intel
from app.agent_gemini import generate_reply

load_dotenv()

app = FastAPI(title="Agentic Honeypot API", version="1.0")


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


def to_string(value):
    """✅ Convert anything to safe string (fixes dict.lower crash)"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    # if dict/list/number -> convert to JSON string
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def pick_message(payload: dict) -> str:
    """✅ Robust extractor for GUVI / unknown payload structures"""
    if not payload:
        return ""

    # normal possible keys
    for k in ["message", "text", "user_message", "msg", "input", "content"]:
        if k in payload:
            v = payload.get(k)
            s = to_string(v)
            if s:
                return s

    # nested event/message
    evt = payload.get("event")
    if isinstance(evt, dict):
        for k in ["message", "text", "content"]:
            if k in evt:
                s = to_string(evt.get(k))
                if s:
                    return s

    # fallback: stringify entire payload
    return to_string(payload)


def pick_conversation_id(payload: dict) -> str:
    if not payload:
        return str(uuid.uuid4())
    for k in ["conversation_id", "conversationId", "session_id", "sessionId", "id", "thread_id"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return str(uuid.uuid4())


async def safe_get_payload(request: Request) -> dict:
    """✅ GUVI safe: handles json/form/raw/empty bodies"""
    # JSON
    try:
        js = await request.json()
        if isinstance(js, dict):
            return js
        return {"data": js}
    except Exception:
        pass

    # form-data
    try:
        form = await request.form()
        if form:
            return dict(form)
    except Exception:
        pass

    # raw text
    try:
        body = await request.body()
        if body:
            txt = body.decode("utf-8", errors="ignore").strip()
            if txt:
                return {"text": txt}
    except Exception:
        pass

    return {}


async def process_request(request: Request):
    payload = await safe_get_payload(request)

    conversation_id = pick_conversation_id(payload)
    session = get_session(conversation_id)

    msg = pick_message(payload)
    msg = to_string(msg)

    if not msg:
        msg = "hello"

    session["history"].append({"role": "scammer", "text": msg})

    # ✅ now msg is ALWAYS a string -> no crash
    detection = detect_scam(msg)

    if detection.get("is_scam"):
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    agent_reply = to_string(agent_reply)

    session["history"].append({"role": "agent", "text": agent_reply})

    full_text = " ".join([to_string(h.get("text")) for h in session["history"]]).strip()
    intel = extract_intel(full_text) if full_text else empty_intel()

    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    full_result = {
        "conversation_id": conversation_id,
        "scam_detected": bool(detection.get("is_scam")),
        "risk_score": float(detection.get("risk_score", 0.0)),
        "scam_type": detection.get("scam_type", "unknown"),
        "agent_reply": agent_reply,
        "engagement_metrics": {
            "turns": turns,
            "duration_seconds": duration
        },
        "extracted_intelligence": intel
    }

    # ✅ GUVI TESTER SAFE RESPONSE FORMAT
    return {
        "status": True,
        "message": "Honeypot endpoint working",
        "result": full_result
    }


# ✅ Root endpoints
@app.get("/")
def root_get():
    return {"status": True, "message": "Honeypot service live"}


@app.post("/")
async def root_post(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_request(request)


# ✅ GET /honeypot for tester connectivity
@app.get("/honeypot")
def honeypot_get(ok: bool = Depends(verify_api_key)):
    return {
        "status": True,
        "message": "Honeypot endpoint reachable",
        "result": {
            "conversation_id": str(uuid.uuid4()),
            "scam_detected": False,
            "risk_score": 0.0,
            "scam_type": "unknown",
            "agent_reply": "Hello! Please share the details.",
            "engagement_metrics": {"turns": 0, "duration_seconds": 0},
            "extracted_intelligence": empty_intel()
        }
    }


# ✅ POST /honeypot main endpoint
@app.post("/honeypot")
async def honeypot_post(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_request(request)
