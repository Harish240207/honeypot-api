from fastapi import FastAPI, Depends, Request
import time
import uuid
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
    return {"status": "ok"}


def pick_message(payload: dict) -> str:
    if not payload:
        return ""
    for k in ["message", "text", "user_message", "msg", "input"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    evt = payload.get("event")
    if isinstance(evt, dict):
        v = evt.get("message") or evt.get("text")
        if isinstance(v, str):
            return v.strip()
    return ""


def pick_conversation_id(payload: dict) -> str:
    for k in ["conversation_id", "conversationId", "session_id", "sessionId", "id"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return str(uuid.uuid4())


async def process_honeypot_request(request: Request):
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    conversation_id = pick_conversation_id(payload)
    session = get_session(conversation_id)

    msg = pick_message(payload)

    # add scammer message
    session["history"].append({"role": "scammer", "text": msg})

    # detection
    detection = detect_scam(msg)

    # agent reply
    if detection["is_scam"]:
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    session["history"].append({"role": "agent", "text": agent_reply})

    full_text = " ".join([h.get("text", "") for h in session["history"]])
    intel = extract_intel(full_text)

    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    return {
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


# ✅ Root endpoint (GUVI safe)
@app.post("/")
async def root_post(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_honeypot_request(request)

@app.get("/")
def root_get():
    return {"status": "ok", "message": "Honeypot service live"}


# ✅ Main endpoint
@app.post("/honeypot")
async def honeypot(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_honeypot_request(request)
