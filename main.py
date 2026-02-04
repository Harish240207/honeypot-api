from fastapi import FastAPI, Depends, Request
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
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


# Optional schema (GUVI may not follow exactly)
class HoneypotRequest(BaseModel):
    conversation_id: Optional[str] = None
    message: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None
    text: Optional[str] = None
    user_message: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


def pick_message(payload_dict: Dict[str, Any]) -> str:
    """
    GUVI / mock scammer might send different key names.
    We accept many possibilities.
    """
    if not payload_dict:
        return ""

    for k in ["message", "text", "user_message", "msg", "input"]:
        val = payload_dict.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()

    # sometimes nested
    evt = payload_dict.get("event")
    if isinstance(evt, dict):
        val = evt.get("message") or evt.get("text")
        if isinstance(val, str):
            return val.strip()

    return ""


def pick_conversation_id(payload_dict: Dict[str, Any]) -> str:
    for k in ["conversation_id", "conversationId", "session_id", "sessionId", "id"]:
        val = payload_dict.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return str(uuid.uuid4())


@app.post("/honeypot")
async def honeypot(request: Request, ok: bool = Depends(verify_api_key)):
    """
    Universal webhook to satisfy GUVI tester and mock scammer events.
    """
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    conversation_id = pick_conversation_id(payload)
    session = get_session(conversation_id)

    msg = pick_message(payload)

    # store scammer message
    if msg:
        session["history"].append({"role": "scammer", "text": msg})
    else:
        session["history"].append({"role": "scammer", "text": ""})

    detection = detect_scam(msg)

    # agent handoff
    if detection["is_scam"]:
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Can you share more details?"

    session["history"].append({"role": "agent", "text": agent_reply})

    # extraction
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
