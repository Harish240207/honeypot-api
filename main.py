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

    for k in ["message", "text", "user_message", "msg", "input", "content"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    evt = payload.get("event")
    if isinstance(evt, dict):
        v = evt.get("message") or evt.get("text") or evt.get("content")
        if isinstance(v, str) and v.strip():
            return v.strip()

    return ""


def pick_conversation_id(payload: dict) -> str:
    if not payload:
        return str(uuid.uuid4())

    for k in ["conversation_id", "conversationId", "session_id", "sessionId", "id", "thread_id"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    return str(uuid.uuid4())


async def safe_get_payload(request: Request) -> dict:
    # 1) Try JSON
    try:
        js = await request.json()
        if isinstance(js, dict):
            return js
        return {"data": js}
    except Exception:
        pass

    # 2) Try form-data
    try:
        form = await request.form()
        if form:
            return dict(form)
    except Exception:
        pass

    # 3) Try raw text
    try:
        body = await request.body()
        if body:
            txt = body.decode("utf-8", errors="ignore").strip()
            if txt:
                return {"text": txt}
    except Exception:
        pass

    return {}


def minimal_output():
    """If GU attaching empty/invalid body, still return valid required response schema."""
    return {
        "conversation_id": str(uuid.uuid4()),
        "scam_detected": False,
        "risk_score": 0.0,
        "scam_type": "unknown",
        "agent_reply": "Hello! Please share the details.",
        "engagement_metrics": {"turns": 0, "duration_seconds": 0},
        "extracted_intelligence": {
            "upi_ids": [],
            "bank_accounts": [],
            "ifsc_codes": [],
            "urls": [],
            "phone_numbers": []
        }
    }


async def process_request(request: Request):
    payload = await safe_get_payload(request)

    conversation_id = pick_conversation_id(payload)
    session = get_session(conversation_id)

    msg = pick_message(payload)

    if not msg:
        msg = "hello"

    # store scammer msg
    session["history"].append({"role": "scammer", "text": msg})

    # detection
    detection = detect_scam(msg)

    # reply
    if detection["is_scam"]:
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    session["history"].append({"role": "agent", "text": agent_reply})

    # extract intel
    full_text = " ".join([h.get("text", "") for h in session["history"]])
    intel = extract_intel(full_text)

    # metrics
    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    # ✅ FLAT schema response
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


# ✅ Root endpoints
@app.get("/")
def root_get():
    return {"status": "ok", "message": "Honeypot service live"}


@app.post("/")
async def root_post(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_request(request)


# ✅ GUVI tester may send GET/POST
@app.get("/honeypot")
def honeypot_get(ok: bool = Depends(verify_api_key)):
    return minimal_output()


@app.post("/honeypot")
async def honeypot_post(request: Request, ok: bool = Depends(verify_api_key)):
    return await process_request(request)
