from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
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


def empty_intel():
    return {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "urls": [],
        "phone_numbers": []
    }


# ✅ IMPORTANT: Root endpoint must return 200 (NO API KEY REQUIRED)
@app.get("/")
def root():
    return {"status": True, "message": "Agentic Honeypot service is live"}


@app.get("/health")
def health():
    return {"status": True, "message": "ok"}


async def safe_payload(request: Request):
    try:
        js = await request.json()
        return js
    except Exception:
        pass

    try:
        form = await request.form()
        if form:
            return dict(form)
    except Exception:
        pass

    try:
        body = await request.body()
        if body:
            txt = body.decode("utf-8", errors="ignore").strip()
            if txt:
                return {"raw_text": txt}
    except Exception:
        pass

    return {}


def make_output(conversation_id: str, is_scam: bool, risk_score: float, scam_type: str,
                reply: str, turns: int, duration: int, intel: dict):
    return {
        "status": True,
        "message": "success",

        # main details
        "conversation_id": conversation_id,
        "scam_detected": is_scam,
        "risk_score": risk_score,
        "scam_type": scam_type,
        "agent_reply": reply,
        "engagement_metrics": {
            "turns": turns,
            "duration_seconds": duration
        },
        "extracted_intelligence": intel,

        # compatibility keys
        "is_scam": is_scam,
        "confidence": risk_score,
        "reply": reply,
        "intel": intel
    }


# ✅ GET /honeypot (with API key) for tester connectivity
@app.get("/honeypot")
def honeypot_get(ok: bool = Depends(verify_api_key)):
    out = make_output(
        conversation_id=str(uuid.uuid4()),
        is_scam=False,
        risk_score=0.0,
        scam_type="unknown",
        reply="Hello! Please share the details.",
        turns=0,
        duration=0,
        intel=empty_intel()
    )
    return JSONResponse(status_code=200, content=out)


# ✅ POST /honeypot (with API key) main endpoint
@app.post("/honeypot")
async def honeypot_post(request: Request, ok: bool = Depends(verify_api_key)):
    payload = await safe_payload(request)

    if not isinstance(payload, dict):
        payload = {"data": payload}

    conversation_id = (
        payload.get("conversation_id")
        or payload.get("conversationId")
        or payload.get("session_id")
        or payload.get("id")
        or str(uuid.uuid4())
    )

    session = get_session(conversation_id)

    msg = ""
    for k in ["message", "text", "msg", "input", "content", "user_message"]:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            msg = v.strip()
            break

    if not msg and isinstance(payload.get("event"), dict):
        evt = payload["event"]
        for k in ["message", "text", "content"]:
            v = evt.get(k)
            if isinstance(v, str) and v.strip():
                msg = v.strip()
                break

    if not msg:
        msg = "hello"

    session["history"].append({"role": "scammer", "text": msg})

    detection = detect_scam(msg)

    if detection["is_scam"]:
        agent_reply = generate_reply(session["history"])
    else:
        agent_reply = "Okay. Please share more details."

    session["history"].append({"role": "agent", "text": agent_reply})

    full_text = " ".join([h.get("text", "") for h in session["history"]])
    intel = extract_intel(full_text) if full_text else empty_intel()

    turns = len(session["history"])
    duration = int(time.time() - session["start_time"])

    out = make_output(
        conversation_id=conversation_id,
        is_scam=detection["is_scam"],
        risk_score=detection["risk_score"],
        scam_type=detection["scam_type"],
        reply=agent_reply,
        turns=turns,
        duration=duration,
        intel=intel
    )

    return JSONResponse(status_code=200, content=out)
