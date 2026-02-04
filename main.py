from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import uuid

load_dotenv()

app = FastAPI(title="GUVI Honeypot Debug API", version="debug")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(path: str, request: Request):
    raw = await request.body()
    headers = dict(request.headers)

    print("\n================ GUVI DEBUG =================")
    print("METHOD:", request.method)
    print("PATH:", "/" + path)
    print("HEADERS:", headers)
    print("RAW_BODY_BYTES:", raw)
    try:
        print("RAW_BODY_TEXT:", raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    print("=============================================\n")

    # Always return a stable JSON
    return JSONResponse(
        status_code=200,
        content={
            "status": True,
            "message": "debug ok",
            "conversation_id": str(uuid.uuid4()),
            "scam_detected": False,
            "risk_score": 0.0,
            "scam_type": "unknown",
            "agent_reply": "hello"
        }
    )
