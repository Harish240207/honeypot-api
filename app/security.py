from fastapi import Header, HTTPException
import os

def verify_api_key(
    x_api_key: str = Header(None),
    authorization: str = Header(None)
):
    expected = os.getenv("API_KEY")

    # 1) Check X-API-KEY
    if x_api_key and x_api_key == expected:
        return True

    # 2) Check Authorization: Bearer <key>
    if authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            if token == expected:
                return True

    raise HTTPException(status_code=401, detail="Invalid API Key")
