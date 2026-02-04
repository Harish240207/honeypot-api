import re
import json


# ✅ Common scam patterns
SCAM_KEYWORDS = [
    "upi", "gpay", "phonepe", "paytm",
    "otp", "verification code", "cvv",
    "bank", "account", "ifsc",
    "investment", "double your money", "loan",
    "refund", "reward", "prize", "lottery",
    "click link", "urgent", "limited time",
    "kyc", "aadhaar", "pan",
    "send money", "transfer", "payment",
]

SCAM_TYPES = {
    "upi_fraud": ["upi", "gpay", "phonepe", "paytm"],
    "otp_scam": ["otp", "verification code", "code"],
    "banking_fraud": ["bank", "account", "ifsc", "cvv"],
    "investment_scam": ["investment", "double your money", "profit"],
    "refund_scam": ["refund", "reward", "prize", "lottery"],
    "link_phishing": ["click link", "http", "www", ".com", ".in"],
    "kyc_scam": ["kyc", "aadhaar", "pan"],
}


def safe_text(value) -> str:
    """
    ✅ Converts ANY input into safe string.
    Fixes crashes caused by dict/list/int inputs.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def scam_score(text) -> float:
    """
    ✅ Returns risk score between 0 and 1
    """
    text = safe_text(text).lower().strip()

    if not text:
        return 0.0

    score = 0

    # Keyword match scoring
    for keyword in SCAM_KEYWORDS:
        if keyword in text:
            score += 1

    # Bonus score for suspicious patterns
    upi_pattern = r"\b[a-zA-Z0-9.\-_]{3,}@[a-zA-Z]{2,}\b"
    phone_pattern = r"\b[6-9]\d{9}\b"
    url_pattern = r"(http[s]?://|www\.)"

    if re.search(upi_pattern, text):
        score += 2
    if re.search(phone_pattern, text):
        score += 1
    if re.search(url_pattern, text):
        score += 1

    # normalize
    normalized = min(score / 8, 1.0)
    return round(normalized, 2)


def detect_scam(message):
    """
    ✅ Safe scam detector function that never crashes
    """
    msg = safe_text(message)
    text = msg.lower().strip()

    score = scam_score(text)

    # scam threshold
    is_scam = score >= 0.35

    scam_type = "unknown"
    if is_scam:
        for t, keys in SCAM_TYPES.items():
            if any(k in text for k in keys):
                scam_type = t
                break

    return {
        "is_scam": is_scam,
        "risk_score": score,
        "scam_type": scam_type
    }
