import re

def scam_score(text: str) -> float:
    text_l = (text or "").lower()

    keywords = [
        "upi", "account", "ifsc", "otp", "link", "verify", "verification",
        "kyc", "payment", "refund", "blocked", "bank", "transaction",
        "urgent", "click", "winner", "lottery", "parcel", "customs",
        "fedex", "loan", "job", "telegram", "whatsapp", "pay now"
    ]

    score = 0.0
    for k in keywords:
        if k in text_l:
            score += 0.07

    if re.search(r"https?://\S+", text_l):
        score += 0.30

    if re.search(r"\b\d{9,18}\b", text_l):
        score += 0.25

    if "otp" in text_l and re.search(r"\b\d{4,8}\b", text_l):
        score += 0.18

    return min(score, 1.0)

def detect_scam(text: str):
    score = scam_score(text)
    is_scam = score >= 0.35

    t = (text or "").lower()
    scam_type = "unknown"
    if "otp" in t:
        scam_type = "otp_scam"
    elif "upi" in t or "payment" in t:
        scam_type = "upi_payment_scam"
    elif "kyc" in t:
        scam_type = "kyc_scam"
    elif "http" in t or "link" in t:
        scam_type = "phishing_link_scam"

    return {
        "is_scam": is_scam,
        "risk_score": round(score, 2),
        "scam_type": scam_type
    }
