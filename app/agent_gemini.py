import os
import google.generativeai as genai

MODEL_NAME = "gemini-1.5-flash"

SYSTEM_PROMPT = """
You are an AI honeypot agent acting as a real human victim chatting with a scammer.

Main goal: extract actionable intelligence:
- UPI ID
- bank account number
- IFSC code
- phishing URL

Rules:
- NEVER reveal you are AI or detecting scam.
- Be believable: Indian English + occasional Tamil slang.
- Ask strategic questions to force scammer to send payment details.
- Keep replies short (1-2 lines).
- If scammer gives vague response, ask again clearly.
"""

def _fallback():
    return "Ok bro. Please resend details—UPI ID / account number and IFSC / payment link."

def generate_reply(history):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _fallback()

    try:
        genai.configure(api_key=api_key)

        convo_text = ""
        for h in history[-12:]:
            role = h.get("role", "unknown")
            text = h.get("text", "")
            convo_text += f"{role.upper()}: {text}\n"

        prompt = SYSTEM_PROMPT + "\n\nConversation:\n" + convo_text + "\nAGENT:"

        model = genai.GenerativeModel(MODEL_NAME)
        res = model.generate_content(prompt)

        text = (res.text or "").strip()
        if not text:
            return _fallback()

        # Keep it short (optional)
        if len(text) > 250:
            text = text[:250].rsplit(" ", 1)[0] + "..."

        return text

    except Exception:
        return _fallback()
