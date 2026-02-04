import time

SESSIONS = {}

def get_session(conversation_id: str):
    if conversation_id not in SESSIONS:
        SESSIONS[conversation_id] = {
            "start_time": time.time(),
            "history": []
        }
    return SESSIONS[conversation_id]
