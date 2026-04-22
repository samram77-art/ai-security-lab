def vulnerable_engine(user_input: str) -> dict:
    simulated_secret = "SYSTEM_PROMPT=internal-policy-do-not-disclose"
    if "system prompt" in user_input.lower() or "hidden instructions" in user_input.lower():
        return {
            "mode": "vulnerable",
            "status": "compromised",
            "response": f"Leaked sensitive context: {simulated_secret}",
        }
    return {
        "mode": "vulnerable",
        "status": "processed",
        "response": f"Processed user request: {user_input}",
    }


def defended_engine(user_input: str) -> dict:
    return {
        "mode": "defended",
        "status": "processed",
        "response": "Request handled with defensive policy. No hidden instructions will be disclosed.",
    }
