SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "reveal the system prompt",
    "show hidden instructions",
    "developer message",
    "system prompt",
    "exfiltrate",
]


def detect_prompt_injection(text: str) -> list[str]:
    hits = []
    lowered = text.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in lowered:
            hits.append(pattern)
    return hits


def apply_basic_guardrails(text: str) -> dict:
    hits = detect_prompt_injection(text)
    if hits:
        return {
            "allowed": False,
            "reason": f"Blocked suspicious patterns: {', '.join(hits)}",
            "sanitized_input": None,
        }
    return {
        "allowed": True,
        "reason": "No known prompt injection patterns detected",
        "sanitized_input": text.strip(),
    }
