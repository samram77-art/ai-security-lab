import argparse
import json
from pathlib import Path

from filters import apply_basic_guardrails
from scenarios import vulnerable_engine, defended_engine


def load_payload(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def run(mode: str, payload_path: str) -> dict:
    payload = load_payload(payload_path)
    if mode == "vulnerable":
        return vulnerable_engine(payload)

    guardrail_result = apply_basic_guardrails(payload)
    if not guardrail_result["allowed"]:
        return {
            "mode": "defended",
            "status": "blocked",
            "response": guardrail_result["reason"],
        }
    return defended_engine(guardrail_result["sanitized_input"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Lab starter")
    parser.add_argument("--mode", choices=["vulnerable", "defended"], required=True)
    parser.add_argument("--payload", required=True)
    args = parser.parse_args()

    result = run(args.mode, args.payload)
    print(json.dumps(result, indent=2))
