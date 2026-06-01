"""
HTTP Endpoint Fuzzer using boofuzz + hypothesis
Fuzzes a local web API for crashes, unexpected responses, and input validation flaws.
Author: samsonram54
"""

import requests
import json
from datetime import datetime
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

TARGET_URL = "http://localhost:5000"  # change to your target
REPORT = []

# ── boofuzz-style manual HTTP fuzzing ──────────────────────────────────────

FUZZ_PAYLOADS = [
    # SQL Injection
    "' OR '1'='1", "'; DROP TABLE users;--", "1' AND SLEEP(5)--",
    # XSS
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    # Path traversal
    "../../../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Command injection
    "; ls -la", "| whoami", "& net user",
    # Oversized input
    "A" * 10000,
    # Null bytes
    "test\x00injection",
    # Format strings
    "%s%s%s%s%s%n",
    # JSON injection
    '{"key": "value", "admin": true}',
]

ENDPOINTS = [
    "/",
    "/api/user",
    "/api/login",
    "/search",
    "/admin",
]

def fuzz_endpoint(endpoint: str, payload: str) -> dict:
    url = TARGET_URL + endpoint
    result = {"endpoint": endpoint, "payload": payload[:80], "status": None, "anomaly": False, "note": ""}
    try:
        r = requests.get(url, params={"q": payload, "input": payload}, timeout=5)
        result["status"] = r.status_code
        if r.status_code in [500, 502, 503]:
            result["anomaly"] = True
            result["note"] = "Server error — possible crash or unhandled exception"
        elif len(r.text) == 0:
            result["anomaly"] = True
            result["note"] = "Empty response — unexpected behavior"
    except requests.exceptions.ConnectionError:
        result["status"] = "CONNECTION_ERROR"
        result["anomaly"] = True
        result["note"] = "Target unreachable or crashed"
    except requests.exceptions.Timeout:
        result["status"] = "TIMEOUT"
        result["anomaly"] = True
        result["note"] = "Possible DoS or time-based injection"
    return result

def run_manual_fuzz():
    print(f"\n{'='*60}")
    print(" AI SECURITY LAB — HTTP Fuzzer")
    print(f" Target    : {TARGET_URL}")
    print(f" Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    total = len(ENDPOINTS) * len(FUZZ_PAYLOADS)
    count = 0
    for endpoint in ENDPOINTS:
        for payload in FUZZ_PAYLOADS:
            count += 1
            result = fuzz_endpoint(endpoint, payload)
            REPORT.append(result)
            flag = "⚠️ " if result["anomaly"] else "   "
            print(f"[{count:>3}/{total}] {flag} {endpoint:<20} {str(result['status']):<6} {result['note']}")

    anomalies = [r for r in REPORT if r["anomaly"]]
    print(f"\n{'='*60}")
    print(f" RESULTS: {len(anomalies)}/{total} anomalies detected")
    print(f"{'='*60}\n")

# ── hypothesis property-based fuzzing ──────────────────────────────────────

@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=1, max_size=500))
def test_search_with_random_input(random_input: str):
    try:
        r = requests.get(TARGET_URL + "/search", params={"q": random_input}, timeout=3)
        assert r.status_code != 500, f"Server crashed on input: {random_input[:100]}"
    except requests.exceptions.ConnectionError:
        pass

# ── entrypoint ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_manual_fuzz()

    print("[*] Running Hypothesis property-based fuzzing on /search...")
    try:
        test_search_with_random_input()
        print("[*] Hypothesis: No crashes detected on /search\n")
    except Exception as e:
        print(f"[!] Hypothesis found an issue: {e}\n")

    report_path = f"fuzzing/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(REPORT, f, indent=2)
    print(f"[*] Report saved to: {report_path}")