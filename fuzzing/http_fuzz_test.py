"""
HTTP Endpoint Fuzzer targeting OWASP Juice Shop
Fuzzes REST endpoints for crashes, injection flaws, and input validation issues.
Author: samsonram54
Target : http://localhost:3000 (OWASP Juice Shop via Docker)
"""

import requests
import json
from datetime import datetime
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

TARGET_URL = "http://localhost:3000"
REPORT = []

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
    "A" * 5000,
    # Null bytes
    "test\x00injection",
    # Format strings
    "%s%s%s%s%n",
    # JSON injection
    '{"email":"admin@juice-sh.op","password":"admin123"}',
    # NoSQL injection
    '{"$gt": ""}',
    # SSTI
    "{{7*7}}", "${7*7}",
]

# Juice Shop REST API endpoints worth fuzzing
ENDPOINTS = [
    "/",
    "/rest/user/login",
    "/rest/products/search",
    "/api/Users",
    "/api/Products",
    "/rest/basket/1",
    "/rest/user/whoami",
    "/api/Feedbacks",
    "/rest/qr-code",
    "/rest/admin/application-configuration",
]


def fuzz_endpoint(endpoint: str, payload: str) -> dict:
    url = TARGET_URL + endpoint
    result = {
        "endpoint": endpoint,
        "payload": payload[:80],
        "status": None,
        "anomaly": False,
        "note": "",
    }
    try:
        # Try GET with query params
        r = requests.get(
            url,
            params={"q": payload, "search": payload},
            timeout=5,
            allow_redirects=True,
        )
        result["status"] = r.status_code

        if r.status_code == 500:
            result["anomaly"] = True
            result["note"] = "500 Server Error — possible crash or unhandled exception"
        elif r.status_code == 200 and "error" in r.text.lower():
            result["anomaly"] = True
            result["note"] = "200 but contains error text — leaking debug info"
        elif len(r.text) == 0:
            result["anomaly"] = True
            result["note"] = "Empty response — unexpected behavior"
        elif "stack" in r.text.lower() or "traceback" in r.text.lower():
            result["anomaly"] = True
            result["note"] = "Stack trace leaked — information disclosure"

    except requests.exceptions.ConnectionError:
        result["status"] = "CONNECTION_ERROR"
        result["anomaly"] = True
        result["note"] = "Target unreachable — is Juice Shop running?"
    except requests.exceptions.Timeout:
        result["status"] = "TIMEOUT"
        result["anomaly"] = True
        result["note"] = "Possible DoS or time-based injection"

    return result


def run_manual_fuzz():
    print(f"\n{'=' * 62}")
    print(" AI SECURITY LAB — HTTP Fuzzer (OWASP Juice Shop)")
    print(f" Target    : {TARGET_URL}")
    print(f" Endpoints : {len(ENDPOINTS)}")
    print(f" Payloads  : {len(FUZZ_PAYLOADS)}")
    print(f" Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 62}\n")

    total = len(ENDPOINTS) * len(FUZZ_PAYLOADS)
    count = 0

    for endpoint in ENDPOINTS:
        for payload in FUZZ_PAYLOADS:
            count += 1
            result = fuzz_endpoint(endpoint, payload)
            REPORT.append(result)
            flag = "⚠️ " if result["anomaly"] else "   "
            print(
                f"[{count:>4}/{total}] {flag} {endpoint:<40} "
                f"{str(result['status']):<6} {result['note']}"
            )

    anomalies = [r for r in REPORT if r["anomaly"]]
    print(f"\n{'=' * 62}")
    print(f" RESULTS: {len(anomalies)}/{total} anomalies detected")
    print(f"{'=' * 62}\n")


@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=1, max_size=200))
def test_search_with_random_input(random_input: str):
    try:
        r = requests.get(
            TARGET_URL + "/rest/products/search",
            params={"q": random_input},
            timeout=3,
        )
        assert r.status_code != 500, f"Server crashed on: {random_input[:80]}"
    except requests.exceptions.ConnectionError:
        pass


if __name__ == "__main__":
    run_manual_fuzz()

    print("[*] Running Hypothesis property-based fuzzing on /rest/products/search...")
    try:
        test_search_with_random_input()
        print("[*] Hypothesis: No 500 errors on /rest/products/search\n")
    except Exception as e:
        print(f"[!] Hypothesis found an issue: {e}\n")

    report_path = f"fuzzing/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(REPORT, f, indent=2, ensure_ascii=False)
    print(f"[*] Report saved to: {report_path}")