# AI Security Lab

A hands-on AI red teaming and security research lab for testing prompt injection, binary analysis, and fuzzing workflows.

## Overview

This repository contains isolated Python environments and starter scripts for:
- AI/LLM prompt injection testing with a local Ollama model.
- Binary analysis with `r2pipe` and `radare2`.
- HTTP fuzzing with `boofuzz` and `hypothesis`.

## Lab Structure

| Module | Purpose | Key Tools |
|---|---|---|
| `pyrit/` | Prompt injection testing | OpenAI-compatible client, Ollama |
| `radare2/` | Binary analysis | `r2pipe`, `radare2` |
| `fuzzing/` | HTTP fuzzing | `boofuzz`, `hypothesis` |

## Setup

### PyRIT / Prompt Injection
```powershell
.\pyrit\.venv\Scripts\activate
python pyrit\prompt_injection_test.py
```

### Binary Analysis
```powershell
.\radare2\.venv\Scripts\activate
python radare2\binary_analysis.py <path-to-binary>
```

### HTTP Fuzzing
```powershell
.\fuzzing\.venv\Scripts\activate
python fuzzing\http_fuzz_test.py
```

## Ollama Configuration

The prompt injection lab uses a local Ollama model through an OpenAI-compatible endpoint.

`.env`:
```env
LLM_ENDPOINT=http://localhost:11434/v1
MODEL_NAME=llama3.2:3b
OPENAI_API_KEY=ollama
```

Start the model before running the script:

```powershell
ollama run llama3.2:3b
```

## Prompt Injection Results

Model tested:
- `llama3.2:3b` via Ollama on a local Windows machine

Test summary:
- Total payloads tested: 8
- Vulnerabilities detected: 5/8
- Report saved to: `pyrit/report_20260601_083944.json`

### Notable Findings
- A basic jailbreak payload returned `PWNED`.
- A developer-mode prompt caused the model to comply with unsafe instructions.
- The detection logic was improved after a false negative was identified.

## Files Generated

- `pyrit/prompt_injection_test.py`
- `pyrit/report_20260601_082550.json`
- `pyrit/report_20260601_083944.json`
- `radare2/binary_analysis.py`
- `fuzzing/http_fuzz_test.py`

## Next Steps

Planned additions:
- Juice Shop target for `fuzzing/http_fuzz_test.py`
- Expanded injection payload set for prompt testing
- Real binary test samples for `radare2/binary_analysis.py`

## Juice Shop Target

Juice Shop can be run locally with Docker:

```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Then update `TARGET_URL` in `fuzzing/http_fuzz_test.py` to:

```python
TARGET_URL = "http://localhost:3000"
```

## HTTP Fuzzing Results — OWASP Juice Shop

**Target:** OWASP Juice Shop (Docker — `bkimminich/juice-shop`)
**Date:** 2026-06-01
**Tool:** `fuzzing/http_fuzz_test.py`
**Engine:** `requests` + `hypothesis` property-based fuzzing

| Metric | Result |
|---|---|
| Total tests run | 170 (10 endpoints × 17 payloads) |
| Anomalies detected | 90/170 (53%) |
| Hypothesis crashes found | 1 (`/rest/products/search`) |
| Report | `fuzzing/report_20260601_111729.json` |

### Findings by Endpoint

| Endpoint | Status | Finding | Severity |
|---|---|---|---|
| `/` | 200 | Error text in response — debug info leaking | Medium |
| `/rest/user/login` | 500 | Crashes on all injection payloads — no sanitization | High |
| `/rest/products/search` | 200/500 | Mixed crashes + Hypothesis DoS confirmed | High |
| `/api/Users` | 401 | Stack trace leaked on every request | High |
| `/rest/basket/1` | 401 | Stack trace leaked — information disclosure | High |
| `/rest/qr-code` | 500 | Crashed on every single payload — fully unprotected | Critical |
| `/rest/admin/application-configuration` | 200/500 | Mixed — some payloads trigger server errors | Medium |

### Notable Findings

- **`/rest/qr-code`** returned HTTP 500 on all 17 payloads — zero input validation
- **`/api/Users` and `/rest/basket/1`** leaked stack traces on 401 responses — internal path disclosure
- **`/rest/user/login`** returned 500 on SQL injection, command injection, and oversized input
- **Hypothesis** (property-based fuzzer) independently confirmed `/rest/products/search` crashes on random string input — potential DoS vector
- Root cause: Juice Shop intentionally lacks input sanitization to simulate real-world vulnerable apps

## Binary Analysis Results — notepad.exe

**Target:** `radare2/samples/notepad.exe` (Windows System Binary)
**Date:** 2026-06-01
**Tool:** `radare2/binary_analysis.py`
**Engine:** r2pipe + radare2 6.1.4

| Metric | Result |
|---|---|
| Format | PE (Windows Executable) |
| Architecture | x86 / 64-bit |
| Symbols Stripped | No — debug symbols present |
| Functions Identified | 336 |
| Dangerous APIs Found | 9 |
| Report | `radare2/report_20260601_114814.json` |

### Security Mitigations

| Protection | Status | Risk |
|---|---|---|
| Stack Canary | ✅ Enabled | Buffer overflow detection active |
| NX / DEP | ⚠️ Disabled | Stack/heap memory is executable |
| PIE / ASLR | ⚠️ Disabled | Binary loads at fixed address — predictable |
| RELOCS | ⚠️ None | No address randomization support |

### Dangerous APIs Identified

| API | Risk |
|---|---|
| `GetProcAddress` | Dynamic function resolution — used in code injection |
| `LoadLibraryExW` | Loads external DLLs at runtime — DLL hijacking risk |
| `ShellExecuteW` | Can launch external processes |
| `GetStartupInfoW` | Leaks process startup context |
| `GetSystemTimeAsFileTime` | Runtime info disclosure |
| `WindowsGetStringRawBuffer` | Direct memory buffer access |

### Key Finding
NX and PIE both disabled means the binary loads at a **fixed, predictable memory address** with **executable stack/heap** — a significant attack surface for memory corruption exploits on older Windows versions.

## Notes

This lab is intentionally defensive and educational. The goal is to build repeatable security testing workflows, document results, and improve detection coverage over time.