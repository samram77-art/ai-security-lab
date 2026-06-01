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

## Notes

This lab is intentionally defensive and educational. The goal is to build repeatable security testing workflows, document results, and improve detection coverage over time.