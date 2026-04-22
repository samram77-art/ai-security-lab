# AI Security Lab

A hands-on lab for learning and demonstrating prompt injection risks, LLM guardrail bypasses, and practical defensive patterns for GenAI applications.

## Why this project
This repo is designed to help security researchers, AI engineers, and pentesters understand how prompt injection works in real workflows. It includes a vulnerable mode, a defended mode, reusable attack payloads, and sample validation logic.

## Features
- Vulnerable prompt-processing flow for testing attacks
- Defended mode with basic filtering and policy checks
- Payload library for direct and indirect prompt injection
- Simple JSON-based result logging
- Starter tests and documentation

## Repo structure
```text
ai-security-lab/
├── app/
│   ├── main.py
│   ├── filters.py
│   └── scenarios.py
├── payloads/
│   ├── direct_ignore.txt
│   ├── direct_exfil.txt
│   └── indirect_markdown.txt
├── docs/
│   ├── architecture.md
│   └── roadmap.md
├── tests/
│   └── test_filters.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app/main.py --mode vulnerable --payload payloads/direct_ignore.txt
python app/main.py --mode defended --payload payloads/direct_ignore.txt
```

## Example use cases
- Demonstrate direct prompt injection
- Compare vulnerable vs defended handling
- Expand the payload corpus for research
- Add LLM API integration later

## Notes
This starter project uses a simulated engine so you can publish it safely without depending on paid APIs. You can later integrate OpenAI-compatible, Ollama, or local model backends.

## Roadmap
- Add real LLM provider adapters
- Add HTML report output
- Add attack scoring dashboard
- Add RAG poisoning scenarios

## Disclaimer
Use this project only for legal, authorized security research and education.
