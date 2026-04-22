# Architecture

This starter lab separates three concerns:

1. Payload input
2. Detection and filtering
3. Simulated response engine

The vulnerable engine intentionally leaks a simulated secret when it encounters certain prompt injection phrases. The defended flow checks for suspicious strings before allowing the request to continue.

Future versions can replace the simulated engine with a real LLM backend and structured output validation.
