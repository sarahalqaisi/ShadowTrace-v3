# Contributing

Create a focused branch and keep security-sensitive changes small enough to review. Never commit `.env`, API keys, incident databases, real evidence, generated reports, or provider responses.

Before opening a pull request, run:

```bash
python -m pytest -q
python -m compileall -q dashboard parsers scripts correlation-engine tests
python -m pip_audit --requirement requirements.txt
git diff --check
```

Provider changes must retain fixed HTTPS destinations, explicit timeouts, disabled redirects, response-size limits, sanitized client errors, offline tests, and private/reserved-indicator tests. Schema changes must be additive and preserve legacy databases.
