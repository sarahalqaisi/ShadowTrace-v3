# Validation

This document describes reproducible checks, not a permanent claim that a future revision has passed them. Run validation on the exact revision under review.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q dashboard parsers scripts correlation-engine tests
python -m pip_audit --requirement requirements.txt
git diff --check
```

The suite covers authentication, security headers, dashboard/API compatibility, IOC normalization and privacy eligibility, provider isolation and HTTP limits, bounded provider-aware caching, evidence fingerprints, correlation pivots, workflow auditing, reports, and additive legacy-database migration.

CI runs in explicit offline mode and must not receive live provider keys. Live-provider behavior still requires controlled integration validation with separately managed credentials. Docker validation requires a local Docker engine.
