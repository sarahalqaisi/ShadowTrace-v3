# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not include API keys, evidence, production indicators, or other sensitive data in a public issue. Include a minimal reproduction, affected revision, and impact where possible.

## Deployment boundary

ShadowTrace is a portfolio/reference DFIR application, not a turnkey internet-facing SOC platform. The built-in session login provides a small local analyst workflow, but production deployment still requires centralized identity, stronger RBAC, rate limiting, monitoring, encrypted backups, secret management, retention controls, and a reviewed HTTPS reverse proxy. Treat imported evidence and provider results as sensitive.

External enrichment is opt-in through `SHADOWTRACE_THREAT_INTEL_MODE=live`. Review provider privacy, contractual, regional, and retention requirements before sending any indicator.
