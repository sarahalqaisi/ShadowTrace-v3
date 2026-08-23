# Threat-intelligence architecture

## Modes and trust boundary

`SHADOWTRACE_THREAT_INTEL_MODE=offline` is the deterministic default. No provider adapter is invoked and the response explicitly records `source: offline`. ShadowTrace never substitutes mock data when a live request fails.

`live` mode enables eligible adapters. The requested indicator is normalized before the privacy gate. Private, loopback, link-local, reserved, multicast, unspecified and documentation-range IPs, localhost, internal/reserved domains, and URLs using those hosts are rejected before provider execution. Provider destinations are fixed in code; an indicator cannot select a destination URL.

ShadowTrace does not resolve submitted domain names locally before a reputation lookup. This avoids making a direct connection to the indicator: the only outbound connections are to fixed provider hosts, and the indicator is encoded as provider API data or a path component. Internal/reserved suffixes and literal blocked IP hosts are still rejected locally.

## Provider protocol

Every adapter returns `ProviderResult` with provider name, status, configuration state, sanitized error category/message, source, and provider-specific data. The coordinator isolates partial failures. The established flattened `geo`, `abuseipdb`, and `virustotal` response objects remain available; normalized results are additive under `provider_results`.

Outbound HTTP requires fixed HTTPS provider URLs, certificate verification, disabled redirects, a configurable timeout, bounded response bytes, and a JSON object response. Secrets are read from environment-backed configuration and are never stored in cache payloads or returned to clients.

## Cache and execution model

The SQLite cache key includes provider, IOC type, and normalized indicator. Entries expire by TTL; expired rows are pruned and the table is capped by `SHADOWTRACE_THREAT_CACHE_MAX_ENTRIES`. The legacy aggregate caches remain for v3 API and map compatibility.

Provider execution remains synchronous. Each request is bounded, and failures are independent. A durable background queue is a future deployment concern: an in-process thread pool would not provide restart durability and would interact poorly with local SQLite across multiple WSGI workers.

## Operational limitations

Provider data is third-party context, not proof that an incident is malicious. Analysts must validate verdicts, timestamps, provider coverage, false positives, and retention obligations. Live provider integration tests require separately managed test credentials and are intentionally absent from offline CI.
