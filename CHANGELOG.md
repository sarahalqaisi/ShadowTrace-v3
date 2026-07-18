# ShadowTrace v3 — Upgrade Summary

## Architecture and cleanup

- Reorganized the Flask project into application, configuration, database, routes, services, templates, and static layers.
- Removed the bundled virtual environment, Git metadata, duplicate backups, bytecode, generated reports, and local secrets from the distributable package.
- Added safe additive SQLite migration and schema-version metadata while preserving legacy records.
- Added WAL mode, busy timeout, indexes, and normalized timestamps.

## IOC intelligence and correlation

- Added deterministic extraction and normalization for IP, domain, URL, MD5, SHA-1, SHA-256, and email indicators.
- Added `iocs`, `ioc_intel_cache`, and `ioc_lookup_history` tables with incident relationships and lookup auditing.
- Added a dedicated IOC Lookup page and authenticated API.
- Added IOC Correlation inside incident investigations.
- Added Similar Incidents ranking using shared IOCs, ATT&CK techniques, and endpoints, with explainable reasons.
- Added an explainable stored Threat Score and minimum-score filtering.

## Threat intelligence

- Expanded VirusTotal enrichment to IPs, domains, URLs, and file hashes.
- Added AbuseIPDB checks for public IPs.
- Added GeoIP enrichment through IPWhois.
- Added provider error isolation, configurable timeouts, generic IOC caching, and compatibility with the earlier IP cache.
- Added safeguards that prevent private and non-routable IP ranges from leaving the application.

## Dashboard and frontend

- Added a responsive dark SOC dashboard and mobile navigation.
- Added charts for severity, status, evidence source, incident trends, and countries.
- Added a Leaflet world map backed by cached public-IP intelligence.
- Added country statistics, IOC quick lookup, Threat Score display, and priority filtering.
- Added toast notifications, a global loading overlay, loading states, improved empty states, and responsive investigation panels.
- Added IOC Correlation and Similar Incidents sections to every incident page.

## Investigation workflow

- Added MITRE ATT&CK and Cyber Kill Chain context.
- Added analyst assignment, incident status workflow, notes, detailed evidence views, timeline reconstruction, recommendations, per-incident activity, and a searchable admin audit log.
- Updated the standalone correlation engine to persist Threat Scores, synchronize IOCs, build timelines, and write activity records.

## Reports and exports

- Added detailed per-incident PDF, CSV, and JSON reports.
- Added filtered incident-queue PDF, CSV, and JSON exports.
- Included IOCs, Threat Score, threat intelligence, timeline, Similar Incidents, notes, and activity in detailed reports.

## Database and demonstration data

- Added all v3 tables, columns, indexes, relationships, caches, and schema metadata.
- Added an idempotent `scripts/seed_data.py` loader with `--reset` support.
- Added five clearly labelled synthetic demonstration incidents with shared IOCs, multiple severity levels, ATT&CK mappings, cached locations, and realistic investigation timelines.

## Security and reliability

- Added CSRF protection, hardened session cookies, parameterized SQL, upload/input limits, safe redirect handling, and non-debug startup.
- Added CSP, clickjacking protection, MIME sniffing protection, referrer policy, and restrictive browser permissions.
- Removed inline JavaScript handlers that conflicted with CSP.
- Added graceful operation when provider keys or external services are unavailable.

## Verification

- Added twelve automated application and migration tests.
- Validated all main UI/API/report routes against the bundled database.
- Validated the standalone correlation engine and data-preserving legacy migration.
- Added compilation, static security-pattern, archive-integrity, and secret-exclusion checks.

## v3.0.1 — Kali setup fix

- Added `setup_kali.sh`, which always runs from the project root and avoids accidentally installing an unrelated `~/requirements.txt`.
- Added Python version and virtual-environment checks with actionable Kali package guidance.
- Added automatic `.env` creation with a generated random secret while preserving existing configuration.
- Clarified that all manual setup commands must be run inside the extracted project directory.
- Verified the seven production dependencies install successfully on Python 3.13.5.
