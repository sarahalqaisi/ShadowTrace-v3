# ShadowTrace v3

ShadowTrace v3 is a defensive SOC and Blue Team investigation platform built with Flask and SQLite. It turns network, host, and file evidence into searchable incidents, correlates indicators of compromise (IOCs), enriches public indicators with optional threat-intelligence providers, maps activity to MITRE ATT&CK and the Cyber Kill Chain, and produces analyst-ready reports.

## Main capabilities

### Investigation and correlation

- Incident queue with full-text search, filters, date ranges, minimum Threat Score, sorting, and server-side pagination
- Deterministic IOC extraction and normalization for IPv4/IPv6, domains, URLs, MD5, SHA-1, SHA-256, and email addresses
- IOC correlation across incidents, evidence, endpoints, and techniques
- Similar Incidents ranking with explainable reasons and shared indicators
- Stored, explainable Threat Score for prioritization and auditing
- Reconstructed incident timeline from Suricata, Auditd, and YARA evidence
- MITRE ATT&CK technique mapping and Cyber Kill Chain phase mapping
- Analyst assignment, workflow status, notes, activity history, and admin audit log

### Threat intelligence

- Dedicated IOC Lookup workspace and JSON API
- VirusTotal support for public IPs, domains, URLs, and file hashes
- AbuseIPDB reputation checks for public IP addresses
- GeoIP enrichment through IPWhois for public IP addresses
- Provider isolation, timeouts, SQLite caching, and graceful operation without API keys
- Privacy safeguards: private, loopback, reserved, multicast, link-local, and unspecified IP addresses are never sent to external providers

### Dashboard and reports

- Responsive dark SOC dashboard
- Chart.js severity, workflow, evidence-source, incident-trend, and country charts
- Leaflet world map using cached public-IP geolocation
- Country statistics and top-origin summaries
- Toast notifications, loading overlay, panel loading states, and mobile navigation
- Detailed incident reports in PDF, CSV, and JSON
- Filtered incident-queue exports in PDF, CSV, and JSON

### Security and maintainability

- Flask application factory and separated database, route, service, template, and static layers
- CSRF protection, hardened cookies, input-size limits, parameterized SQL, and security headers
- Content Security Policy, clickjacking protection, MIME sniffing protection, and restrictive browser permissions
- Safe additive SQLite migrations that preserve existing users, incidents, evidence, notes, assignments, and timelines
- WAL mode, busy timeout, indexes, cached enrichment, and a health endpoint
- No bundled virtual environment, secrets, Git history, bytecode, or generated reports

## Project structure

```text
ShadowTrace_v3/
├── dashboard/
│   ├── __init__.py              # Application factory, CSRF, errors, security headers
│   ├── config.py                # Environment-based configuration
│   ├── db.py                    # SQLite access and safe v3 migration
│   ├── routes.py                # UI, APIs, workflow, lookup, and reports
│   ├── services/
│   │   ├── audit.py             # Activity and audit helpers
│   │   ├── ioc.py               # IOC extraction, normalization, and correlation
│   │   ├── reporting.py         # PDF, CSV, and JSON generation
│   │   └── threat_intel.py      # GeoIP, VirusTotal, AbuseIPDB, scoring, cache
│   ├── templates/               # Dashboard, incident, IOC, audit, login, errors
│   └── static/                  # CSS, JavaScript, and assets
├── correlation-engine/          # Standalone evidence correlation pipeline
├── parsers/                     # Suricata, Auditd, and YARA importers
├── database/                    # Database, schema, and migration reference
├── detection-rules/             # Suricata and YARA rules
├── sample-evidence/             # Safe local demonstration evidence
├── scripts/                     # Database, user, and seed-data helpers
├── tests/                       # Automated application and migration tests
├── docs/VALIDATION.md           # Completed verification record
├── run.py                       # Local entry point
└── requirements.txt
```

## Requirements

- Python 3.11 or newer
- A modern browser
- Internet access only when using external GeoIP or threat-intelligence enrichment

## Quick start

> Run installation commands **inside the extracted `ShadowTrace_v3` directory**. Running them from `~` may accidentally use an unrelated `~/requirements.txt`.

### Kali Linux — recommended automatic setup

```bash
cd ~/Downloads
unzip ShadowTrace_v3.zip
cd ShadowTrace_v3
chmod +x setup_kali.sh
./setup_kali.sh --create-user
source .venv/bin/activate
python run.py
```

The setup script resolves its own project directory, creates `.venv`, installs only ShadowTrace dependencies, generates `.env` with a random secret, and initializes/upgrades the database.

### Linux or macOS — manual setup

```bash
cd /path/to/ShadowTrace_v3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r ./requirements.txt
cp .env.example .env
python scripts/init_db.py
python scripts/create_user.py --role Admin
python run.py
```

### Windows PowerShell

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/init_db.py
python scripts/create_user.py --role Admin
python run.py
```

Before starting the server, replace `SHADOWTRACE_SECRET_KEY` in `.env` with a strong random value:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open `http://127.0.0.1:5000`.

The included SQLite database contains clearly labelled demonstration incidents plus any preserved incident already present in the submitted project. User passwords are stored only as secure hashes, so create a new account when the existing password is unknown.

## Seed data

Load the deterministic v3 demonstration dataset:

```bash
python scripts/seed_data.py
```

Reload only the records labelled `[DEMO]`:

```bash
python scripts/seed_data.py --reset
```

The seed dataset is intentionally synthetic. It uses documentation-safe IP ranges and cached demonstration geolocation so the dashboard, map, country chart, IOC correlation, Threat Scores, and Similar Incidents can be reviewed without making external requests.

## Threat-intelligence configuration

ShadowTrace works without provider keys. Add keys to `.env` to enable optional reputation enrichment:

```env
ABUSEIPDB_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
```

Useful runtime settings:

```env
SHADOWTRACE_COOKIE_SECURE=false
SHADOWTRACE_REQUEST_TIMEOUT=7
SHADOWTRACE_THREAT_CACHE_MINUTES=60
SHADOWTRACE_PAGE_SIZE=10
```

Set `SHADOWTRACE_COOKIE_SECURE=true` only when the application is served over HTTPS.

## Import and correlate evidence

```bash
python parsers/suricata_parser.py /path/to/eve.json
python parsers/auditd_parser.py /path/to/audit.log
python parsers/yara_parser.py detection-rules/yara/shadowtrace_suspicious.yar /path/to/file
python correlation-engine/correlate.py
```

The correlation engine groups compatible evidence, creates or updates incidents, builds the timeline, applies ATT&CK and Kill Chain context, calculates a Threat Score, synchronizes IOCs, and writes activity entries.

## IOC Lookup

Use **IOC Lookup** in the navigation to inspect an IP, domain, URL, file hash, or email address. The result includes:

- Normalized indicator type and value
- Matching incidents and evidence
- External provider status when applicable
- GeoIP and reputation details for eligible public indicators
- Aggregated verdict and score
- Lookup history and audit entry

The JSON endpoint is available to authenticated users at `POST /api/ioc/lookup` and accepts form data containing `indicator`.

## Reports and exports

Each incident page can export a detailed PDF, CSV, or JSON report containing:

- Incident metadata and Threat Score
- Evidence and raw source details
- Reconstructed timeline
- IOCs and correlation data
- Threat-intelligence verdicts
- Similar Incidents and shared indicators
- Notes and activity history

The dashboard also exports the currently filtered incident queue in all three formats.

## Tests

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The v3 suite validates authentication, security headers, dashboard APIs, filtering, pagination inputs, IOC handling, correlation, Similar Incidents, country statistics, workflow auditing, reports, and legacy database migration.

## Production checklist

- Generate and protect a long random `SHADOWTRACE_SECRET_KEY`.
- Serve through a production WSGI server and HTTPS reverse proxy; do not use Flask's development server publicly.
- Set `SHADOWTRACE_COOKIE_SECURE=true` behind HTTPS.
- Restrict filesystem permissions for `.env`, the SQLite database, logs, and reports.
- Back up the database before every production upgrade.
- Review provider privacy, retention, terms, quotas, and regional requirements before enabling external enrichment.
- Replace SQLite with a managed multi-user database if the deployment requires high write concurrency or multiple application replicas.

## Validation

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the completed test and package checks.
