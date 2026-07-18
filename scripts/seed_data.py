#!/usr/bin/env python3
"""Load deterministic, clearly labelled demo incidents for ShadowTrace v3."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from dashboard.services.ioc import sync_incident_iocs

DATABASE = BASE_DIR / "database" / "shadowtrace.db"
SCHEMA = BASE_DIR / "database" / "schema.sql"
DEMO_PREFIX = "[DEMO]"


def now(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat()


DEMO_INCIDENTS = [
    {
        "title": "[DEMO] Credential Access Campaign",
        "severity": "HIGH",
        "confidence": 91,
        "threat_score": 78,
        "source_ip": "198.51.100.23",
        "destination_ip": "10.20.1.15",
        "status": "Investigating",
        "summary": "Simulated password-spraying activity followed by a successful login. Uses RFC documentation addresses only.",
        "stage": "Credential Access → Initial Access",
        "chain": "Exploitation → Installation",
        "techniques": "T1110.003 - Password Spraying; T1078 - Valid Accounts",
        "evidence": [
            ("authentication_alert", "Auditd", -85, "Repeated failed logins from 198.51.100.23 against analyst@example.org", 38),
            ("authentication_success", "Auditd", -79, "Successful login from 198.51.100.23 after the failed attempts", 40),
        ],
    },
    {
        "title": "[DEMO] Web Payload Delivery",
        "severity": "CRITICAL",
        "confidence": 96,
        "threat_score": 93,
        "source_ip": "203.0.113.44",
        "destination_ip": "10.20.2.80",
        "status": "Contained",
        "summary": "Simulated exploit delivery and malware download with a shared domain and SHA-256 indicator.",
        "stage": "Initial Access → Execution",
        "chain": "Delivery → Exploitation → Installation",
        "techniques": "T1190 - Exploit Public-Facing Application; T1105 - Ingress Tool Transfer",
        "evidence": [
            ("web_alert", "Suricata", -70, "Exploit request from 203.0.113.44 to https://malicious-update.example/payload", 50),
            ("file_hash", "YARA", -66, "Downloaded SHA-256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 43),
        ],
    },
    {
        "title": "[DEMO] Lateral Movement Attempt",
        "severity": "HIGH",
        "confidence": 87,
        "threat_score": 72,
        "source_ip": "198.51.100.23",
        "destination_ip": "10.20.3.22",
        "status": "Open",
        "summary": "Simulated remote-service discovery linked to the same source IOC as the credential-access case.",
        "stage": "Discovery → Lateral Movement",
        "chain": "Exploitation → Actions on Objectives",
        "techniques": "T1046 - Network Service Discovery; T1021 - Remote Services",
        "evidence": [
            ("network_alert", "Suricata", -54, "SMB and SSH scan from 198.51.100.23 against 10.20.3.22", 37),
            ("host_alert", "Auditd", -50, "Remote service authentication attempt for ops@example.org", 35),
        ],
    },
    {
        "title": "[DEMO] Phishing Attachment",
        "severity": "HIGH",
        "confidence": 89,
        "threat_score": 81,
        "source_ip": "192.0.2.61",
        "destination_ip": "10.20.4.31",
        "status": "Investigating",
        "summary": "Simulated phishing attachment sharing a payload hash and delivery domain with another case.",
        "stage": "Delivery → Execution",
        "chain": "Delivery → Exploitation",
        "techniques": "T1566.001 - Spearphishing Attachment; T1204.002 - Malicious File",
        "evidence": [
            ("email_alert", "MailGateway", -41, "Attachment referenced malicious-update.example and user finance@example.org", 38),
            ("file_hash", "YARA", -38, "Matched SHA-256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 43),
        ],
    },
    {
        "title": "[DEMO] Reconnaissance Burst",
        "severity": "MEDIUM",
        "confidence": 80,
        "threat_score": 46,
        "source_ip": "203.0.113.44",
        "destination_ip": "10.20.5.0",
        "status": "Resolved",
        "summary": "Simulated network reconnaissance sharing a source IOC with the web-payload incident.",
        "stage": "Reconnaissance",
        "chain": "Reconnaissance",
        "techniques": "T1046 - Network Service Discovery",
        "evidence": [
            ("network_alert", "Suricata", -25, "Port scan from 203.0.113.44 across the application subnet", 46),
        ],
    },
]

GEO = {
    "198.51.100.23": ("Germany", "DE", "Frankfurt", 50.1109, 8.6821, 78),
    "203.0.113.44": ("Singapore", "SG", "Singapore", 1.3521, 103.8198, 93),
    "192.0.2.61": ("United States", "US", "Ashburn", 39.0438, -77.4874, 81),
}


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA.read_text(encoding="utf-8"))
    columns = {row[1] for row in connection.execute("PRAGMA table_info(incidents)")}
    if "threat_score" not in columns:
        connection.execute("ALTER TABLE incidents ADD COLUMN threat_score INTEGER NOT NULL DEFAULT 0")
    connection.commit()


def reset_demo(connection: sqlite3.Connection) -> None:
    ids = [row[0] for row in connection.execute("SELECT id FROM incidents WHERE title LIKE ?", (f"{DEMO_PREFIX}%",))]
    for incident_id in ids:
        connection.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
    connection.commit()


def seed(connection: sqlite3.Connection) -> int:
    created = 0
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)
    for index, item in enumerate(DEMO_INCIDENTS):
        exists = connection.execute("SELECT id FROM incidents WHERE title = ?", (item["title"],)).fetchone()
        if exists:
            sync_incident_iocs(exists[0], connection)
            continue
        first_seen = (base_time + timedelta(minutes=index * 17)).isoformat()
        last_seen = (base_time + timedelta(minutes=index * 17 + 9)).isoformat()
        cursor = connection.execute(
            """
            INSERT INTO incidents (
                title, severity, confidence, threat_score, source_ip, destination_ip,
                first_seen, last_seen, status, summary, attack_stage, kill_chain_phase,
                mitre_techniques, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["title"], item["severity"], item["confidence"], item["threat_score"],
                item["source_ip"], item["destination_ip"], first_seen, last_seen,
                item["status"], item["summary"], item["stage"], item["chain"],
                item["techniques"], first_seen, last_seen,
            ),
        )
        incident_id = cursor.lastrowid
        for evidence_index, (etype, tool, minute_offset, description, risk) in enumerate(item["evidence"]):
            event_time = (base_time + timedelta(minutes=index * 17 + evidence_index * 4)).isoformat()
            connection.execute(
                """
                INSERT INTO evidence (
                    incident_id, evidence_type, source_tool, timestamp, source_ip,
                    destination_ip, description, risk_points, raw_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id, etype, tool, event_time, item["source_ip"],
                    item["destination_ip"], description, risk,
                    json.dumps({"demo": True, "description": description}),
                ),
            )
            techniques = [part.strip() for part in item["techniques"].split(";")]
            connection.execute(
                """
                INSERT INTO attack_timeline (
                    incident_id, event_time, attack_stage, kill_chain_phase,
                    description, mitre_technique
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id, event_time,
                    item["stage"].split(" → ")[min(evidence_index, len(item["stage"].split(" → ")) - 1)],
                    item["chain"].split(" → ")[min(evidence_index, len(item["chain"].split(" → ")) - 1)],
                    description,
                    techniques[min(evidence_index, len(techniques) - 1)],
                ),
            )
        connection.execute(
            "INSERT INTO activity_log (incident_id, username, action, details, created_at) VALUES (?, 'seed-data', 'demo_incident_created', ?, ?)",
            (incident_id, json.dumps({"demo": True}), first_seen),
        )
        sync_incident_iocs(incident_id, connection)
        created += 1

    expires = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    for ip, (country, code, city, lat, lon, score) in GEO.items():
        payload = {
            "value": ip,
            "normalized_value": ip,
            "ioc_type": "ip",
            "ip": ip,
            "valid_public_ip": False,
            "cached": False,
            "message": "Synthetic GeoIP and reputation data loaded by scripts/seed_data.py.",
            "geo": {
                "provider": "ShadowTrace Seed",
                "available": True,
                "configured": True,
                "country": country,
                "country_code": code,
                "city": city,
                "region": "Demo Region",
                "latitude": lat,
                "longitude": lon,
                "timezone": "UTC",
                "isp": "Documentation Network",
                "organization": "ShadowTrace Demo",
                "asn": "AS0",
                "is_proxy": False,
                "is_vpn": False,
                "is_tor": False,
            },
            "abuseipdb": {"provider": "AbuseIPDB", "available": False, "configured": False, "message": "Synthetic demo record."},
            "virustotal": {"provider": "VirusTotal", "available": False, "configured": False, "message": "Synthetic demo record."},
            "risk": {"score": score, "level": "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM", "reasons": ["Synthetic score for UI demonstration only."]},
            "updated_at": now(),
        }
        encoded = json.dumps(payload)
        connection.execute(
            """
            INSERT INTO threat_intel_cache (ip_address, payload_json, updated_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at, expires_at=excluded.expires_at
            """,
            (ip, encoded, now(), expires),
        )
        connection.execute(
            """
            INSERT INTO ioc_intel_cache (ioc_type, normalized_value, payload_json, updated_at, expires_at)
            VALUES ('ip', ?, ?, ?, ?)
            ON CONFLICT(ioc_type, normalized_value) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at, expires_at=excluded.expires_at
            """,
            (ip, encoded, now(), expires),
        )
    connection.commit()
    return created


def main() -> None:
    parser = argparse.ArgumentParser(description="Load deterministic ShadowTrace v3 demo data.")
    parser.add_argument("--reset", action="store_true", help="Remove existing [DEMO] incidents before loading them again.")
    args = parser.parse_args()
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    ensure_schema(connection)
    if args.reset:
        reset_demo(connection)
    created = seed(connection)
    connection.close()
    print(f"[OK] ShadowTrace demo data ready. Created {created} new incident(s).")


if __name__ == "__main__":
    main()
