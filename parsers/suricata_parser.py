#!/usr/bin/env python3

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "shadowtrace.db"
sys.path.insert(0, str(BASE_DIR))
from dashboard.services.evidence import evidence_fingerprint


def calculate_risk(alert: dict) -> int:
    severity = alert.get("severity", 3)

    severity_scores = {
        1: 40,
        2: 25,
        3: 10,
    }

    return severity_scores.get(severity, 5)


def parse_suricata_file(file_path: Path) -> None:
    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    processed = 0

    with file_path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            description = alert.get("signature", "Unknown Suricata alert")
            risk_points = calculate_risk(alert)

            values = {
                "evidence_type": "network_alert", "source_tool": "Suricata",
                "timestamp": event.get("timestamp"), "source_ip": event.get("src_ip"),
                "destination_ip": event.get("dest_ip"), "description": description,
                "raw_event": json.dumps(event),
            }
            cursor.execute(
                """
                INSERT INTO evidence (
                    evidence_type,
                    source_tool,
                    timestamp,
                    source_ip,
                    destination_ip,
                    description,
                    risk_points,
                    raw_event
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "network_alert",
                    "Suricata",
                    event.get("timestamp"),
                    event.get("src_ip"),
                    event.get("dest_ip"),
                    description,
                    risk_points,
                    values["raw_event"],
                ),
            )
            cursor.execute(
                "UPDATE evidence SET evidence_sha256=?, ingested_at=? WHERE id=?",
                (evidence_fingerprint(values), datetime.now(timezone.utc).isoformat(), cursor.lastrowid),
            )

            processed += 1

    connection.commit()
    connection.close()

    print(f"[OK] Imported {processed} Suricata alerts.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parsers/suricata_parser.py <eve.json>")
        sys.exit(1)

    parse_suricata_file(Path(sys.argv[1]))
