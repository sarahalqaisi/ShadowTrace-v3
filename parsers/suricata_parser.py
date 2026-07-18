#!/usr/bin/env python3

import json
import sqlite3
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "shadowtrace.db"


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
                    json.dumps(event),
                ),
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
