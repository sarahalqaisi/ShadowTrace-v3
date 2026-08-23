#!/usr/bin/env python3

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "shadowtrace.db"
sys.path.insert(0, str(BASE_DIR))
from dashboard.services.evidence import evidence_fingerprint


def parse_audit_log(log_path: Path) -> None:
    if not log_path.exists():
        print(f"[ERROR] Audit log not found: {log_path}")
        sys.exit(1)

    raw_log = log_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    if "shadowtrace_sensitive" not in raw_log:
        print("[INFO] No ShadowTrace Auditd events found.")
        return

    descriptions = []

    if "secret.txt" in raw_log:
        descriptions.append(
            "Sensitive test file was modified or its permissions changed"
        )

    if "chmod" in raw_log:
        descriptions.append(
            "File permission modification detected"
        )

    description = "; ".join(descriptions)

    if not description:
        description = "Sensitive file activity detected by Auditd"

    timestamp = datetime.now(timezone.utc).isoformat()

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    values = {"evidence_type": "host_file_activity", "source_tool": "Auditd", "timestamp": timestamp,
              "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
              "description": description, "raw_event": raw_log}
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
            "host_file_activity",
            "Auditd",
            timestamp,
            "127.0.0.1",
            "127.0.0.1",
            description,
            25,
            raw_log,
        ),
    )
    cursor.execute(
        "UPDATE evidence SET evidence_sha256=?, ingested_at=? WHERE id=?",
        (evidence_fingerprint(values), timestamp, cursor.lastrowid),
    )

    connection.commit()
    connection.close()

    print("[OK] Imported 1 Auditd host evidence event.")
    print(f"[INFO] Description: {description}")
    print("[INFO] Risk points: 25")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python parsers/auditd_parser.py "
            "<audit-log-file>"
        )
        sys.exit(1)

    parse_audit_log(Path(sys.argv[1]))
