#!/usr/bin/env python3

import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "database" / "shadowtrace.db"
sys.path.insert(0, str(BASE_DIR))
from dashboard.services.evidence import evidence_fingerprint


def scan_file(rule_path: Path, target_path: Path) -> None:
    if not rule_path.exists():
        print(f"[ERROR] YARA rule not found: {rule_path}")
        sys.exit(1)

    if not target_path.exists():
        print(f"[ERROR] Target file not found: {target_path}")
        sys.exit(1)

    result = subprocess.run(
        [
            "yara",
            str(rule_path),
            str(target_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode not in (0, 1):
        print("[ERROR] YARA execution failed.")
        print(result.stderr)
        sys.exit(1)

    output = result.stdout.strip()

    if not output:
        print("[INFO] No YARA matches detected.")
        return

    matched_rule = output.split()[0]

    description = (
        f"YARA detected suspicious behavior indicators "
        f"in file {target_path.name}. "
        f"Matched rule: {matched_rule}"
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    values = {"evidence_type": "suspicious_file", "source_tool": "YARA", "timestamp": timestamp,
              "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
              "description": description, "raw_event": output}
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
            "suspicious_file",
            "YARA",
            timestamp,
            "127.0.0.1",
            "127.0.0.1",
            description,
            30,
            output,
        ),
    )
    cursor.execute(
        "UPDATE evidence SET evidence_sha256=?, ingested_at=? WHERE id=?",
        (evidence_fingerprint(values), timestamp, cursor.lastrowid),
    )

    connection.commit()
    connection.close()

    print("[OK] Imported 1 YARA evidence event.")
    print(f"[INFO] Matched rule: {matched_rule}")
    print(f"[INFO] Target file: {target_path}")
    print("[INFO] Risk points: 30")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python parsers/yara_parser.py "
            "<rule-file> <target-file>"
        )
        sys.exit(1)

    scan_file(
        Path(sys.argv[1]),
        Path(sys.argv[2]),
    )
