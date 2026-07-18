#!/usr/bin/env python3
"""Correlate unassigned evidence into explainable incidents."""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "database" / "shadowtrace.db"
SCHEMA = BASE_DIR / "database" / "schema.sql"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.services.ioc import sync_incident_iocs


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def confidence(count: int, tool_count: int) -> int:
    return min(35 + count * 10 + tool_count * 8, 100)


def mapping(description: str, evidence_type: str) -> tuple[str, str, str]:
    text = f"{evidence_type} {description}".lower()
    if "scan" in text or "recon" in text or "network_alert" in text:
        return "Reconnaissance", "Reconnaissance", "T1046 - Network Service Discovery"
    if "permission" in text or "chmod" in text or "sensitive" in text or "host_file_activity" in text:
        return "Defense Evasion", "Exploitation", "T1222.002 - Linux and Mac File Permissions Modification"
    if "yara" in text or "suspicious_file" in text or "matched rule" in text:
        return "Execution", "Exploitation", "T1204 - User Execution"
    if "credential" in text or "login" in text:
        return "Credential Access", "Actions on Objectives", "T1110 - Brute Force"
    return "Investigation", "Unknown", "Needs analyst review"


def classify(events: list[sqlite3.Row]) -> tuple[str, str, str, str]:
    mapped = [mapping(row["description"] or "", row["evidence_type"] or "") for row in events]
    stages = list(dict.fromkeys(item[0] for item in mapped))
    chains = list(dict.fromkeys(item[1] for item in mapped if item[1] != "Unknown"))
    techniques = list(dict.fromkeys(item[2] for item in mapped))
    if len(stages) >= 3:
        title = "Multi-Stage Suspicious Activity Detected"
    elif "Reconnaissance" in stages and "Defense Evasion" in stages:
        title = "Reconnaissance Followed by Sensitive Host Activity"
    elif "Reconnaissance" in stages and "Execution" in stages:
        title = "Reconnaissance Followed by Suspicious Execution"
    elif len(stages) == 1:
        title = f"{stages[0]} Activity Detected"
    else:
        title = "Correlated Security Activity"
    return title, " → ".join(stages), " → ".join(chains) or "Unknown", "; ".join(techniques)


def prepare(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA.read_text(encoding="utf-8"))
    for table, definition in [
        ("incidents", "attack_stage TEXT"), ("incidents", "kill_chain_phase TEXT"),
        ("incidents", "mitre_techniques TEXT"), ("incidents", "created_at TEXT"),
        ("incidents", "updated_at TEXT"), ("incidents", "threat_score INTEGER NOT NULL DEFAULT 0"),
        ("attack_timeline", "kill_chain_phase TEXT"),
    ]:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        name = definition.split()[0]
        if name not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
    connection.commit()


def update_incident(connection: sqlite3.Connection, incident_id: int) -> None:
    events = connection.execute(
        "SELECT * FROM evidence WHERE incident_id = ? ORDER BY timestamp, id", (incident_id,)
    ).fetchall()
    if not events:
        return
    score = min(sum(row["risk_points"] or 0 for row in events), 100)
    tools = len({row["source_tool"] for row in events if row["source_tool"]})
    title, attack_stage, chain, techniques = classify(events)
    timestamps = [row["timestamp"] for row in events if row["timestamp"]]
    first_seen = min(timestamps) if timestamps else now()
    last_seen = max(timestamps) if timestamps else first_seen
    summary = (
        f"ShadowTrace correlated {len(events)} evidence records from {tools} security tool(s). "
        f"Threat score: {score}/100. Severity: {severity(score)}."
    )
    connection.execute(
        """
        UPDATE incidents SET title=?, severity=?, confidence=?, first_seen=?, last_seen=?, summary=?,
            attack_stage=?, kill_chain_phase=?, mitre_techniques=?, threat_score=?, updated_at=?
        WHERE id=?
        """,
        (title, severity(score), confidence(len(events), tools), first_seen, last_seen, summary,
         attack_stage, chain, techniques, score, now(), incident_id),
    )
    connection.execute("DELETE FROM attack_timeline WHERE incident_id = ?", (incident_id,))
    for event in events:
        stage, phase, technique = mapping(event["description"] or "", event["evidence_type"] or "")
        connection.execute(
            """
            INSERT INTO attack_timeline (
                incident_id, event_time, attack_stage, kill_chain_phase, description, mitre_technique
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, event["timestamp"], stage, phase, event["description"], technique),
        )
    connection.execute(
        """INSERT INTO activity_log (incident_id, user_id, username, action, details, created_at)
           VALUES (?, NULL, 'correlation-engine', 'incident_correlated', ?, ?)""",
        (incident_id, json.dumps({"evidence_count": len(events), "score": score}), now()),
    )
    sync_incident_iocs(incident_id, connection)


def correlate() -> None:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    prepare(connection)
    pending = connection.execute("SELECT * FROM evidence WHERE incident_id IS NULL ORDER BY timestamp, id").fetchall()
    if not pending:
        print("[INFO] No unassigned evidence records found.")
        connection.close()
        return

    touched: set[int] = set()
    for event in pending:
        source_ip = event["source_ip"] or "unknown"
        existing = connection.execute(
            """SELECT id FROM incidents WHERE COALESCE(source_ip, 'unknown') = ?
               AND COALESCE(status, 'Open') NOT IN ('Resolved', 'Closed') ORDER BY id DESC LIMIT 1""",
            (source_ip,),
        ).fetchone()
        if existing:
            incident_id = existing["id"]
        else:
            timestamp = event["timestamp"] or now()
            cursor = connection.execute(
                """INSERT INTO incidents (
                    title, severity, confidence, source_ip, destination_ip, first_seen, last_seen,
                    status, summary, created_at, updated_at
                ) VALUES (?, 'LOW', 35, ?, ?, ?, ?, 'Open', ?, ?, ?)""",
                ("New Correlated Security Activity", event["source_ip"], event["destination_ip"],
                 timestamp, timestamp, "Incident created from newly imported evidence.", now(), now()),
            )
            incident_id = cursor.lastrowid
        connection.execute("UPDATE evidence SET incident_id = ? WHERE id = ?", (incident_id, event["id"]))
        touched.add(incident_id)

    for incident_id in sorted(touched):
        update_incident(connection, incident_id)
    connection.commit()
    connection.close()
    print(f"[OK] Correlated {len(pending)} evidence record(s) into {len(touched)} incident(s).")


if __name__ == "__main__":
    correlate()
