from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g

SCHEMA_VERSION = "3.0.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = Path(current_app.config["DATABASE_PATH"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _add_column(connection: sqlite3.Connection, table: str, definition: str) -> None:
    name = definition.split()[0]
    if name not in _table_columns(connection, table):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def init_db() -> None:
    connection = get_db()
    schema_path = Path(current_app.config["BASE_DIR"]) / "database" / "schema.sql"
    connection.executescript(schema_path.read_text(encoding="utf-8"))

    # Upgrade older project databases without deleting evidence or analyst data.
    for definition in (
        "attack_stage TEXT",
        "kill_chain_phase TEXT",
        "mitre_techniques TEXT",
        "created_at TEXT",
        "updated_at TEXT",
        "threat_score INTEGER NOT NULL DEFAULT 0",
    ):
        _add_column(connection, "incidents", definition)
    _add_column(connection, "attack_timeline", "kill_chain_phase TEXT")
    _add_column(connection, "evidence", "evidence_sha256 TEXT")
    _add_column(connection, "evidence", "ingested_at TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(evidence_sha256)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_threat_score ON incidents(threat_score)")

    timeline_rows = connection.execute(
        "SELECT id, attack_stage FROM attack_timeline WHERE kill_chain_phase IS NULL"
    ).fetchall()
    for row in timeline_rows:
        stage = (row["attack_stage"] or "").lower()
        phase = (
            "Reconnaissance" if "recon" in stage
            else "Exploitation" if any(word in stage for word in ("host", "execution", "file", "defense"))
            else "Unknown"
        )
        connection.execute(
            "UPDATE attack_timeline SET kill_chain_phase = ? WHERE id = ?", (phase, row["id"])
        )

    incident_ids = connection.execute("SELECT id FROM incidents").fetchall()
    for incident_row in incident_ids:
        incident_id = incident_row["id"]
        timeline = connection.execute(
            "SELECT attack_stage, kill_chain_phase, mitre_technique FROM attack_timeline "
            "WHERE incident_id = ? ORDER BY event_time, id",
            (incident_id,),
        ).fetchall()
        if timeline:
            stages = list(dict.fromkeys(row["attack_stage"] for row in timeline if row["attack_stage"]))
            phases = list(dict.fromkeys(
                row["kill_chain_phase"] for row in timeline
                if row["kill_chain_phase"] and row["kill_chain_phase"] != "Unknown"
            ))
            techniques = list(dict.fromkeys(row["mitre_technique"] for row in timeline if row["mitre_technique"]))
            connection.execute(
                """UPDATE incidents SET
                       attack_stage = COALESCE(attack_stage, ?),
                       kill_chain_phase = COALESCE(kill_chain_phase, ?),
                       mitre_techniques = COALESCE(mitre_techniques, ?)
                   WHERE id = ?""",
                (" → ".join(stages), " → ".join(phases), "; ".join(techniques), incident_id),
            )

    now = utc_now()
    connection.execute(
        """
        UPDATE incidents
        SET created_at = COALESCE(created_at, first_seen, ?),
            updated_at = COALESCE(updated_at, last_seen, first_seen, ?)
        WHERE created_at IS NULL OR updated_at IS NULL
        """,
        (now, now),
    )
    connection.execute(
        """
        UPDATE incidents
        SET threat_score = MIN(100, COALESCE((
            SELECT SUM(COALESCE(e.risk_points, 0)) FROM evidence e WHERE e.incident_id = incidents.id
        ), 0))
        WHERE threat_score IS NULL OR threat_score = 0
        """
    )
    connection.execute(
        """
        INSERT INTO schema_metadata (key, value, updated_at) VALUES ('schema_version', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (SCHEMA_VERSION, now),
    )
    connection.commit()

    from dashboard.services.evidence import backfill_evidence_integrity

    backfill_evidence_integrity(connection)
    connection.commit()

    # IOC extraction is deterministic and additive; it can safely be rerun on upgrades.
    from dashboard.services.ioc import sync_all_iocs

    sync_all_iocs(connection)
    connection.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
