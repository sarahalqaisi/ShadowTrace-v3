from __future__ import annotations

import hashlib
import json
from typing import Any

from dashboard.db import utc_now


def evidence_fingerprint(values: dict[str, Any]) -> str:
    """Hash stable source fields so later exports can identify changed evidence rows."""
    canonical = {key: values.get(key) for key in (
        "evidence_type", "source_tool", "timestamp", "source_ip", "destination_ip", "description", "raw_event"
    )}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def backfill_evidence_integrity(connection) -> int:
    rows = connection.execute("SELECT * FROM evidence WHERE evidence_sha256 IS NULL").fetchall()
    for row in rows:
        connection.execute(
            "UPDATE evidence SET evidence_sha256 = ?, ingested_at = COALESCE(ingested_at, ?) WHERE id = ?",
            (evidence_fingerprint(dict(row)), utc_now(), row["id"]),
        )
    return len(rows)
