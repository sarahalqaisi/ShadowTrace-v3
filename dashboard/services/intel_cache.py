from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from dashboard.db import get_db, utc_now


class ProviderCache:
    def __init__(self, ttl_minutes: int, max_entries: int) -> None:
        self.ttl_minutes = max(1, min(int(ttl_minutes), 24 * 60))
        self.max_entries = max(1, min(int(max_entries), 50_000))

    def get(self, provider: str, ioc_type: str, normalized: str) -> dict[str, Any] | None:
        row = get_db().execute(
            """SELECT payload_json, expires_at FROM threat_intel_provider_cache
               WHERE provider = ? AND ioc_type = ? AND normalized_value = ?""",
            (provider, ioc_type, normalized),
        ).fetchone()
        if not row:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc):
                get_db().execute(
                    "DELETE FROM threat_intel_provider_cache WHERE provider = ? AND ioc_type = ? AND normalized_value = ?",
                    (provider, ioc_type, normalized),
                )
                get_db().commit()
                return None
            return json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def put(self, provider: str, ioc_type: str, normalized: str, payload: dict[str, Any]) -> None:
        now = utc_now()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=self.ttl_minutes)).isoformat()
        db = get_db()
        db.execute(
            """INSERT INTO threat_intel_provider_cache
                   (provider, ioc_type, normalized_value, payload_json, updated_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(provider, ioc_type, normalized_value) DO UPDATE SET
                   payload_json=excluded.payload_json, updated_at=excluded.updated_at,
                   expires_at=excluded.expires_at""",
            (provider, ioc_type, normalized, json.dumps(payload, default=str), now, expires),
        )
        db.execute("DELETE FROM threat_intel_provider_cache WHERE expires_at <= ?", (now,))
        db.execute(
            """DELETE FROM threat_intel_provider_cache WHERE rowid IN (
                   SELECT rowid FROM threat_intel_provider_cache ORDER BY updated_at DESC
                   LIMIT -1 OFFSET ?
               )""",
            (self.max_entries,),
        )
        db.commit()
