from __future__ import annotations

import json
from typing import Any

from flask import has_request_context, request, session

from dashboard.db import get_db, utc_now


def _serialize(details: Any) -> str:
    if details is None:
        return "{}"
    if isinstance(details, str):
        return json.dumps({"message": details}, ensure_ascii=False)
    return json.dumps(details, ensure_ascii=False, default=str)


def record_audit(
    action: str,
    entity_type: str = "system",
    entity_id: int | str | None = None,
    details: Any = None,
    *,
    incident_id: int | None = None,
    user_id: int | None = None,
    username: str | None = None,
) -> None:
    db = get_db()
    if has_request_context():
        user_id = user_id if user_id is not None else session.get("user_id")
        username = username or session.get("username") or "anonymous"
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        ip_address = ip_address.split(",", 1)[0].strip()
        user_agent = request.user_agent.string[:500]
    else:
        username = username or "system"
        ip_address = ""
        user_agent = ""

    timestamp = utc_now()
    payload = _serialize(details)
    db.execute(
        """
        INSERT INTO audit_log (
            user_id, username, action, entity_type, entity_id,
            details, ip_address, user_agent, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, action, entity_type, str(entity_id) if entity_id is not None else None,
         payload, ip_address, user_agent, timestamp),
    )
    if incident_id is not None:
        db.execute(
            """
            INSERT INTO activity_log (incident_id, user_id, username, action, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, user_id, username, action, payload, timestamp),
        )
    db.commit()
