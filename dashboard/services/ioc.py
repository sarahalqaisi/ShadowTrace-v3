from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from dashboard.db import get_db, utc_now

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IOC_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256", "email"}


def detect_ioc_type(value: str | None) -> str | None:
    raw = (value or "").strip().strip("[](){}<>,;\"'")
    if not raw:
        return None
    compact = raw.lower()
    if len(compact) in HASH_LENGTHS and re.fullmatch(r"[a-f0-9]+", compact):
        return HASH_LENGTHS[len(compact)]
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass
    parsed = urlsplit(raw)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return "url"
    if EMAIL_RE.fullmatch(raw):
        return "email"
    if DOMAIN_RE.fullmatch(raw) and not raw.endswith("."):
        return "domain"
    return None


def normalize_ioc(value: str, ioc_type: str | None = None) -> tuple[str, str]:
    raw = value.strip().strip("[](){}<>,;\"'")
    if not raw or len(raw) > 4096:
        raise ValueError("Unsupported or invalid IOC value.")
    kind = ioc_type or detect_ioc_type(raw)
    if kind not in IOC_TYPES:
        raise ValueError("Unsupported or invalid IOC value.")
    if kind == "ip":
        normalized = ipaddress.ip_address(raw).compressed
    elif kind in {"md5", "sha1", "sha256", "email"}:
        normalized = raw.lower().rstrip(".")
    elif kind == "domain":
        try:
            normalized = raw.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("The domain is not valid.") from exc
        if len(normalized) > 253 or any(not label or len(label) > 63 for label in normalized.split(".")):
            raise ValueError("The domain is not valid.")
    elif kind == "url":
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("The URL scheme must be HTTP or HTTPS.")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError("The URL does not include a valid hostname.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not accepted.")
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError as exc:
            raise ValueError("The URL port is invalid.") from exc
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("The URL hostname is invalid.") from exc
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        normalized = urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path or "/", parsed.query, ""))
    else:  # pragma: no cover - guarded above
        normalized = raw
    return kind, normalized


def extract_iocs(*values: Any) -> list[dict[str, str]]:
    found: dict[tuple[str, str], str] = {}

    def add(candidate: str, forced_type: str | None = None) -> None:
        candidate = candidate.rstrip(".,;:!?)\"]}'")
        try:
            kind, normalized = normalize_ioc(candidate, forced_type)
        except (ValueError, TypeError):
            return
        found[(kind, normalized)] = candidate

    for value in values:
        if value is None:
            continue
        text = str(value)
        for match in URL_RE.findall(text):
            add(match, "url")
        for match in EMAIL_RE.findall(text):
            add(match, "email")
        for match in HASH_RE.findall(text):
            add(match)
        for match in IPV4_RE.findall(text):
            add(match, "ip")
        # IPv6 values are usually whitespace- or JSON-delimited; validate candidate tokens.
        for token in re.split(r"[\s,;=\"'{}()\[\]<>]+", text):
            if ":" in token and len(token) >= 3:
                add(token, "ip")
        for match in DOMAIN_RE.findall(text):
            # Domains embedded in extracted URLs/emails are still useful correlations,
            # but keep them as a separate domain IOC.
            add(match, "domain")
    return [
        {"ioc_type": kind, "normalized_value": normalized, "value": found[(kind, normalized)]}
        for kind, normalized in sorted(found)
    ]


def _timestamp_min(values: Iterable[str | None]) -> str | None:
    cleaned = [str(value) for value in values if value]
    return min(cleaned) if cleaned else None


def _timestamp_max(values: Iterable[str | None]) -> str | None:
    cleaned = [str(value) for value in values if value]
    return max(cleaned) if cleaned else None


def sync_incident_iocs(incident_id: int, connection=None) -> int:
    db = connection or get_db()
    incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        return 0
    evidence = db.execute(
        "SELECT * FROM evidence WHERE incident_id = ? ORDER BY timestamp, id", (incident_id,)
    ).fetchall()

    observations: dict[tuple[str, str], dict[str, Any]] = {}

    def observe(value: str | None, source: str, seen: str | None, risk: int = 0) -> None:
        if not value:
            return
        for item in extract_iocs(value):
            key = (item["ioc_type"], item["normalized_value"])
            current = observations.setdefault(
                key,
                {
                    "ioc_type": item["ioc_type"],
                    "normalized_value": item["normalized_value"],
                    "value": item["value"],
                    "sources": set(),
                    "times": [],
                    "risk": 0,
                },
            )
            current["sources"].add(source)
            if seen:
                current["times"].append(seen)
            current["risk"] = max(current["risk"], int(risk or 0))

    observe(incident["source_ip"], "incident.source_ip", incident["first_seen"], incident["threat_score"] if "threat_score" in incident.keys() else 0)
    observe(incident["destination_ip"], "incident.destination_ip", incident["first_seen"], 0)
    for row in evidence:
        seen = row["timestamp"] or incident["first_seen"]
        risk = row["risk_points"] or 0
        observe(row["source_ip"], f"evidence:{row['id']}:source_ip", seen, risk)
        observe(row["destination_ip"], f"evidence:{row['id']}:destination_ip", seen, risk)
        observe(row["description"], f"evidence:{row['id']}:description", seen, risk)
        observe(row["raw_event"], f"evidence:{row['id']}:raw_event", seen, risk)

    # Only replace automatically extracted rows; future manually curated IOCs remain intact.
    db.execute("DELETE FROM iocs WHERE incident_id = ? AND source LIKE 'automatic:%'", (incident_id,))
    now = utc_now()
    for item in observations.values():
        times = item["times"] or [incident["first_seen"], incident["last_seen"]]
        source = "automatic:" + ",".join(sorted(item["sources"]))[:900]
        confidence = min(100, 65 + max(0, len(item["sources"]) - 1) * 8)
        db.execute(
            """
            INSERT INTO iocs (
                incident_id, ioc_type, value, normalized_value, source, confidence,
                threat_score, first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id, ioc_type, normalized_value) DO UPDATE SET
                value = excluded.value,
                source = excluded.source,
                confidence = MAX(iocs.confidence, excluded.confidence),
                threat_score = MAX(iocs.threat_score, excluded.threat_score),
                first_seen = COALESCE(MIN(iocs.first_seen, excluded.first_seen), iocs.first_seen, excluded.first_seen),
                last_seen = COALESCE(MAX(iocs.last_seen, excluded.last_seen), iocs.last_seen, excluded.last_seen),
                updated_at = excluded.updated_at
            """,
            (
                incident_id,
                item["ioc_type"],
                item["value"],
                item["normalized_value"],
                source,
                confidence,
                min(item["risk"], 100),
                _timestamp_min(times),
                _timestamp_max(times),
                now,
                now,
            ),
        )
    if connection is None:
        db.commit()
    return len(observations)


def sync_all_iocs(connection=None) -> int:
    db = connection or get_db()
    total = 0
    for row in db.execute("SELECT id FROM incidents ORDER BY id").fetchall():
        total += sync_incident_iocs(row["id"] if hasattr(row, "keys") else row[0], db)
    if connection is None:
        db.commit()
    return total


def incident_iocs(incident_id: int):
    return get_db().execute(
        "SELECT * FROM iocs WHERE incident_id = ? ORDER BY threat_score DESC, ioc_type, normalized_value",
        (incident_id,),
    ).fetchall()


def local_ioc_matches(value: str, ioc_type: str | None = None) -> dict[str, Any]:
    kind, normalized = normalize_ioc(value, ioc_type)
    rows = get_db().execute(
        """
        SELECT o.*, i.title, i.severity, i.status, i.threat_score AS incident_threat_score,
               i.first_seen AS incident_first_seen, i.last_seen AS incident_last_seen
        FROM iocs o JOIN incidents i ON i.id = o.incident_id
        WHERE o.ioc_type = ? AND o.normalized_value = ?
        ORDER BY i.threat_score DESC, i.last_seen DESC, i.id DESC
        """,
        (kind, normalized),
    ).fetchall()
    return {
        "ioc_type": kind,
        "normalized_value": normalized,
        "count": len(rows),
        "incidents": rows,
    }


def find_similar_incidents(incident_id: int, limit: int = 8) -> list[dict[str, Any]]:
    db = get_db()
    base = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not base:
        return []
    base_iocs = {
        (row["ioc_type"], row["normalized_value"])
        for row in db.execute("SELECT ioc_type, normalized_value FROM iocs WHERE incident_id = ?", (incident_id,))
    }
    base_techniques = {
        part.strip().split(" - ", 1)[0]
        for part in (base["mitre_techniques"] or "").split(";")
        if part.strip()
    }
    candidates = db.execute("SELECT * FROM incidents WHERE id <> ?", (incident_id,)).fetchall()
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        candidate_iocs = {
            (row["ioc_type"], row["normalized_value"])
            for row in db.execute(
                "SELECT ioc_type, normalized_value FROM iocs WHERE incident_id = ?", (candidate["id"],)
            )
        }
        shared_iocs = sorted(base_iocs & candidate_iocs)
        candidate_techniques = {
            part.strip().split(" - ", 1)[0]
            for part in (candidate["mitre_techniques"] or "").split(";")
            if part.strip()
        }
        shared_techniques = sorted(base_techniques & candidate_techniques)
        same_source = bool(base["source_ip"] and base["source_ip"] == candidate["source_ip"])
        same_destination = bool(base["destination_ip"] and base["destination_ip"] == candidate["destination_ip"])
        score = min(
            100,
            len(shared_iocs) * 32
            + len(shared_techniques) * 12
            + (18 if same_source else 0)
            + (7 if same_destination else 0),
        )
        if score <= 0:
            continue
        reasons: list[str] = []
        if shared_iocs:
            reasons.append(f"{len(shared_iocs)} shared IOC(s)")
        if shared_techniques:
            reasons.append(f"{len(shared_techniques)} shared MITRE technique(s)")
        if same_source:
            reasons.append("same source IP")
        if same_destination:
            reasons.append("same destination IP")
        ranked.append(
            {
                **dict(candidate),
                "similarity_score": score,
                "shared_iocs": [f"{kind}:{value}" for kind, value in shared_iocs[:8]],
                "shared_techniques": shared_techniques,
                "reasons": reasons,
            }
        )
    ranked.sort(key=lambda row: (row["similarity_score"], row.get("threat_score") or 0, row["id"]), reverse=True)
    return ranked[: max(1, min(limit, 25))]


def ioc_statistics() -> dict[str, Any]:
    db = get_db()
    by_type = {
        row["ioc_type"]: row["total"]
        for row in db.execute("SELECT ioc_type, COUNT(*) total FROM iocs GROUP BY ioc_type ORDER BY total DESC")
    }
    correlated = db.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT ioc_type, normalized_value FROM iocs
            GROUP BY ioc_type, normalized_value HAVING COUNT(DISTINCT incident_id) > 1
        )
        """
    ).fetchone()[0]
    return {
        "total": db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
        "unique": db.execute("SELECT COUNT(*) FROM (SELECT 1 FROM iocs GROUP BY ioc_type, normalized_value)").fetchone()[0],
        "correlated": correlated,
        "by_type": by_type,
    }
