from __future__ import annotations

import base64
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import requests
from flask import current_app

from dashboard.db import get_db, utc_now
from dashboard.services.ioc import detect_ioc_type, normalize_ioc


def _empty_provider(name: str, message: str, configured: bool = True) -> dict[str, Any]:
    return {"provider": name, "available": False, "configured": configured, "message": message}


def _safe_for_external(ioc_type: str, normalized: str) -> tuple[bool, str | None]:
    if ioc_type == "ip":
        parsed = ipaddress.ip_address(normalized)
        if not parsed.is_global:
            return False, "Private, loopback, reserved, multicast, and unspecified addresses are not sent to external services."
        return True, None
    if ioc_type == "domain":
        lower = normalized.lower()
        if lower.endswith((".local", ".internal", ".lan", ".home", ".test")):
            return False, "Internal or reserved domains are not sent to external services."
        return True, None
    if ioc_type == "url":
        host = urlsplit(normalized).hostname or ""
        if host.endswith((".local", ".internal", ".lan", ".home", ".test")):
            return False, "URLs pointing to internal or reserved hosts are not sent to external services."
        try:
            parsed = ipaddress.ip_address(host)
            if not parsed.is_global:
                return False, "URLs pointing to private or reserved IP addresses are not sent to external services."
        except ValueError:
            pass
        return True, None
    if ioc_type in {"md5", "sha1", "sha256"}:
        return True, None
    return False, f"External reputation lookup is not supported for {ioc_type} indicators."


def _cached(ioc_type: str, normalized: str) -> dict[str, Any] | None:
    row = get_db().execute(
        "SELECT payload_json, expires_at FROM ioc_intel_cache WHERE ioc_type = ? AND normalized_value = ?",
        (ioc_type, normalized),
    ).fetchone()
    if not row:
        # v2/v3 compatibility for IP-only cache entries.
        if ioc_type == "ip":
            row = get_db().execute(
                "SELECT payload_json, expires_at FROM threat_intel_cache WHERE ip_address = ?", (normalized,)
            ).fetchone()
        if not row:
            return None
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            return None
        payload = json.loads(row["payload_json"])
        payload["cached"] = True
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def _store(ioc_type: str, normalized: str, payload: dict[str, Any]) -> None:
    minutes = current_app.config["THREAT_CACHE_MINUTES"]
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    encoded = json.dumps(payload, ensure_ascii=False, default=str)
    db = get_db()
    db.execute(
        """
        INSERT INTO ioc_intel_cache (ioc_type, normalized_value, payload_json, updated_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ioc_type, normalized_value) DO UPDATE SET
            payload_json = excluded.payload_json,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at
        """,
        (ioc_type, normalized, encoded, utc_now(), expires.isoformat()),
    )
    if ioc_type == "ip":
        db.execute(
            """
            INSERT INTO threat_intel_cache (ip_address, payload_json, updated_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            (normalized, encoded, utc_now(), expires.isoformat()),
        )
    db.commit()


def _geo(ip_address: str) -> dict[str, Any]:
    try:
        response = requests.get(
            f"https://ipwho.is/{quote(ip_address, safe='')}",
            timeout=current_app.config["REQUEST_TIMEOUT"],
            headers={"User-Agent": "ShadowTrace/3.0"},
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("success", True):
            return _empty_provider("IPWhois", data.get("message", "Geolocation lookup failed."))
        connection = data.get("connection") or {}
        security = data.get("security") or {}
        return {
            "provider": "IPWhois",
            "available": True,
            "configured": True,
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": (data.get("timezone") or {}).get("id"),
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "asn": connection.get("asn"),
            "is_proxy": bool(security.get("proxy")),
            "is_vpn": bool(security.get("vpn")),
            "is_tor": bool(security.get("tor")),
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _empty_provider("IPWhois", f"Geolocation service unavailable: {type(exc).__name__}")


def _abuseipdb(ip_address: str) -> dict[str, Any]:
    key = current_app.config["ABUSEIPDB_API_KEY"]
    if not key:
        return _empty_provider("AbuseIPDB", "Set ABUSEIPDB_API_KEY in .env to enable this provider.", False)
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json"},
            timeout=current_app.config["REQUEST_TIMEOUT"],
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "provider": "AbuseIPDB",
            "available": True,
            "configured": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
            "country_code": data.get("countryCode"),
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _empty_provider("AbuseIPDB", f"Provider unavailable: {type(exc).__name__}")


def _vt_endpoint(ioc_type: str, normalized: str) -> str:
    if ioc_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{quote(normalized, safe='')}"
    if ioc_type == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{quote(normalized, safe='')}"
    if ioc_type in {"md5", "sha1", "sha256"}:
        return f"https://www.virustotal.com/api/v3/files/{quote(normalized, safe='')}"
    if ioc_type == "url":
        url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
        return f"https://www.virustotal.com/api/v3/urls/{url_id}"
    raise ValueError("VirusTotal does not support this IOC type.")


def _virustotal(ioc_type: str, normalized: str) -> dict[str, Any]:
    key = current_app.config["VIRUSTOTAL_API_KEY"]
    if not key:
        return _empty_provider("VirusTotal", "Set VIRUSTOTAL_API_KEY in .env to enable this provider.", False)
    if ioc_type not in {"ip", "domain", "url", "md5", "sha1", "sha256"}:
        return _empty_provider("VirusTotal", f"VirusTotal lookup is not supported for {ioc_type} indicators.")
    try:
        response = requests.get(
            _vt_endpoint(ioc_type, normalized),
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=current_app.config["REQUEST_TIMEOUT"],
        )
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        return {
            "provider": "VirusTotal",
            "available": True,
            "configured": True,
            "object_type": ioc_type,
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "network": attributes.get("network"),
            "as_owner": attributes.get("as_owner"),
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "times_submitted": attributes.get("times_submitted"),
            "last_final_url": attributes.get("last_final_url"),
            "categories": attributes.get("categories") or {},
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _empty_provider("VirusTotal", f"Provider unavailable: {type(exc).__name__}")


def _risk(abuse: dict[str, Any], vt: dict[str, Any], geo: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    abuse_score = int(abuse.get("abuse_confidence_score") or 0)
    malicious = int(vt.get("malicious") or 0)
    suspicious = int(vt.get("suspicious") or 0)
    reputation = int(vt.get("reputation") or 0)
    if abuse.get("available"):
        score += round(abuse_score * 0.55)
        if abuse_score >= 25:
            reasons.append(f"AbuseIPDB confidence is {abuse_score}%")
    if vt.get("available"):
        score += min(40, malicious * 7 + suspicious * 3)
        if reputation < 0:
            score += min(10, abs(reputation))
        if malicious:
            reasons.append(f"VirusTotal has {malicious} malicious detections")
        if suspicious:
            reasons.append(f"VirusTotal has {suspicious} suspicious detections")
    if geo.get("is_proxy") or geo.get("is_vpn") or geo.get("is_tor"):
        score += 10
        reasons.append("Anonymization or proxy indicators detected")
    score = min(max(score, 0), 100)
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 80 else "CRITICAL"
    return {"score": score, "level": level, "reasons": reasons or ["No strong malicious indicators were returned."]}


def lookup_indicator(value: str | None, ioc_type: str | None = None, *, force: bool = False) -> dict[str, Any]:
    try:
        kind, normalized = normalize_ioc(value or "", ioc_type or detect_ioc_type(value))
    except (ValueError, TypeError):
        message = "The supplied indicator is invalid or unsupported."
        empty = _empty_provider("GeoIP", message)
        return {
            "value": value,
            "normalized_value": value,
            "ioc_type": ioc_type or "unknown",
            "ip": value if ioc_type == "ip" else None,
            "valid_public_ip": False,
            "cached": False,
            "message": message,
            "geo": empty,
            "abuseipdb": _empty_provider("AbuseIPDB", message),
            "virustotal": _empty_provider("VirusTotal", message),
            "risk": {"score": 0, "level": "UNKNOWN", "reasons": [message]},
            "updated_at": utc_now(),
        }

    if not force:
        cached = _cached(kind, normalized)
        if cached:
            return cached

    safe, safety_message = _safe_for_external(kind, normalized)
    if kind == "ip" and safe:
        geo = _geo(normalized)
        abuse = _abuseipdb(normalized)
    else:
        geo = _empty_provider("IPWhois", safety_message or "GeoIP is available only for public IP indicators.")
        abuse = _empty_provider("AbuseIPDB", safety_message or "AbuseIPDB is available only for public IP indicators.")
    vt = _virustotal(kind, normalized) if safe else _empty_provider("VirusTotal", safety_message or "External lookup is disabled for this indicator.")
    payload = {
        "value": value,
        "normalized_value": normalized,
        "ioc_type": kind,
        "ip": normalized if kind == "ip" else None,
        "valid_public_ip": bool(kind == "ip" and safe),
        "cached": False,
        "message": safety_message,
        "geo": geo,
        "abuseipdb": abuse,
        "virustotal": vt,
        "risk": _risk(abuse, vt, geo),
        "updated_at": utc_now(),
    }
    _store(kind, normalized, payload)
    return payload


def lookup_ip(ip_address: str | None, *, force: bool = False) -> dict[str, Any]:
    return lookup_indicator(ip_address, "ip", force=force)


def country_statistics() -> list[dict[str, Any]]:
    db = get_db()
    rows = db.execute(
        """
        SELECT i.id, i.severity, i.threat_score, c.payload_json
        FROM incidents i JOIN threat_intel_cache c ON c.ip_address = i.source_ip
        ORDER BY i.id DESC
        """
    ).fetchall()
    totals: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            geo = payload.get("geo") or {}
            country = geo.get("country") or "Unknown"
            code = geo.get("country_code") or "--"
            key = (country, code)
            item = totals.setdefault(
                key,
                {"country": country, "country_code": code, "incidents": 0, "critical": 0, "max_threat_score": 0},
            )
            item["incidents"] += 1
            if str(row["severity"] or "").upper() == "CRITICAL":
                item["critical"] += 1
            item["max_threat_score"] = max(item["max_threat_score"], int(row["threat_score"] or 0))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return sorted(totals.values(), key=lambda item: (item["incidents"], item["max_threat_score"]), reverse=True)
