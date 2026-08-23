from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from flask import current_app

from dashboard.db import get_db, utc_now
from dashboard.services.intel_cache import ProviderCache
from dashboard.services.intel_models import ProviderResult
from dashboard.services.intel_providers import AbuseIPDBProvider, IPWhoisProvider, SafeHttpClient, VirusTotalProvider
from dashboard.services.ioc import detect_ioc_type, normalize_ioc

BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".test", ".invalid", ".example")


def _unavailable(name: str, message: str, configured: bool = True, category: str = "ineligible") -> ProviderResult:
    return ProviderResult(name, "error", configured, error_category=category, message=message)


def _safe_for_external(ioc_type: str, normalized: str) -> tuple[bool, str | None]:
    message = "Private, loopback, reserved, local, multicast, and documentation indicators are not sent to providers."
    if ioc_type == "ip":
        return (True, None) if ipaddress.ip_address(normalized).is_global else (False, message)
    if ioc_type in {"domain", "url"}:
        host = normalized if ioc_type == "domain" else (urlsplit(normalized).hostname or "")
        host = host.lower().rstrip(".")
        if host in {"localhost", "localhost.localdomain"} or host.endswith(BLOCKED_SUFFIXES):
            return False, message
        try:
            if not ipaddress.ip_address(host).is_global:
                return False, message
        except ValueError:
            pass
        return True, None
    if ioc_type in {"md5", "sha1", "sha256"}:
        return True, None
    return False, f"External reputation lookup is not supported for {ioc_type} indicators."


def _provider_set():
    client = SafeHttpClient(current_app.config["REQUEST_TIMEOUT"], current_app.config["THREAT_MAX_RESPONSE_BYTES"])
    return [IPWhoisProvider(client), AbuseIPDBProvider(client, current_app.config["ABUSEIPDB_API_KEY"]),
            VirusTotalProvider(client, current_app.config["VIRUSTOTAL_API_KEY"])]


def _run_providers(kind: str, normalized: str, safe: bool, safety_message: str | None, force: bool):
    cache = ProviderCache(current_app.config["THREAT_CACHE_MINUTES"], current_app.config["THREAT_CACHE_MAX_ENTRIES"])
    results: dict[str, ProviderResult] = {}
    for provider in _provider_set():
        if not provider.supports(kind):
            result = _unavailable(provider.name, f"{provider.name} does not support {kind} indicators.")
        elif not safe:
            result = _unavailable(provider.name, safety_message or "Indicator is not eligible for external lookup.")
        elif current_app.config["THREAT_INTEL_MODE"] == "offline":
            result = ProviderResult(provider.name, "error", False, error_category="offline",
                                    message="Provider lookup is disabled in explicit offline mode.", source="offline")
        else:
            cached = None if force else cache.get(provider.name, kind, normalized)
            if cached:
                cached.pop("available", None)
                result = ProviderResult(**cached)
            else:
                result = provider.lookup(kind, normalized)
                cache.put(provider.name, kind, normalized, result.normalized())
        results[provider.name] = result
    return results


def _risk(abuse: dict[str, Any], vt: dict[str, Any], geo: dict[str, Any]) -> dict[str, Any]:
    score, reasons = 0, []
    abuse_score = int(abuse.get("abuse_confidence_score") or 0)
    malicious, suspicious = int(vt.get("malicious") or 0), int(vt.get("suspicious") or 0)
    reputation = int(vt.get("reputation") or 0)
    if abuse.get("available"):
        score += round(abuse_score * 0.55)
        if abuse_score >= 25: reasons.append(f"AbuseIPDB confidence is {abuse_score}%")
    if vt.get("available"):
        score += min(40, malicious * 7 + suspicious * 3)
        if reputation < 0: score += min(10, abs(reputation))
        if malicious: reasons.append(f"VirusTotal has {malicious} malicious detections")
        if suspicious: reasons.append(f"VirusTotal has {suspicious} suspicious detections")
    if geo.get("is_proxy") or geo.get("is_vpn") or geo.get("is_tor"):
        score += 10; reasons.append("Anonymization or proxy indicators detected")
    score = min(max(score, 0), 100)
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 80 else "CRITICAL"
    return {"score": score, "level": level, "reasons": reasons or ["No strong malicious indicators were returned."]}


def _store_aggregate(kind: str, normalized: str, payload: dict[str, Any]) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(minutes=current_app.config["THREAT_CACHE_MINUTES"])).isoformat()
    encoded, now = json.dumps(payload, default=str), utc_now()
    db = get_db()
    db.execute("""INSERT INTO ioc_intel_cache VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ioc_type, normalized_value) DO UPDATE SET payload_json=excluded.payload_json,
        updated_at=excluded.updated_at, expires_at=excluded.expires_at""", (kind, normalized, encoded, now, expires))
    if kind == "ip":
        db.execute("""INSERT INTO threat_intel_cache VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET payload_json=excluded.payload_json,
            updated_at=excluded.updated_at, expires_at=excluded.expires_at""", (normalized, encoded, now, expires))
    db.commit()


def lookup_indicator(value: str | None, ioc_type: str | None = None, *, force: bool = False) -> dict[str, Any]:
    try:
        kind, normalized = normalize_ioc(value or "", ioc_type or detect_ioc_type(value))
    except (ValueError, TypeError):
        message = "The supplied indicator is invalid or unsupported."
        return {"value": value, "normalized_value": value, "ioc_type": ioc_type or "unknown", "ip": None,
                "valid_public_ip": False, "cached": False, "message": message,
                "geo": _unavailable("GeoIP", message).legacy(), "abuseipdb": _unavailable("AbuseIPDB", message).legacy(),
                "virustotal": _unavailable("VirusTotal", message).legacy(),
                "risk": {"score": 0, "level": "UNKNOWN", "reasons": [message]}, "updated_at": utc_now()}
    safe, safety_message = _safe_for_external(kind, normalized)
    results = _run_providers(kind, normalized, safe, safety_message, force)
    geo, abuse, vt = (results[name].legacy() for name in ("IPWhois", "AbuseIPDB", "VirusTotal"))
    payload = {"value": value, "normalized_value": normalized, "ioc_type": kind,
               "ip": normalized if kind == "ip" else None, "valid_public_ip": bool(kind == "ip" and safe),
               "cached": False, "message": safety_message, "geo": geo, "abuseipdb": abuse, "virustotal": vt,
               "risk": _risk(abuse, vt, geo), "updated_at": utc_now(),
               "provider_results": {name: result.normalized() for name, result in results.items()},
               "mode": current_app.config["THREAT_INTEL_MODE"]}
    _store_aggregate(kind, normalized, payload)
    return payload


def lookup_ip(ip_address: str | None, *, force: bool = False) -> dict[str, Any]:
    return lookup_indicator(ip_address, "ip", force=force)


def country_statistics() -> list[dict[str, Any]]:
    rows = get_db().execute("""SELECT i.id, i.severity, i.threat_score, c.payload_json FROM incidents i
        JOIN threat_intel_cache c ON c.ip_address=i.source_ip ORDER BY i.id DESC""").fetchall()
    totals: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        try:
            geo = json.loads(row["payload_json"]).get("geo") or {}
            key = (geo.get("country") or "Unknown", geo.get("country_code") or "--")
            item = totals.setdefault(key, {"country": key[0], "country_code": key[1], "incidents": 0,
                                           "critical": 0, "max_threat_score": 0})
            item["incidents"] += 1
            if str(row["severity"] or "").upper() == "CRITICAL": item["critical"] += 1
            item["max_threat_score"] = max(item["max_threat_score"], int(row["threat_score"] or 0))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return sorted(totals.values(), key=lambda item: (item["incidents"], item["max_threat_score"]), reverse=True)
