from __future__ import annotations

import base64
import json
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import requests

from dashboard.services.intel_models import ProviderResult


class IntelligenceProvider(Protocol):
    name: str

    def supports(self, ioc_type: str) -> bool: ...
    def lookup(self, ioc_type: str, value: str) -> ProviderResult: ...


class SafeHttpClient:
    """Small, fixed-destination HTTP boundary for threat-intelligence providers."""

    ALLOWED_HOSTS = frozenset({"ipwho.is", "api.abuseipdb.com", "www.virustotal.com"})

    def __init__(self, timeout: float, max_bytes: int) -> None:
        self.timeout = max(0.1, min(float(timeout), 30.0))
        self.max_bytes = max(1024, min(int(max_bytes), 5 * 1024 * 1024))

    def get_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        destination = urlsplit(url)
        if destination.scheme != "https" or destination.hostname not in self.ALLOWED_HOSTS:
            raise ValueError("Provider destination is not allowed")
        response = requests.get(
            url,
            timeout=self.timeout,
            allow_redirects=False,
            verify=True,
            stream=True,
            **kwargs,
        )
        try:
            response.raise_for_status()
            if 300 <= response.status_code < 400:
                raise requests.RequestException("Provider redirects are disabled")
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > self.max_bytes:
                raise ValueError("Provider response exceeded the configured size limit")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=16_384):
                body.extend(chunk)
                if len(body) > self.max_bytes:
                    raise ValueError("Provider response exceeded the configured size limit")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Provider returned an unexpected JSON shape")
            return data
        finally:
            response.close()


class BaseProvider:
    name = "provider"

    def __init__(self, client: SafeHttpClient, api_key: str = "") -> None:
        self.client = client
        self.api_key = api_key

    def failure(self, category: str, message: str, *, configured: bool = True) -> ProviderResult:
        return ProviderResult(self.name, "error", configured, error_category=category, message=message)


class IPWhoisProvider(BaseProvider):
    name = "IPWhois"

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        try:
            data = self.client.get_json(
                f"https://ipwho.is/{quote(value, safe='')}",
                headers={"User-Agent": "ShadowTrace/3.1"},
            )
            if not data.get("success", True):
                return self.failure("provider_rejected", "Geolocation provider rejected the lookup.")
            connection, security = data.get("connection") or {}, data.get("security") or {}
            result = {
                "country": data.get("country"), "country_code": data.get("country_code"),
                "region": data.get("region"), "city": data.get("city"),
                "latitude": data.get("latitude"), "longitude": data.get("longitude"),
                "timezone": (data.get("timezone") or {}).get("id"), "isp": connection.get("isp"),
                "organization": connection.get("org"), "asn": connection.get("asn"),
                "is_proxy": bool(security.get("proxy")), "is_vpn": bool(security.get("vpn")),
                "is_tor": bool(security.get("tor")),
            }
            return ProviderResult(self.name, "ok", True, result)
        except requests.Timeout:
            return self.failure("timeout", "Geolocation provider timed out.")
        except (requests.RequestException, ValueError, TypeError):
            return self.failure("unavailable", "Geolocation provider is unavailable.")


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        if not self.api_key:
            return self.failure("not_configured", "AbuseIPDB is not configured.", configured=False)
        try:
            data = self.client.get_json(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.api_key, "Accept": "application/json"},
            ).get("data") or {}
            return ProviderResult(self.name, "ok", True, {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0), "last_reported_at": data.get("lastReportedAt"),
                "usage_type": data.get("usageType"), "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted"), "country_code": data.get("countryCode"),
            })
        except requests.Timeout:
            return self.failure("timeout", "AbuseIPDB timed out.")
        except (requests.RequestException, ValueError, TypeError):
            return self.failure("unavailable", "AbuseIPDB is unavailable.")


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.TYPES

    def _url(self, ioc_type: str, value: str) -> str:
        if ioc_type == "ip": return f"https://www.virustotal.com/api/v3/ip_addresses/{quote(value, safe='')}"
        if ioc_type == "domain": return f"https://www.virustotal.com/api/v3/domains/{quote(value, safe='')}"
        if ioc_type in {"md5", "sha1", "sha256"}: return f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}"
        encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"https://www.virustotal.com/api/v3/urls/{encoded}"

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        if not self.api_key:
            return self.failure("not_configured", "VirusTotal is not configured.", configured=False)
        try:
            attributes = (self.client.get_json(
                self._url(ioc_type, value), headers={"x-apikey": self.api_key, "Accept": "application/json"}
            ).get("data") or {}).get("attributes") or {}
            stats = attributes.get("last_analysis_stats") or {}
            fields = {key: attributes.get(key) for key in (
                "reputation", "last_analysis_date", "network", "as_owner", "meaningful_name",
                "type_description", "times_submitted", "last_final_url",
            )}
            fields.update({"object_type": ioc_type, "malicious": int(stats.get("malicious", 0) or 0),
                           "suspicious": int(stats.get("suspicious", 0) or 0),
                           "harmless": int(stats.get("harmless", 0) or 0),
                           "undetected": int(stats.get("undetected", 0) or 0),
                           "categories": attributes.get("categories") or {}})
            return ProviderResult(self.name, "ok", True, fields)
        except requests.Timeout:
            return self.failure("timeout", "VirusTotal timed out.")
        except (requests.RequestException, ValueError, TypeError):
            return self.failure("unavailable", "VirusTotal is unavailable.")
