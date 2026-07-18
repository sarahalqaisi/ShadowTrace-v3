from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    BASE_DIR = BASE_DIR
    DATABASE_PATH = Path(os.getenv("SHADOWTRACE_DATABASE", BASE_DIR / "database" / "shadowtrace.db"))
    SECRET_KEY = os.getenv("SHADOWTRACE_SECRET_KEY")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SHADOWTRACE_COOKIE_SECURE", "false").lower() == "true"
    MAX_CONTENT_LENGTH = 4 * 1024 * 1024
    JSON_SORT_KEYS = False
    REQUEST_TIMEOUT = float(os.getenv("SHADOWTRACE_REQUEST_TIMEOUT", "7"))
    THREAT_CACHE_MINUTES = int(os.getenv("SHADOWTRACE_THREAT_CACHE_MINUTES", "60"))
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    DEFAULT_PAGE_SIZE = int(os.getenv("SHADOWTRACE_PAGE_SIZE", "10"))
    MAX_PAGE_SIZE = 100
    CSRF_ENABLED = True

    @classmethod
    def validate(cls) -> None:
        if not cls.SECRET_KEY:
            raise RuntimeError(
                "SHADOWTRACE_SECRET_KEY is missing. Copy .env.example to .env "
                "and set a strong random value."
            )
