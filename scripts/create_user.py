#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "database" / "shadowtrace.db"
SCHEMA = BASE_DIR / "database" / "schema.sql"


def create_user(username_arg: str | None = None, role_arg: str | None = None) -> None:
    username = (username_arg or input("Username: ")).strip()
    if not username or len(username) > 80:
        raise SystemExit("[ERROR] Username must be between 1 and 80 characters.")
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("[ERROR] Passwords do not match.")
    if len(password) < 10:
        raise SystemExit("[ERROR] Password must be at least 10 characters.")
    role = (role_arg or input("Role [Analyst/Admin] (default Analyst): ") or "Analyst").strip().title()
    if role not in {"Analyst", "Admin"}:
        raise SystemExit("[ERROR] Role must be Analyst or Admin.")

    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.executescript(SCHEMA.read_text(encoding="utf-8"))
    try:
        connection.execute(
            "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (username, generate_password_hash(password), role, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        raise SystemExit("[ERROR] Username already exists.")
    finally:
        connection.close()
    print(f"[OK] Created {role} account: {username}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a ShadowTrace user account.")
    parser.add_argument("--username")
    parser.add_argument("--role", choices=["Analyst", "Admin"])
    args = parser.parse_args()
    create_user(args.username, args.role)
