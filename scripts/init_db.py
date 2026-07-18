#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dashboard import create_app
from dashboard.db import init_db

app = create_app()
with app.app_context():
    init_db()
print("[OK] ShadowTrace database schema is ready.")
