from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

from dashboard import create_app
from dashboard.db import SCHEMA_VERSION, get_db, utc_now
from dashboard.services.ioc import extract_iocs, find_similar_incidents, sync_all_iocs


SHARED_SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


class ShadowTraceAppTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE_PATH": Path(self.tempdir.name) / "test.db",
                "CSRF_ENABLED": False,
                "REQUEST_TIMEOUT": 0.05,
                "ABUSEIPDB_API_KEY": "",
                "VIRUSTOTAL_API_KEY": "",
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db = get_db()
            user_id = db.execute(
                "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
                ("admin", generate_password_hash("StrongPass123!"), "Admin", utc_now()),
            ).lastrowid
            incident_1 = db.execute(
                """INSERT INTO incidents (
                    title, severity, confidence, threat_score, source_ip, destination_ip,
                    first_seen, last_seen, status, summary, attack_stage, kill_chain_phase,
                    mitre_techniques, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "Test Correlated Incident",
                    "HIGH",
                    88,
                    65,
                    "127.0.0.1",
                    "10.0.0.5",
                    utc_now(),
                    utc_now(),
                    "Investigating",
                    "A safe test incident.",
                    "Reconnaissance",
                    "Reconnaissance",
                    "T1046 - Network Service Discovery",
                    utc_now(),
                    utc_now(),
                ),
            ).lastrowid
            incident_2 = db.execute(
                """INSERT INTO incidents (
                    title, severity, confidence, threat_score, source_ip, destination_ip,
                    first_seen, last_seen, status, summary, attack_stage, kill_chain_phase,
                    mitre_techniques, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "Related Hash Incident",
                    "MEDIUM",
                    75,
                    48,
                    "127.0.0.1",
                    "10.0.0.8",
                    utc_now(),
                    utc_now(),
                    "Open",
                    "Shares an IOC and MITRE technique.",
                    "Reconnaissance",
                    "Reconnaissance",
                    "T1046 - Network Service Discovery",
                    utc_now(),
                    utc_now(),
                ),
            ).lastrowid
            db.execute(
                """INSERT INTO evidence (
                    incident_id, evidence_type, source_tool, timestamp, source_ip,
                    destination_ip, description, risk_points, raw_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident_1,
                    "network_alert",
                    "Suricata",
                    utc_now(),
                    "127.0.0.1",
                    "10.0.0.5",
                    f"Test scan alert for malicious.example with SHA-256 {SHARED_SHA256}",
                    40,
                    "{}",
                ),
            )
            db.execute(
                """INSERT INTO evidence (
                    incident_id, evidence_type, source_tool, timestamp, source_ip,
                    destination_ip, description, risk_points, raw_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident_2,
                    "file_hash",
                    "YARA",
                    utc_now(),
                    "127.0.0.1",
                    "10.0.0.8",
                    f"Matched {SHARED_SHA256}",
                    48,
                    "{}",
                ),
            )
            for incident_id in (incident_1, incident_2):
                db.execute(
                    """INSERT INTO attack_timeline (
                        incident_id, event_time, attack_stage, kill_chain_phase,
                        description, mitre_technique
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        incident_id,
                        utc_now(),
                        "Reconnaissance",
                        "Reconnaissance",
                        "Test scan alert",
                        "T1046 - Network Service Discovery",
                    ),
                )
            db.execute(
                "INSERT INTO incident_assignments (incident_id, user_id, assigned_at) VALUES (?, ?, ?)",
                (incident_1, user_id, utc_now()),
            )
            db.commit()
            sync_all_iocs()

    def tearDown(self):
        self.tempdir.cleanup()

    def login(self):
        return self.client.post(
            "/login",
            data={"username": "admin", "password": "StrongPass123!"},
            follow_redirects=True,
        )

    def test_health_and_security_headers(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.assertEqual(response.get_json()["version"], SCHEMA_VERSION)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_login_dashboard_filters_and_api(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Threat Operations Dashboard", response.data)
        self.assertIn(b"IOC Lookup & Correlation", response.data)
        api = self.client.get("/api/dashboard")
        self.assertEqual(api.status_code, 200)
        data = api.get_json()
        self.assertEqual(data["total_incidents"], 2)
        self.assertGreaterEqual(data["ioc_statistics"]["correlated"], 1)
        filtered = self.client.get("/?severity=HIGH&q=Correlated&min_score=60")
        self.assertIn(b"Test Correlated Incident", filtered.data)
        self.assertNotIn(b"Related Hash Incident", filtered.data)

    def test_incident_page_and_private_ip_intelligence(self):
        self.login()
        response = self.client.get("/incident/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test Correlated Incident", response.data)
        self.assertIn(b"Private, loopback, reserved", response.data)
        self.assertIn(b"IOC correlation", response.data)
        self.assertIn(SHARED_SHA256.encode(), response.data)

    def test_ioc_extraction_normalization(self):
        results = extract_iocs(
            f"Visit HTTPS://Example.ORG/path and hash {SHARED_SHA256}; contact soc@example.org; IP 8.8.8.8"
        )
        pairs = {(item["ioc_type"], item["normalized_value"]) for item in results}
        self.assertIn(("sha256", SHARED_SHA256), pairs)
        self.assertIn(("ip", "8.8.8.8"), pairs)
        self.assertIn(("email", "soc@example.org"), pairs)
        self.assertIn(("domain", "example.org"), pairs)
        self.assertTrue(any(kind == "url" and value.startswith("https://example.org") for kind, value in pairs))

    def test_ioc_lookup_and_api_correlation(self):
        self.login()
        response = self.client.get(f"/ioc?value={SHARED_SHA256}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"2 local incident matches", response.data)
        self.assertIn(b"VirusTotal", response.data)
        api = self.client.get(f"/api/ioc/lookup?value={SHARED_SHA256}")
        self.assertEqual(api.status_code, 200)
        data = api.get_json()
        self.assertEqual(data["ioc_type"], "sha256")
        self.assertEqual(data["local_match_count"], 2)
        self.assertEqual(len(data["incidents"]), 2)

    def test_invalid_ioc_api(self):
        self.login()
        response = self.client.get("/api/ioc/lookup?value=not-an-indicator")
        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid", response.get_json()["error"].lower())

    def test_similar_incidents_service_and_api(self):
        self.login()
        with self.app.app_context():
            related = find_similar_incidents(1)
            self.assertEqual(related[0]["id"], 2)
            self.assertGreater(related[0]["similarity_score"], 50)
            self.assertTrue(related[0]["shared_iocs"])
        response = self.client.get("/api/incidents/1/similar")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()[0]["id"], 2)

    def test_reports_include_iocs_and_similarity(self):
        self.login()
        for path, mime in [
            ("/incident/1/report.json", "application/json"),
            ("/incident/1/report.csv", "text/csv"),
            ("/incident/1/report.pdf", "application/pdf"),
            ("/reports/incidents.json", "application/json"),
            ("/reports/incidents.csv", "text/csv"),
            ("/reports/incidents.pdf", "application/pdf"),
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, mime)
                self.assertGreater(len(response.data), 20)
        payload = self.client.get("/incident/1/report.json").get_json()
        self.assertTrue(payload["iocs"])
        self.assertTrue(payload["similar_incidents"])
        self.assertEqual(payload["incident"]["threat_score"], 65)

    def test_country_statistics_api(self):
        self.login()
        payload = {
            "geo": {"available": True, "country": "Jordan", "country_code": "JO"},
            "risk": {"score": 60, "level": "HIGH"},
        }
        with self.app.app_context():
            db = get_db()
            db.execute(
                """INSERT INTO incidents (
                    title, severity, confidence, threat_score, source_ip, first_seen,
                    last_seen, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "Geo Test",
                    "HIGH",
                    70,
                    60,
                    "192.0.2.44",
                    utc_now(),
                    utc_now(),
                    "Open",
                    utc_now(),
                    utc_now(),
                ),
            )
            db.execute(
                "INSERT INTO threat_intel_cache (ip_address, payload_json, updated_at, expires_at) VALUES (?, ?, ?, ?)",
                ("192.0.2.44", json.dumps(payload), utc_now(), "2999-01-01T00:00:00+00:00"),
            )
            db.commit()
        response = self.client.get("/api/countries")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()[0]["country"], "Jordan")

    def test_workflow_actions_are_audited(self):
        self.login()
        response = self.client.post(
            "/incident/1/status", data={"status": "Contained"}, follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incident status updated", response.data)
        self.client.post(
            "/incident/1/notes",
            data={"note": "Validated by the analyst."},
            follow_redirects=True,
        )
        with self.app.app_context():
            db = get_db()
            self.assertEqual(
                db.execute("SELECT status FROM incidents WHERE id = 1").fetchone()[0], "Contained"
            )
            self.assertGreaterEqual(
                db.execute("SELECT COUNT(*) FROM activity_log WHERE incident_id = 1").fetchone()[0],
                2,
            )
            self.assertGreaterEqual(db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 3)

    def test_audit_filters(self):
        self.login()
        self.client.get(f"/ioc?value={SHARED_SHA256}")
        response = self.client.get("/audit?action=ioc_lookup&q=sha256")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ioc Lookup", response.data)


class LegacyDatabaseMigrationTests(unittest.TestCase):
    def test_legacy_database_is_upgraded_without_data_loss(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                    severity TEXT NOT NULL, confidence INTEGER NOT NULL,
                    source_ip TEXT, destination_ip TEXT, first_seen TEXT, last_seen TEXT,
                    status TEXT, summary TEXT
                )"""
            )
            connection.execute(
                "INSERT INTO incidents (title, severity, confidence, source_ip, status) VALUES ('Legacy Case', 'HIGH', 80, '10.0.0.2', 'Open')"
            )
            connection.commit()
            connection.close()
            app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "migration-secret",
                    "DATABASE_PATH": path,
                    "CSRF_ENABLED": False,
                }
            )
            with app.app_context():
                db = get_db()
                columns = {row[1] for row in db.execute("PRAGMA table_info(incidents)")}
                self.assertIn("threat_score", columns)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT title FROM incidents").fetchone()[0], "Legacy Case")
                self.assertIsNotNone(
                    db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='iocs'").fetchone()
                )


if __name__ == "__main__":
    unittest.main()
