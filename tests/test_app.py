import json
import tempfile
import unittest
from pathlib import Path

import app as cyber


class CyberShieldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cyber.DB_PATH = Path(self.tmp.name) / "test.sqlite3"
        cyber.init_db()
        cyber.app.config.update(TESTING=True)
        self.client = cyber.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_home_and_health(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/health").json["status"], "ok")

    def test_safe_url_and_history(self):
        response = self.client.post("/api/analyze-url", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["classification"], "safe")
        dash = self.client.get("/api/dashboard").json
        self.assertEqual((dash["total_scans"], dash["safe_urls"]), (1, 1))

    def test_suspicious_and_high_risk(self):
        suspicious = cyber.analyze_url("http://example.com/login")
        high = cyber.analyze_url("http://192.168.1.3/urgent-login")
        self.assertEqual(suspicious["classification"], "suspicious")
        self.assertEqual(high["classification"], "high_risk")
        self.assertTrue(suspicious["reasons"])

    def test_invalid_inputs_rejected(self):
        for value in ("", "javascript:alert(1)", "https://user:pass@example.com", "a b.com"):
            self.assertEqual(self.client.post("/api/analyze-url", json={"url": value}).status_code, 400)

    def test_no_url_value_is_saved(self):
        secret = "https://private-example.test/login"
        self.client.post("/api/analyze-url", json={"url": secret})
        with cyber.connect_db() as db:
            stored = " ".join(str(x) for row in db.execute("SELECT * FROM activity") for x in row)
        self.assertNotIn(secret, stored)

    def test_password_endpoint_does_not_accept_or_store_password(self):
        response = self.client.post("/api/password-assessment", data=json.dumps({"password": "Secret123!"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        with cyber.connect_db() as db:
            stored = " ".join(str(x) for row in db.execute("SELECT * FROM activity") for x in row)
        self.assertNotIn("Secret123!", stored)
        self.assertEqual(self.client.get("/api/dashboard").json["password_assessments"], 1)


if __name__ == "__main__":
    unittest.main()
