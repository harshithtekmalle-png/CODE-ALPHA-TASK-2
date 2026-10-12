"""
Unit and Integration Test Suite for PhishGuard
Tests detector.py, database.py, and app.py API endpoints.
"""

import os
import unittest
import tempfile
import json
import detector
import database
from app import app


class TestPhishGuardDetector(unittest.TestCase):
    """Unit tests for the rule-based detection engine in detector.py."""

    def test_risk_level_boundaries(self):
        """Verify risk score to risk level mapping boundary behavior."""
        self.assertEqual(detector.get_risk_level(0), "Low Risk")
        self.assertEqual(detector.get_risk_level(24), "Low Risk")
        self.assertEqual(detector.get_risk_level(25), "Suspicious")
        self.assertEqual(detector.get_risk_level(49), "Suspicious")
        self.assertEqual(detector.get_risk_level(50), "High Risk")
        self.assertEqual(detector.get_risk_level(74), "High Risk")
        self.assertEqual(detector.get_risk_level(75), "Critical")
        self.assertEqual(detector.get_risk_level(100), "Critical")

    def test_analyze_url_benign(self):
        """Safe test input https://example.com should have a Low Risk score."""
        target = "https://example.com"
        result = detector.analyze_url(target)
        self.assertEqual(result["target"], target)
        self.assertEqual(result["risk_level"], "Low Risk")
        self.assertLessEqual(result["score"], 24)
        self.assertEqual(result["scan_type"], "url")
        self.assertIn("timestamp", result)
        self.assertIn("explanation", result)

    def test_analyze_url_empty_input(self):
        """Empty or whitespace URL should yield zero score and Low Risk safely."""
        result = detector.analyze_url("   ")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_level"], "Low Risk")
        self.assertEqual(result["indicators"], [])

    def test_analyze_url_ip_hostname(self):
        """Raw IP address in hostname should trigger critical IP host indicator."""
        target = "http://192.168.1.1/login"
        result = detector.analyze_url(target)
        self.assertEqual(result["target"], target)
        self.assertGreaterEqual(result["score"], 32)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("ip_as_host", indicator_ids)
        self.assertIn("suspicious_keywords", indicator_ids)

    def test_analyze_url_at_symbol_obfuscation(self):
        """URLs utilizing @ symbol redirection trick must trigger critical indicator."""
        target = "http://paypal.com@verify-identity.xyz/update"
        result = detector.analyze_url(target)
        self.assertEqual(result["target"], target)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("at_symbol_obfuscation", indicator_ids)
        self.assertIn("suspicious_tld", indicator_ids)
        self.assertGreaterEqual(result["score"], 50)

    def test_analyze_url_shortener(self):
        """Known URL shorteners should trigger the shortener indicator."""
        target = "https://bit.ly/urgent-login"
        result = detector.analyze_url(target)
        self.assertEqual(result["target"], target)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("url_shortener", indicator_ids)

    def test_analyze_url_excessive_subdomains(self):
        """Excessive subdomains (4+ parts) should trigger subdomain indicator."""
        target = "https://a.b.c.d.example.com/portal"
        result = detector.analyze_url(target)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("excessive_subdomains", indicator_ids)

    def test_analyze_url_unusual_port(self):
        """Unusual web ports like 8080 or 2082 should be flagged."""
        target = "http://example.com:8080/test"
        result = detector.analyze_url(target)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("unusual_port", indicator_ids)

    def test_analyze_message_benign(self):
        """Benign communication message should receive a Low Risk rating."""
        target = "Hello Sarah, can we reschedule our 2 PM check-in to 3 PM? Thanks!"
        result = detector.analyze_message(target)
        self.assertEqual(result["target"], target)
        self.assertEqual(result["risk_level"], "Low Risk")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["indicators"], [])

    def test_analyze_message_empty(self):
        """Empty message should return 0 score safely."""
        result = detector.analyze_message("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_level"], "Low Risk")

    def test_analyze_message_phishing_lure(self):
        """Message with urgency, credential harvesting, and threats should score Critical."""
        target = (
            "URGENT: Your account has been suspended due to unauthorized access. "
            "You must enter your password and verify your credentials within 24 hours "
            "or your account will be terminated permanently."
        )
        result = detector.analyze_message(target)
        self.assertEqual(result["target"], target)
        self.assertGreaterEqual(result["score"], 50)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("urgency_extreme", indicator_ids)
        self.assertIn("account_threat", indicator_ids)
        self.assertIn("credential_harvest", indicator_ids)

    def test_analyze_message_prize_lure(self):
        """Message claiming prize winner should flag reward lure indicator."""
        target = "Congratulations! You have won $10,000 in our lottery winner giveaway! Claim your cash prize now."
        result = detector.analyze_message(target)
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("prize_reward_lure", indicator_ids)


class TestPhishGuardDatabase(unittest.TestCase):
    """Unit tests for SQLite database operations in database.py."""

    def setUp(self):
        # Create a temporary database file for isolation
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        database.init_db(self.temp_db_path)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_init_db_and_save_scan(self):
        """Verify saving scans and reading back from SQLite."""
        record = database.save_scan(
            scan_type="url",
            target="https://example.com",
            score=12,
            risk_level="Low Risk",
            indicators=[{"id": "unencrypted_http", "weight": 12}],
            explanation="Test explanation.",
            timestamp="2026-10-11T10:00:00Z",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(record["id"])
        self.assertEqual(record["target"], "https://example.com")
        self.assertEqual(record["score"], 12)

        history = database.get_history(db_path=self.temp_db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["target"], "https://example.com")
        self.assertEqual(len(history[0]["indicators"]), 1)

    def test_clear_history_and_stats(self):
        """Verify clear_history removes records and resets stats to 0."""
        database.save_scan(
            scan_type="url",
            target="https://example.com",
            score=10,
            risk_level="Low Risk",
            indicators=[],
            explanation="Safe",
            timestamp="2026-10-11T10:00:00Z",
            db_path=self.temp_db_path
        )
        database.save_scan(
            scan_type="message",
            target="Urgent alert: verify password immediately",
            score=80,
            risk_level="Critical",
            indicators=[],
            explanation="Critical",
            timestamp="2026-10-11T10:01:00Z",
            db_path=self.temp_db_path
        )

        stats = database.get_dashboard_stats(db_path=self.temp_db_path)
        self.assertEqual(stats["total_scans"], 2)
        self.assertEqual(stats["url_scans"], 1)
        self.assertEqual(stats["message_scans"], 1)
        self.assertEqual(stats["low_risk"], 1)
        self.assertEqual(stats["critical"], 1)

        # Clear history
        deleted = database.clear_history(db_path=self.temp_db_path)
        self.assertEqual(deleted, 2)

        stats_after = database.get_dashboard_stats(db_path=self.temp_db_path)
        self.assertEqual(stats_after["total_scans"], 0)
        self.assertEqual(stats_after["url_scans"], 0)
        self.assertEqual(stats_after["message_scans"], 0)
        self.assertEqual(stats_after["low_risk"], 0)
        self.assertEqual(stats_after["critical"], 0)

        history_after = database.get_history(db_path=self.temp_db_path)
        self.assertEqual(len(history_after), 0)


class TestPhishGuardFlaskAPI(unittest.TestCase):
    """Integration tests for Flask application routes and REST APIs."""

    def setUp(self):
        # Create an isolated temporary test database
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        database.init_db(self.temp_db_path)

        # Point database module to test DB
        self.original_db = database.DEFAULT_DB_FILE
        database.DEFAULT_DB_FILE = self.temp_db_path

        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        database.DEFAULT_DB_FILE = self.original_db
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_get_index_page(self):
        """GET / should render the main PhishGuard HTML application."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("PHISHGUARD", html)
        self.assertIn("Real-Time Phishing Detection", html)
        self.assertNotIn("CodeAlpha", html)
        self.assertNotIn("Task 2", html)

    def test_post_scan_url_success(self):
        """POST /api/scan-url with valid URL should return 200 with structured JSON."""
        test_url = "https://example.com"
        response = self.client.post(
            "/api/scan-url",
            data=json.dumps({"url": test_url}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["target"], test_url)
        self.assertEqual(data["data"]["risk_level"], "Low Risk")
        self.assertIn("score", data["data"])
        self.assertIn("indicators", data["data"])
        self.assertIn("stats", data)
        self.assertEqual(data["stats"]["total_scans"], 1)
        self.assertEqual(data["stats"]["url_scans"], 1)

    def test_post_scan_url_invalid_inputs(self):
        """POST /api/scan-url with invalid or missing inputs must return 400 Bad Request."""
        # Non-JSON
        resp = self.client.post("/api/scan-url", data="not json", content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

        # Empty body
        resp = self.client.post("/api/scan-url", data=json.dumps({}), content_type="application/json")
        self.assertEqual(resp.status_code, 400)

        # Empty URL string
        resp = self.client.post("/api/scan-url", data=json.dumps({"url": "   "}), content_type="application/json")
        self.assertEqual(resp.status_code, 400)

        # Overly long URL (> 2048 chars)
        oversized = "https://example.com/" + ("a" * 2050)
        resp = self.client.post("/api/scan-url", data=json.dumps({"url": oversized}), content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_post_analyze_message_success(self):
        """POST /api/analyze-message should return 200 and analyze current message."""
        test_msg = "Hello team, please find the meeting notes attached."
        response = self.client.post(
            "/api/analyze-message",
            data=json.dumps({"message": test_msg}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["target"], test_msg)
        self.assertEqual(data["data"]["risk_level"], "Low Risk")
        self.assertIn("stats", data)
        self.assertEqual(data["stats"]["total_scans"], 1)
        self.assertEqual(data["stats"]["message_scans"], 1)

    def test_get_and_delete_history(self):
        """Test GET /api/history and DELETE /api/history lifecycle."""
        # 1. Insert a URL scan
        self.client.post(
            "/api/scan-url",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        # 2. Insert a Message scan
        self.client.post(
            "/api/analyze-message",
            data=json.dumps({"message": "Hello"}),
            content_type="application/json"
        )

        # Retrieve history
        get_resp = self.client.get("/api/history")
        self.assertEqual(get_resp.status_code, 200)
        data = get_resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["history"]), 2)
        self.assertEqual(data["stats"]["total_scans"], 2)

        # Delete history
        del_resp = self.client.delete("/api/history")
        self.assertEqual(del_resp.status_code, 200)
        del_data = del_resp.get_json()
        self.assertTrue(del_data["success"])
        self.assertEqual(del_data["stats"]["total_scans"], 0)

        # Check history is now empty
        get_resp2 = self.client.get("/api/history")
        self.assertEqual(len(get_resp2.get_json()["history"]), 0)


if __name__ == "__main__":
    unittest.main()
