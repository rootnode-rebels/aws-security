"""
Unit tests validating Amazon SNS & Email notification dispatch for:
1. Password Reset Token recovery emails on /api/auth/forgot-password.
2. Password Changed / Rotated security confirmations.
3. Impossible Travel / High Risk ML Block alerts.
4. Secondary Device / MFA verification code deliveries.
5. In-App Dispatched Notifications retrieval API (/api/security/dispatched-notifications).
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from backend.app import app
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter
from backend.security.notification_service import notification_service

class TestNotificationService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_email = "sns_tester@awssecurity.io"
        cls.test_pwd = "StrongSecure#2026"
        cls.test_sec_pwd = "MasterTest#2026"

    def setUp(self):
        rate_limiter.clear_all()
        db.users.delete_one({"email": self.test_email})
        db.active_sessions.delete_many({"user_email": self.test_email})
        db.password_resets.delete_many({"email": self.test_email})
        db.get_collection("security_alerts").delete_many({"user_email": self.test_email})
        db.get_collection("dispatched_notifications").delete_many({"recipient_email": self.test_email})

        # Register user
        reg_res = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "full_name": "SNS Tester",
            "password": self.test_pwd,
            "secondary_password": self.test_sec_pwd,
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_sns_test_01",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_sns_test_hash"
            }
        })
        self.assertEqual(reg_res.status_code, 201)

    def test_forgot_password_dispatches_sns_email(self):
        """Verify /api/auth/forgot-password sends a real notification record to user's email."""
        resp = self.client.post("/api/auth/forgot-password", json={"email": self.test_email})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertIn("demo_reset_token", data)
        self.assertIn("channel", data)

        # Verify dispatched_notifications has the record
        records = db.get_collection("dispatched_notifications").find({"recipient_email": self.test_email})
        self.assertGreaterEqual(len(records), 1)

        reset_notif = next((r for r in records if r.get("notification_type") == "PASSWORD_RESET_TOKEN"), None)
        self.assertIsNotNone(reset_notif)
        self.assertEqual(reset_notif["recipient_email"], self.test_email)
        self.assertIn("Password Reset", reset_notif["subject"])
        self.assertIn(data["demo_reset_token"], reset_notif["body_text"])

    def test_dispatched_notifications_api(self):
        """Verify /api/security/dispatched-notifications returns messages."""
        # 1. Dispatch forgot-password
        self.client.post("/api/auth/forgot-password", json={"email": self.test_email})

        # 2. Login to get token
        login_res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_sns_test_01",
                "os": "Windows NT 10.0"
            }
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["token"]

        # 3. Query dispatched notifications
        get_res = self.client.get("/api/security/dispatched-notifications", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(get_res.status_code, 200)
        notifs = get_res.json()["notifications"]
        self.assertGreaterEqual(len(notifs), 1)
        self.assertEqual(notifs[0]["recipient_email"], self.test_email)

    def test_change_password_dispatches_confirmation(self):
        """Verify /api/auth/change-password dispatches a security update email."""
        # Login
        login_res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {"browser": "Chrome", "browser_id": "chrome_sns_test_01", "os": "Windows NT 10.0"}
        })
        token = login_res.json()["token"]

        new_pwd = "UpdatedSecure#2026"
        chg_res = self.client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {token}"}, json={
            "current_password": self.test_pwd,
            "new_password": new_pwd
        })
        self.assertEqual(chg_res.status_code, 200)

        # Verify dispatched record
        records = db.get_collection("dispatched_notifications").find({
            "recipient_email": self.test_email,
            "notification_type": "PASSWORD_CHANGED"
        })
        self.assertGreaterEqual(len(records), 1)
        self.assertIn("Password Updated", records[0]["subject"])

    def test_emergency_freeze_dispatches_status_alert(self):
        """Verify emergency account lockout dispatches an account status alert."""
        login_res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {"browser": "Chrome", "browser_id": "chrome_sns_test_01", "os": "Windows NT 10.0"}
        })
        token = login_res.json()["token"]

        lock_res = self.client.post("/api/auth/lock-account", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(lock_res.status_code, 200)

        records = db.get_collection("dispatched_notifications").find({
            "recipient_email": self.test_email,
            "notification_type": "ACCOUNT_STATUS_CHANGE"
        })
        self.assertGreaterEqual(len(records), 1)
        self.assertIn("Freeze", records[0]["subject"])

    def test_registration_dispatches_welcome_notification(self):
        """Verify registration dispatches an ACCOUNT_REGISTERED notification."""
        records = db.get_collection("dispatched_notifications").find({
            "recipient_email": self.test_email,
            "notification_type": "ACCOUNT_REGISTERED"
        })
        self.assertGreaterEqual(len(records), 1)
        self.assertIn("Registered", records[0]["subject"])

    def test_secondary_password_update_dispatches_notification(self):
        """Verify updating Master Secondary Password dispatches an alert."""
        login_res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {"browser": "Chrome", "browser_id": "chrome_sns_test_01", "os": "Windows NT 10.0"}
        })
        token = login_res.json()["token"]

        res = self.client.post("/api/auth/secondary-password/update", headers={"Authorization": f"Bearer {token}"}, json={
            "current_password": self.test_sec_pwd,
            "new_secondary_password": "NewMasterSecondary#2026"
        })
        self.assertEqual(res.status_code, 200)

        records = db.get_collection("dispatched_notifications").find({
            "recipient_email": self.test_email,
            "notification_type": "SECONDARY_PASSWORD_ROTATED"
        })
        self.assertGreaterEqual(len(records), 1)
        self.assertIn("Secondary Password Updated", records[0]["subject"])

    def test_simulate_attack_dispatches_threat_notification(self):
        """Verify Red Team simulated attack dispatches a critical threat notification."""
        sim_res = self.client.post("/api/security/simulate-attack", json={
            "target_email": self.test_email,
            "attack_type": "IMPOSSIBLE_TRAVEL"
        })
        self.assertEqual(sim_res.status_code, 200)

        records = db.get_collection("dispatched_notifications").find({
            "recipient_email": self.test_email,
            "notification_type": "THREAT_BLOCKED"
        })
        self.assertGreaterEqual(len(records), 1)
        self.assertIn("CRITICAL ALERT", records[0]["subject"])

    def test_notification_status_and_engine_mode(self):
        """Verify engine status keys and /api/security/dispatched-notifications metadata."""
        status = notification_service.get_status()
        self.assertIn("mode", status)
        self.assertIn("description", status)
        self.assertIn("live_delivery", status)

        res = self.client.get("/api/security/dispatched-notifications")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("engine_mode", data)
        self.assertIn("engine_description", data)
        self.assertIn("engine_status", data)
        self.assertIn("notifications", data)

    def test_clear_endpoints_for_events_cloudwatch_and_notifications(self):
        """Verify clear endpoints empty records and reset metrics."""
        # 1. Clear dispatched notifications
        clear_notif = self.client.post("/api/security/dispatched-notifications/clear")
        self.assertEqual(clear_notif.status_code, 200)
        self.assertEqual(clear_notif.json()["status"], "SUCCESS")

        # 2. Clear security events
        clear_events = self.client.post("/api/security/events/clear")
        self.assertEqual(clear_events.status_code, 200)
        self.assertEqual(clear_events.json()["status"], "SUCCESS")
        events_res = self.client.get("/api/security/events")
        self.assertEqual(len(events_res.json()["events"]), 0)

        # 3. Clear cloudwatch telemetry
        clear_cw = self.client.post("/api/monitoring/cloudwatch/clear")
        self.assertEqual(clear_cw.status_code, 200)
        self.assertEqual(clear_cw.json()["status"], "SUCCESS")
        cw_summary = self.client.get("/api/monitoring/cloudwatch").json()
        self.assertEqual(len(cw_summary["recent_logs"]), 0)
        self.assertEqual(cw_summary["metrics"]["BlockedHijacks"], 0)
        self.assertEqual(cw_summary["metrics"]["HighRiskDetections"], 0)
        self.assertGreaterEqual(cw_summary["metrics"]["Invocations"], 1)


if __name__ == "__main__":
    unittest.main()
