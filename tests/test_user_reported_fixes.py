"""
Unit Tests validating:
1. Prominent One-Click sign-in allowance functionality from Primary Device.
2. 'Keep This Device Main' (prompt_primary_device) triggered on registration and initial login.
3. Zero primary device data leakage to secondary devices (IP, hardware, canvas, tokens, alerts).
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

class TestUserReportedFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_email = "shivu_test@awssecurity.io"
        cls.test_pwd = "StrongSecure#2026"
        cls.test_sec_pwd = "MasterShivu#2026"

    def setUp(self):
        rate_limiter.clear_all()
        db.users.delete_one({"email": self.test_email})
        db.active_sessions.delete_many({"user_email": self.test_email})
        db.get_collection("security_alerts").delete_many({"user_email": self.test_email})

    def test_keep_device_main_option_and_zero_data_leak(self):
        # 1. Register new user
        reg_res = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "full_name": "Shivu Tester",
            "password": self.test_pwd,
            "secondary_password": self.test_sec_pwd,
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_shivu_primary_01",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_primary_secret_hash",
                "screen_resolution": "1920x1080"
            }
        })
        self.assertEqual(reg_res.status_code, 201)

        # 2. First login on Primary Browser -> MUST prompt "Set as Your Main Device" (prompt_primary_device = True)
        login_p = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_shivu_primary_01",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_primary_secret_hash",
                "screen_resolution": "1920x1080"
            }
        })
        self.assertEqual(login_p.status_code, 200)
        p_data = login_p.json()
        self.assertTrue(p_data.get("prompt_primary_device"), "First login MUST offer 'Keep this device as main device'!")
        self.assertTrue(p_data.get("is_primary_device"))
        p_token = p_data["token"]
        p_headers = {"Authorization": f"Bearer {p_token}"}

        # 3. Confirm this device as main device (initial confirmation does not require entering secondary password again)
        confirm_res = self.client.post("/api/auth/devices/set-primary", headers=p_headers, json={
            "is_primary": True,
            "device_label": "Main Device (Chrome on Windows NT 10.0)"
        })
        self.assertEqual(confirm_res.status_code, 200)

        # 4. Secondary device attempts login
        sec_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {
                "browser": "Firefox",
                "browser_id": "firefox_secondary_99",
                "os": "Ubuntu Linux",
                "canvas_hash": "canvas_secondary_ubuntu_hash",
                "screen_resolution": "1366x768"
            }
        })
        self.assertEqual(sec_login.status_code, 200)
        sec_data = sec_login.json()
        self.assertEqual(sec_data["status"], "MFA_REQUIRED")
        temp_token = sec_data["temp_token"]

        # ZERO DATA ABOUT PRIMARY LEAKED TO SECONDARY DEVICE:
        self.assertNotIn("target_primary_device", sec_data, "Secondary device must NOT receive primary device info!")
        self.assertNotIn("Chrome", sec_data.get("message", ""))
        self.assertNotIn("Windows", sec_data.get("message", ""))

        # 5. Primary device checks alerts: sees SECONDARY_DEVICE_APPROVAL_REQUEST with verification code
        p_alerts = self.client.get("/api/security/user-alerts", headers=p_headers).json()["alerts"]
        self.assertEqual(len(p_alerts), 1)
        self.assertEqual(p_alerts[0]["type"], "SECONDARY_DEVICE_APPROVAL_REQUEST")
        self.assertTrue(bool(p_alerts[0].get("verification_code")))
        v_code = p_alerts[0]["verification_code"]

        # 6. Primary device executes ONE-CLICK ALLOWANCE
        approve_res = self.client.post("/api/auth/devices/approve-secondary", headers=p_headers, json={
            "temp_token": temp_token,
            "approved": True
        })
        self.assertEqual(approve_res.status_code, 200)
        self.assertEqual(approve_res.json()["status"], "SUCCESS")

        # 7. Secondary device polling resolves immediately to APPROVED with active session token
        poll_res = self.client.get(f"/api/auth/mfa-poll/{temp_token}")
        self.assertEqual(poll_res.status_code, 200)
        poll_data = poll_res.json()
        self.assertEqual(poll_data["status"], "APPROVED")
        sec_token = poll_data["token"]
        sec_headers = {"Authorization": f"Bearer {sec_token}"}

        # 8. Secondary Device calls /api/auth/me -> Primary device MUST BE NONE (zero data leak)
        sec_me = self.client.get("/api/auth/me", headers=sec_headers).json()
        self.assertIsNone(sec_me.get("primary_device"), "Secondary device must NOT receive primary_device in /api/auth/me!")
        self.assertFalse(sec_me.get("is_primary_device"))

        # 9. Secondary Device calls /api/auth/sessions -> Primary session IP and hardware MUST BE MASKED
        sec_sessions = self.client.get("/api/auth/sessions", headers=sec_headers).json()["sessions"]
        primary_session_seen = next(s for s in sec_sessions if s["is_primary_device"])
        self.assertIn("Protected", primary_session_seen["device"])
        self.assertIn("Protected", primary_session_seen["ip_address"])

        # 10. Secondary Device calls /api/security/user-alerts -> ZERO approval requests or verification codes returned
        sec_alerts = self.client.get("/api/security/user-alerts", headers=sec_headers).json()["alerts"]
        for alert in sec_alerts:
            self.assertNotEqual(alert.get("type"), "SECONDARY_DEVICE_APPROVAL_REQUEST")
            self.assertNotIn("verification_code", alert)

        print("[TEST] One-Click allowance, Keep This Device Main option, and Zero Primary Data Leakage tests all PASSED!")

if __name__ == "__main__":
    unittest.main()
