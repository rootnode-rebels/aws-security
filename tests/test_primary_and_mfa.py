"""
Unit Tests for Primary Device Logout Immunity, Master Secondary Password,
and Cross-Device MFA Approval Workflow.
"""
import sys
import os
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from backend.app import app
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter

class TestPrimaryDeviceAndCrossMFA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_email = "tester_primary_mfa@awssecurity.io"
        cls.test_password = "PrimarySecure#2026"
        cls.default_sec_pwd = "MasterKey#2026"

    def setUp(self):
        rate_limiter.clear_all()
        db.users.delete_one({"email": self.test_email})
        db.active_sessions.delete_many({"user_email": self.test_email})
        db.get_collection("security_alerts").delete_many({"user_email": self.test_email})

        # Register fresh user with Primary Device hardware footprint
        reg_resp = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "full_name": "Primary Device Owner",
            "password": self.test_password,
            "secondary_password": self.default_sec_pwd,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_primary_hw_01",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_primary_unique_01",
                "screen_resolution": "1920x1080"
            }
        })
        self.assertEqual(reg_resp.status_code, 201, f"Registration failed: {reg_resp.text}")

        # Primary device first login
        p_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "chrome_primary_hw_01",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_primary_unique_01",
                "screen_resolution": "1920x1080"
            }
        })
        self.assertEqual(p_login.status_code, 200)
        self.primary_token = p_login.json()["token"]
        self.primary_headers = {"Authorization": f"Bearer {self.primary_token}"}

        # Designate as Primary Device
        set_prim = self.client.post("/api/auth/devices/set-primary", headers=self.primary_headers, json={
            "is_primary": True,
            "device_label": "Primary Security Portal (Desktop Chrome)",
            "secondary_password": self.default_sec_pwd
        })
        self.assertEqual(set_prim.status_code, 200)

    def test_01_primary_device_logout_immunity(self):
        """Test primary device session is immune to lock-account, kill-others, and timestamp expiration."""
        # Check profile
        me = self.client.get("/api/auth/me", headers=self.primary_headers).json()
        self.assertEqual(me["device_tier"], "PRIMARY")
        self.assertTrue(me["is_primary_device"])

        # Execute emergency lock-account
        lock_res = self.client.post("/api/auth/lock-account", headers=self.primary_headers)
        self.assertEqual(lock_res.status_code, 200)

        # Primary device is NOT logged out! It can still query /api/auth/me
        me_after_lock = self.client.get("/api/auth/me", headers=self.primary_headers)
        self.assertEqual(me_after_lock.status_code, 200)
        self.assertEqual(me_after_lock.json()["status"], "LOCKED")
        self.assertTrue(me_after_lock.json()["account_is_frozen"])

        # Self-unfreeze from Primary Device
        unlock_res = self.client.post("/api/auth/unlock-self", headers=self.primary_headers)
        self.assertEqual(unlock_res.status_code, 200)

        me_restored = self.client.get("/api/auth/me", headers=self.primary_headers)
        self.assertEqual(me_restored.status_code, 200)
        self.assertEqual(me_restored.json()["status"], "ACTIVE")
        self.assertFalse(me_restored.json()["account_is_frozen"])

    def test_02_secondary_device_mfa_challenge_and_code_delivery(self):
        """Test secondary device sign-in triggers MFA and delivers code ONLY to Primary Device."""
        # Secondary device attempts sign-in
        sec_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Firefox",
                "browser_id": "firefox_secondary_hw_02",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_secondary_unique_02",
                "screen_resolution": "1440x900"
            }
        })
        self.assertEqual(sec_login.status_code, 200)
        sec_data = sec_login.json()
        self.assertEqual(sec_data["status"], "MFA_REQUIRED")
        temp_token = sec_data["temp_token"]
        self.assertTrue(temp_token)
        # CRITICAL: Verification code MUST NOT be leaked in the secondary response!
        self.assertNotIn("mfa_code", sec_data)
        self.assertNotIn("demo_mfa_code", sec_data)

        # Verify Primary Device received the verification code in security_alerts
        alerts = self.client.get("/api/security/user-alerts", headers=self.primary_headers).json()["alerts"]
        approval_alert = next((a for a in alerts if a.get("type") == "SECONDARY_DEVICE_APPROVAL_REQUEST"), None)
        self.assertIsNotNone(approval_alert, "Secondary device approval request alert not found on primary device!")
        self.assertEqual(approval_alert["status"], "PENDING_APPROVAL")
        code = approval_alert["verification_code"]
        self.assertEqual(len(code), 6)

        # Secondary device verifies using the 6-digit code received on the primary device
        verify_res = self.client.post("/api/auth/verify-mfa", json={
            "email": self.test_email,
            "temp_token": temp_token,
            "mfa_code": code
        })
        self.assertEqual(verify_res.status_code, 200)
        sec_active_token = verify_res.json()["token"]

        # Verify secondary device has active session tagged as SECONDARY
        sec_headers = {"Authorization": f"Bearer {sec_active_token}"}
        sec_me = self.client.get("/api/auth/me", headers=sec_headers).json()
        self.assertEqual(sec_me["device_tier"], "SECONDARY")
        self.assertFalse(sec_me["is_primary_device"])

        # Verify Primary Device is STILL authenticated as PRIMARY
        prim_me = self.client.get("/api/auth/me", headers=self.primary_headers).json()
        self.assertEqual(prim_me["device_tier"], "PRIMARY")
        self.assertTrue(prim_me["is_primary_device"])

    def test_03_secondary_device_one_click_approval_polling(self):
        """Test Primary Device one-click approval via /api/auth/devices/approve-secondary and mfa-poll."""
        sec_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Edge",
                "browser_id": "edge_secondary_hw_03",
                "os": "Windows NT 10.0",
                "canvas_hash": "canvas_secondary_edge_03",
                "screen_resolution": "1920x1080"
            }
        })
        temp_token = sec_login.json()["temp_token"]

        # Secondary device polls before approval -> status should be PENDING
        poll1 = self.client.get(f"/api/auth/mfa-poll/{temp_token}").json()
        self.assertEqual(poll1["status"], "PENDING")

        # Primary Device performs One-Click Approval
        approve_res = self.client.post("/api/auth/devices/approve-secondary", headers=self.primary_headers, json={
            "temp_token": temp_token,
            "approved": True
        })
        self.assertEqual(approve_res.status_code, 200)

        # Secondary device polls again -> status APPROVED with session token!
        poll2 = self.client.get(f"/api/auth/mfa-poll/{temp_token}").json()
        self.assertEqual(poll2["status"], "APPROVED")
        self.assertTrue(poll2.get("token"))

    def test_04_master_secondary_password_required_for_device_promotion(self):
        """Test changing/transferring primary device strictly requires Master Secondary Password."""
        # Obtain a secondary session
        sec_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Mobile Safari",
                "browser_id": "safari_mobile_04",
                "os": "iOS 17",
                "canvas_hash": "canvas_safari_04",
                "screen_resolution": "390x844"
            }
        })
        temp_token = sec_login.json()["temp_token"]
        self.client.post("/api/auth/devices/approve-secondary", headers=self.primary_headers, json={
            "temp_token": temp_token,
            "approved": True
        })
        sec_token = self.client.get(f"/api/auth/mfa-poll/{temp_token}").json()["token"]
        sec_headers = {"Authorization": f"Bearer {sec_token}"}

        # Attempt 1: Promote without secondary password -> Rejected (400 or 401)
        fail1 = self.client.post("/api/auth/devices/set-primary", headers=sec_headers, json={
            "is_primary": True,
            "device_label": "Hacked Device Promotion",
            "secondary_password": None
        })
        self.assertIn(fail1.status_code, [400, 401])

        # Attempt 2: Promote with WRONG secondary password -> Rejected (401)
        fail2 = self.client.post("/api/auth/devices/set-primary", headers=sec_headers, json={
            "is_primary": True,
            "device_label": "Hacked Device Promotion",
            "secondary_password": "WrongSecondaryPassword#999"
        })
        self.assertEqual(fail2.status_code, 401)

        # Attempt 3: Promote with CORRECT secondary password -> Succeeded (200)
        success = self.client.post("/api/auth/devices/set-primary", headers=sec_headers, json={
            "is_primary": True,
            "device_label": "New Promoted Primary Device",
            "secondary_password": self.default_sec_pwd
        })
        self.assertEqual(success.status_code, 200)

        # Verify secondary device has now been promoted to PRIMARY
        promoted_me = self.client.get("/api/auth/me", headers=sec_headers).json()
        self.assertEqual(promoted_me["device_tier"], "PRIMARY")
        self.assertTrue(promoted_me["is_primary_device"])

    def test_05_update_secondary_password(self):
        """Test updating the Master Secondary Security Password."""
        new_sec_pwd = "NewMasterKey#2099"
        update_res = self.client.post("/api/auth/secondary-password/update", headers=self.primary_headers, json={
            "current_password": self.default_sec_pwd,
            "new_secondary_password": new_sec_pwd
        })
        self.assertEqual(update_res.status_code, 200)

        # Verify old password is now rejected
        fail_old = self.client.post("/api/auth/devices/set-primary", headers=self.primary_headers, json={
            "is_primary": True,
            "device_label": "Testing Old Secondary Pwd",
            "secondary_password": self.default_sec_pwd
        })
        self.assertEqual(fail_old.status_code, 401)

        # Verify new password is accepted
        success_new = self.client.post("/api/auth/devices/set-primary", headers=self.primary_headers, json={
            "is_primary": True,
            "device_label": "Testing New Secondary Pwd",
            "secondary_password": new_sec_pwd
        })
        self.assertEqual(success_new.status_code, 200)

if __name__ == "__main__":
    unittest.main()
