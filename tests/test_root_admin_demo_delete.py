"""
Unit tests for Root Admin designation, Demo user deletion, and Maintenance mode.
"""
import sys
import os
import unittest
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["SUPER_ADMIN_PASSWORD"] = "likitha@2005"

from fastapi.testclient import TestClient
from backend.app import app, seed_demo_user_if_needed
from database.db_manager import db

class TestRootAdminAndDemoDeletion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ["DEPLOYMENT_MODE"] = "DEVELOPMENT"
        cls.client = TestClient(app)
        admin_email = os.getenv("SUPER_ADMIN_EMAIL", "anushree2k5@gmail.com")
        db.active_sessions.delete_many({"user_email": admin_email})
        # Authenticate Super Admin to get admin authorization token
        login_res = cls.client.post("/api/auth/login", json={
            "email": admin_email,
            "password": os.getenv("SUPER_ADMIN_PASSWORD", "TempAdmin#2026"),
            "fingerprint": {"browser": "Chrome", "browser_id": "root_admin_test_bid", "os": "Windows NT 10.0"},
            "terminate_other_sessions": True
        })
        assert login_res.status_code == 200, f"Super Admin login failed: {login_res.text}"
        cls.admin_token = login_res.json()["token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def test_01_new_registered_user_standard_role(self):
        """Verify newly registered users receive standard USER role (Principle of Least Privilege)."""
        test_email = f"sec_user_{int(time.time()*1000)}@awssecurity.io"
        test_pwd = "UserPassword#2026!"
        test_name = "Security Analyst"

        # Register
        reg_res = self.client.post("/api/auth/register", json={
            "email": test_email,
            "full_name": test_name,
            "password": test_pwd,
            "fingerprint": {"os": "Windows NT 10.0", "browser": "Chrome", "screen_resolution": "1920x1080"},
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}
        })
        self.assertEqual(reg_res.status_code, 201)
        reg_data = reg_res.json()
        self.assertEqual(reg_data.get("status"), "success")
        self.assertFalse(reg_data.get("requires_verification"))

        # Verify database record assigns standard USER role
        user_doc = db.users.find_one({"email": test_email})
        self.assertIsNotNone(user_doc)
        self.assertEqual(user_doc.get("role"), "USER")
        self.assertFalse(user_doc.get("is_root_admin", False))

        # Login as new user
        login_res = self.client.post("/api/auth/login", json={
            "email": test_email,
            "password": test_pwd,
            "fingerprint": {"os": "Windows NT 10.0", "browser": "Chrome", "screen_resolution": "1920x1080", "browser_id": "analyst_chrome_bid"}
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.json()
        token = login_data.get("token")
        self.assertIsNotNone(token)
        self.assertEqual(login_data["user"]["role"], "USER")

        # Check /api/auth/me
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.json()
        self.assertEqual(me_data.get("role"), "USER")

        # Cleanup
        db.users.delete_one({"email": test_email})
        db.active_sessions.delete_many({"user_email": test_email})

    def test_02_allow_deletion_of_demo_as_root_admin(self):
        """Verify Super Admin can delete demo account via CMS admin endpoint."""
        demo_email = "demo@awssecurity.io"
        
        # Ensure demo account is present in database for deletion test
        demo_user = db.users.find_one({"email": demo_email})
        if not demo_user:
            db.get_collection("system_metadata").delete_many({"key": "initial_seed_completed"})
            db.get_collection("system_metadata").delete_many({"key": f"deleted_user_{demo_email}"})
            seed_demo_user_if_needed(force=True)
            demo_user = db.users.find_one({"email": demo_email})

        self.assertIsNotNone(demo_user, "demo@awssecurity.io must be present before test deletion")

        # Delete demo@awssecurity.io via CMS endpoint with Super Admin Authorization header
        del_res = self.client.delete(f"/api/cms/users/{demo_email}", headers=self.admin_headers)
        self.assertEqual(del_res.status_code, 200)
        del_data = del_res.json()
        self.assertEqual(del_data.get("status"), "SUCCESS")

        # Assert demo@awssecurity.io is gone from database
        deleted_check = db.users.find_one({"email": demo_email})
        self.assertIsNone(deleted_check, "demo@awssecurity.io must be deleted from db")

        # Restore demo account for continued testing
        db.get_collection("system_metadata").delete_many({"key": "initial_seed_completed"})
        seed_demo_user_if_needed(force=True)

    def test_03_maintenance_mode_and_root_admin_control(self):
        """Verify maintenance mode broadcasts status and requires Super Admin control."""
        # Enable maintenance mode using Super Admin credentials
        enable_res = self.client.post("/api/system/maintenance?enable=true", headers=self.admin_headers)
        self.assertEqual(enable_res.status_code, 200)
        self.assertTrue(enable_res.json().get("maintenance_mode"))

        # Check system status
        status_res = self.client.get("/api/system/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertTrue(status_data.get("maintenance_mode"))
        self.assertEqual(status_data.get("status"), "SERVICE_UNDER_MAINTENANCE")

        # Disable maintenance mode using Super Admin credentials
        disable_res = self.client.post("/api/system/maintenance?enable=false", headers=self.admin_headers)
        self.assertEqual(disable_res.status_code, 200)
        self.assertFalse(disable_res.json().get("maintenance_mode"))

        # Check status restored
        restored_status = self.client.get("/api/system/status")
        self.assertEqual(restored_status.status_code, 200)
        self.assertFalse(restored_status.json().get("maintenance_mode"))
        self.assertEqual(restored_status.json().get("status"), "HEALTHY")

if __name__ == "__main__":
    unittest.main()
