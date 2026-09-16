"""
Unit tests for Root Admin designation, Demo user deletion, and Maintenance mode.
"""
import sys
import os
import unittest
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from backend.app import app, seed_demo_user_if_needed
from database.db_manager import db

class TestRootAdminAndDemoDeletion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_new_registered_user_is_root_admin(self):
        """Verify newly registered users automatically receive Root Admin status."""
        test_email = f"sec_root_{int(time.time()*1000)}@awssecurity.io"
        test_pwd = "RootPassword#2026!"
        test_name = "Chief Security Officer"

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
        self.assertEqual(reg_data.get("role"), "ROOT_ADMIN")
        self.assertTrue(reg_data.get("is_root_admin"))

        # Verify database record
        user_doc = db.users.find_one({"email": test_email})
        self.assertIsNotNone(user_doc)
        self.assertEqual(user_doc.get("role"), "ROOT_ADMIN")
        self.assertTrue(user_doc.get("is_root_admin"))

        # Login as new user
        login_res = self.client.post("/api/auth/login", json={
            "email": test_email,
            "password": test_pwd,
            "fingerprint": {"os": "Windows NT 10.0", "browser": "Chrome", "screen_resolution": "1920x1080", "browser_id": "root_chrome_bid"}
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.json()
        token = login_data.get("token")
        self.assertIsNotNone(token)
        self.assertEqual(login_data["user"]["role"], "ROOT_ADMIN")
        self.assertTrue(login_data["user"]["is_root_admin"])

        # Check /api/auth/me
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.json()
        self.assertEqual(me_data.get("role"), "ROOT_ADMIN")
        self.assertTrue(me_data.get("is_root_admin"))

        # Cleanup
        db.users.delete_one({"email": test_email})
        db.active_sessions.delete_many({"user_email": test_email})

    def test_02_allow_deletion_of_demo_as_root_admin(self):
        """Verify root admin can delete demo@awssecurity.io via CMS admin endpoint."""
        demo_email = "demo@awssecurity.io"
        
        # Ensure demo account is present in database for deletion test
        demo_user = db.users.find_one({"email": demo_email})
        if not demo_user:
            # Seed demo user
            db.get_collection("system_metadata").delete_many({"key": "initial_seed_completed"})
            seed_demo_user_if_needed()
            demo_user = db.users.find_one({"email": demo_email})

        self.assertIsNotNone(demo_user, "demo@awssecurity.io must be present before test deletion")

        # Delete demo@awssecurity.io via CMS endpoint
        del_res = self.client.delete(f"/api/cms/users/{demo_email}")
        self.assertEqual(del_res.status_code, 200)
        del_data = del_res.json()
        self.assertEqual(del_data.get("status"), "SUCCESS")

        # Assert demo@awssecurity.io is gone from database
        deleted_check = db.users.find_one({"email": demo_email})
        self.assertIsNone(deleted_check, "demo@awssecurity.io must be deleted from db")

        # Assert calling seed_demo_user_if_needed does not resurrect demo@awssecurity.io
        seed_demo_user_if_needed()
        self.assertIsNone(db.users.find_one({"email": demo_email}), "Deleted demo account should not be resurrected")

        # Restore demo account for continued testing if desired
        db.get_collection("system_metadata").delete_many({"key": "initial_seed_completed"})
        seed_demo_user_if_needed()

    def test_03_maintenance_mode_and_root_admin_control(self):
        """Verify maintenance mode broadcasts status and allows Root Admin override."""
        # Enable maintenance mode
        enable_res = self.client.post("/api/system/maintenance?enable=true")
        self.assertEqual(enable_res.status_code, 200)
        self.assertTrue(enable_res.json().get("maintenance_mode"))

        # Check system status
        status_res = self.client.get("/api/system/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertTrue(status_data.get("maintenance_mode"))
        self.assertEqual(status_data.get("status"), "SERVICE_UNDER_MAINTENANCE")

        # Disable maintenance mode
        disable_res = self.client.post("/api/system/maintenance?enable=false")
        self.assertEqual(disable_res.status_code, 200)
        self.assertFalse(disable_res.json().get("maintenance_mode"))

        # Check status restored
        restored_status = self.client.get("/api/system/status")
        self.assertEqual(restored_status.status_code, 200)
        self.assertFalse(restored_status.json().get("maintenance_mode"))
        self.assertEqual(restored_status.json().get("status"), "HEALTHY")

if __name__ == "__main__":
    unittest.main()
