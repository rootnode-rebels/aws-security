"""
Unit Tests validating Background Real-Time System Notifications:
1. Native Desktop Notification Dispatcher (Windows Toast / Action Center).
2. Server-Sent Events (SSE) Stream /api/security/stream for 0ms Primary Device push.
3. Access Control: SSE stream is permitted only for Primary Devices (403 for secondary).
"""
import sys
import os
import unittest
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from backend.app import app, broadcaster
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter
from backend.security.desktop_notifier import send_desktop_notification

class TestBackgroundNotifications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_email = "bg_notifier@awssecurity.io"
        cls.test_pwd = "PrimarySecure#2026"
        cls.test_sec_pwd = "MasterKey#2026"

    def setUp(self):
        rate_limiter.clear_all()
        db.users.delete_one({"email": self.test_email})
        db.active_sessions.delete_many({"user_email": self.test_email})
        db.get_collection("security_alerts").delete_many({"user_email": self.test_email})

    def test_01_desktop_notifier_dispatch(self):
        """Verify that send_desktop_notification executes asynchronously without raising any exceptions."""
        try:
            send_desktop_notification(
                title="🔐 AWSSecurity Test Alert",
                message="Secondary device requesting sign-in access. Code: 999888"
            )
            success = True
        except Exception as e:
            success = False
        self.assertTrue(success)

    def test_02_sse_stream_access_control(self):
        """Verify that /api/security/stream requires authentication and is restricted to Primary Devices."""
        # 1. Register & login Primary Device
        self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "full_name": "Notifier Tester",
            "password": self.test_pwd,
            "secondary_password": self.test_sec_pwd,
            "fingerprint": {"browser": "Chrome", "browser_id": "hw_p1", "os": "Windows NT 10.0"}
        })
        p_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {"browser": "Chrome", "browser_id": "hw_p1", "os": "Windows NT 10.0"}
        })
        p_token = p_login.json()["token"]

        # Confirm primary
        self.client.post("/api/auth/devices/set-primary", headers={"Authorization": f"Bearer {p_token}"}, json={
            "is_primary": True,
            "device_label": "Primary Device"
        })

        # 2. Login Secondary Device
        s_login = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_pwd,
            "fingerprint": {"browser": "Firefox", "browser_id": "hw_s2", "os": "Linux"}
        })
        temp_token = s_login.json()["temp_token"]
        self.client.post("/api/auth/devices/approve-secondary", headers={"Authorization": f"Bearer {p_token}"}, json={
            "temp_token": temp_token,
            "approved": True
        })
        s_token = self.client.get(f"/api/auth/mfa-poll/{temp_token}").json()["token"]

        # Secondary device calling /api/security/stream MUST BE 403 FORBIDDEN
        res_sec = self.client.get(f"/api/security/stream?token={s_token}")
        self.assertEqual(res_sec.status_code, 403)

        # Unauthenticated request MUST BE 401
        res_unauth = self.client.get("/api/security/stream")
        self.assertEqual(res_unauth.status_code, 401)

    def test_03_broadcaster_event_dispatch(self):
        """Verify the in-memory broadcaster delivers notifications to primary listeners."""
        q = broadcaster.subscribe("test_user@domain.com")
        self.assertIsNotNone(q)

        async def run_broadcast():
            await broadcaster.broadcast("test_user@domain.com", {"type": "TEST_ALERT", "code": "123456"})
            event = await asyncio.wait_for(q.get(), timeout=2.0)
            return event

        event = asyncio.run(run_broadcast())
        self.assertEqual(event.get("type"), "TEST_ALERT")
        self.assertEqual(event.get("code"), "123456")
        broadcaster.unsubscribe("test_user@domain.com", q)

if __name__ == "__main__":
    unittest.main()
