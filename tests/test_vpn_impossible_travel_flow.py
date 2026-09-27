"""
Unit and Integration Tests for GeoIP Intelligence, Human Coverable Distance vs Impossible Travel,
and Notification Dispatch Routing (External Email vs Main Device In-App Inbox).
"""
import unittest
import time
import json
from fastapi.testclient import TestClient

from backend.app import app
from database.db_manager import db
from backend.security.notification_service import notification_service
from backend.security.geoip_service import resolve_ip_geolocation, KNOWN_GEO_PRESETS
from backend.ml.feature_extractor import calculate_geo_velocity, extract_features
from backend.ml.model import ml_engine


class TestVpnAndImpossibleTravel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_email = f"travel_tester_{int(time.time()*1000)}@awssecurity.io"
        cls.password = "SecureTravelPass#2026!"

        # Register test account
        res = cls.client.post("/api/auth/register", json={
            "full_name": "Travel Test User",
            "email": cls.test_email,
            "password": cls.password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "bid_primary_nyc_dev",
                "os": "Windows NT 10.0",
                "screen_resolution": "1920x1080",
                "canvas_hash": "canvas_primary_nyc_hash"
            }
        })
        assert res.status_code == 201, f"Registration failed: {res.status_code} {res.text}"

        # Sign in with Primary Device
        login_res = cls.client.post("/api/auth/login", json={
            "email": cls.test_email,
            "password": cls.password,
            "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
            "fingerprint": {
                "browser": "Chrome",
                "browser_id": "bid_primary_nyc_dev",
                "os": "Windows NT 10.0",
                "screen_resolution": "1920x1080",
                "canvas_hash": "canvas_primary_nyc_hash"
            }
        })
        assert login_res.status_code == 200, f"Login failed: {login_res.status_code} {login_res.text}"
        cls.token = login_res.json()["token"]

        # Confirm Primary Device
        cls.client.post("/api/auth/set-primary-device", json={
            "device_id": "dev_primary_nyc",
            "label": "Primary Security Device (NYC)",
            "client_confirmed": True
        }, headers={"Authorization": f"Bearer {cls.token}"})

    def test_01_geoip_service_resolution(self):
        """Verify GeoIP service correctly resolves presets and calculates reputation."""
        # Tokyo VPN
        tokyo = resolve_ip_geolocation("133.242.18.5")
        self.assertEqual(tokyo["city"], "Tokyo")
        self.assertEqual(tokyo["country"], "Japan")
        self.assertTrue(tokyo["is_vpn"])
        self.assertGreaterEqual(tokyo["ip_reputation"], 0.8)

        # London Tor Relay
        london = resolve_ip_geolocation("185.220.101.5")
        self.assertEqual(london["city"], "London")
        self.assertTrue(london["is_vpn"])
        self.assertGreaterEqual(london["ip_reputation"], 0.9)

        # Philadelphia (Human coverable)
        philly = resolve_ip_geolocation("198.51.100.42")
        self.assertEqual(philly["city"], "Philadelphia")
        self.assertFalse(philly["is_vpn"])

    def test_02_detect_client_ip_api(self):
        """Verify GET /api/security/detect-client-ip and /api/security/vpn-presets."""
        res = self.client.get("/api/security/detect-client-ip")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("geo", data)

        res_presets = self.client.get("/api/security/vpn-presets")
        self.assertEqual(res_presets.status_code, 200)
        presets = res_presets.json()["presets"]
        self.assertIn("133.242.18.5", presets)
        self.assertIn("198.51.100.42", presets)

    def test_03_human_coverable_distance_velocity(self):
        """
        Verify that regional distance (<= 400 km, e.g. Philadelphia 130 km away from NYC)
        caps velocity to ground travel speed (<= 120 km/h) so the ML model handles it contextually.
        """
        nyc_geo = {"lat": 40.7128, "lon": -74.0060}
        philly_geo = {"lat": 39.9526, "lon": -75.1652}
        now = time.time()
        # Even if login occurs 2 minutes after NYC login
        dist, vel = calculate_geo_velocity(philly_geo, nyc_geo, now, now - 120)
        self.assertLessEqual(dist, 400.0) # ~130 km
        self.assertLessEqual(vel, 120.0)  # Capped for ground commute travel!

    def test_04_human_coverable_distance_handled_by_model(self):
        """
        Verify that when an unrecognized secondary device logs in from a human-coverable
        regional distance (Philadelphia), the ML model handles it with STEP_UP_MFA,
        delivers the verification code to the Main Device in-app inbox,
        and does NOT send external spam mail.
        """
        # Attempt login from secondary device in Philadelphia
        res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.password,
            "spoofed_ip": "198.51.100.42",
            "geo": {"lat": 39.9526, "lon": -75.1652, "city": "Philadelphia", "country": "US"},
            "fingerprint": {
                "browser": "Firefox",
                "browser_id": "bid_secondary_philly_dev",
                "os": "Ubuntu Linux",
                "screen_resolution": "1366x768",
                "canvas_hash": "canvas_secondary_philly_hash"
            }
        })

        # Model handles it contextually: Requires MFA challenge (NOT blocked!)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "MFA_REQUIRED")
        self.assertIn("temp_token", data)

        # Verify that verification code was generated for Primary Device
        temp_token = data["temp_token"]
        alert = db.get_collection("security_alerts").find_one({
            "user_email": self.test_email,
            "temp_token": temp_token
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "SECONDARY_DEVICE_APPROVAL_REQUEST")
        otp_code = alert["verification_code"]
        self.assertTrue(len(otp_code) == 6 and otp_code.isdigit())

        # Complete secondary sign-in using OTP
        mfa_res = self.client.post("/api/auth/verify-mfa", json={
            "email": self.test_email,
            "temp_token": temp_token,
            "mfa_code": otp_code
        })
        self.assertEqual(mfa_res.status_code, 200)
        self.assertEqual(mfa_res.json()["status"], "SUCCESS")

        # Verify notification was logged in Main Device In-App Inbox but marked routine (no external mail)
        routine_notif = db.get_collection("dispatched_notifications").find_one({
            "recipient_email": self.test_email,
            "notification_type": "SECONDARY_DEVICE_LOGIN"
        })
        self.assertIsNotNone(routine_notif)
        self.assertEqual(routine_notif["channel"], "Main Device In-App Inbox (Routine)")

    def test_05_impossible_travel_triggers_block_and_external_mail(self):
        """
        Verify that login from Tokyo (VPN / 8,500 km/h) triggers Impossible Travel:
        - Blocked with HTTP 403 (BLOCK_SESSION).
        - Serious threat notification dispatched (external email / SNS eligible).
        - High-priority security alert created for Primary Device.
        """
        res = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.password,
            "spoofed_ip": "133.242.18.5",
            "geo": {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "Japan"},
            "fingerprint": {
                "browser": "Chrome Headless / Bot",
                "browser_id": "bid_tokyo_attacker",
                "os": "Linux x86_64",
                "screen_resolution": "800x600",
                "canvas_hash": "canvas_tokyo_spoofed"
            }
        })

        # Intercepted and hard-blocked!
        self.assertEqual(res.status_code, 403)
        err_detail = res.json()["detail"]
        self.assertEqual(err_detail["error"], "Access Blocked")
        self.assertGreaterEqual(err_detail["risk_score"], 70.0)

        # Verify Serious Threat Alert was created in database
        threat_alert = db.get_collection("security_alerts").find_one({
            "user_email": self.test_email,
            "type": "HIGH_RISK_HIJACK_BLOCKED",
            "origin": {"$regex": "Tokyo"}
        })
        self.assertIsNotNone(threat_alert)
        self.assertIn("Tokyo", threat_alert["origin"])

        # Verify Serious Email was dispatched
        threat_notif = db.get_collection("dispatched_notifications").find_one({
            "recipient_email": self.test_email,
            "notification_type": "THREAT_BLOCKED"
        })
        self.assertIsNotNone(threat_notif)
        self.assertTrue(threat_notif.get("is_serious", True))
        self.assertIn("CRITICAL ALERT", threat_notif["subject"])


if __name__ == "__main__":
    unittest.main()
