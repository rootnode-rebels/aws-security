"""
Deep Cybersecurity & Threat Vector Verification Suite.
Validates:
1. Cryptographic Primitives (PBKDF2-HMAC-SHA256, unique salts, token entropy, TOTP, one-time backup codes)
2. Path Traversal & Local File Inclusion Defenses
3. NoSQL / BSON Injection Blocking
4. Role-Based Access Control (RBAC) & Least Privilege
5. Device Tier Isolation & Zero Primary Data Leakage
6. Automated Watchdog Daemon & Service Worker Root Scope
"""
import os
import sys
import re
import time
import unittest
import re

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from backend.app import app, seed_demo_user_if_needed
from database.db_manager import db
from backend.security.auth import (
    hash_password, verify_password, generate_session_token,
    generate_totp_secret, compute_totp, verify_totp_code,
    generate_backup_codes, verify_and_consume_backup_code
)
from backend.security.sanitizer import sanitize_mongo_dict
from backend.security.rate_limiter import rate_limiter


class TestDeepSecurityProbe(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_demo_user_if_needed(force=True)
        rate_limiter.clear_all()
        cls.client_ctx = TestClient(app)
        cls.client = cls.client_ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client_ctx.__exit__(None, None, None)
        except Exception:
            pass

    def test_01_cryptographic_primitives(self):
        """Vector 1: Cryptographic Primitives, Salting, TOTP, and One-Time Backup Codes."""
        pwd = "SuperSecretPassword#2026!"
        h1, s1 = hash_password(pwd)
        h2, s2 = hash_password(pwd)

        self.assertNotEqual(s1, s2, "Salt generation must be non-deterministic")
        self.assertNotEqual(h1, h2, "Hashes with distinct salts must not collide")
        self.assertTrue(verify_password(pwd, h1, s1))
        self.assertFalse(verify_password(pwd + "wrong", h1, s1))
        self.assertFalse(verify_password("", h1, s1))

        t1 = generate_session_token()
        t2 = generate_session_token()
        self.assertGreaterEqual(len(t1), 43)
        self.assertNotEqual(t1, t2)

        secret = generate_totp_secret()
        code = compute_totp(secret)
        self.assertTrue(verify_totp_code(secret, code))
        self.assertFalse(verify_totp_code(secret, "000000" if code != "000000" else "111111"))

        b_codes = generate_backup_codes(4)
        first_code_str = b_codes[0]["code"]
        valid_burn, updated_codes = verify_and_consume_backup_code(first_code_str, b_codes)
        self.assertTrue(valid_burn)
        self.assertTrue(updated_codes[0]["used"])
        valid_replay, _ = verify_and_consume_backup_code(first_code_str, updated_codes)
        self.assertFalse(valid_replay)

    def test_02_path_traversal_and_lfi_defenses(self):
        """Vector 2: Path Traversal and Local File Inclusion Defenses."""
        traversal_payloads = [
            "/../../etc/passwd",
            "/..\\..\\windows\\win.ini",
            "/%2e%2e/%2e%2e/package.json",
            "/static/../../backend/app.py",
            "/static/..%2f..%2f.env",
            "/.env",
            "/data/db.json"
        ]
        for p in traversal_payloads:
            res = self.client.get(p)
            self.assertNotIn("SUPER_ADMIN_PASSWORD", res.text)
            self.assertNotIn("class NotificationBroadcaster", res.text)
            self.assertNotIn("root:x:0:0:", res.text)
            self.assertNotIn("[extensions]", res.text)

    def test_03_nosql_and_bson_injection_defenses(self):
        """Vector 3: NoSQL / BSON Query Operator Injection Defenses."""
        nosql_payloads = [
            {"email": {"$gt": ""}, "password": {"$gt": ""}},
            {"email": {"$ne": None}, "password": "Password123!"},
            {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"email": {"$where": "this.email == this.email"}, "password": "test"}
        ]
        for payload in nosql_payloads:
            res = self.client.post("/api/auth/login", json=payload)
            self.assertIn(res.status_code, (400, 422))

            reg_payload = {"email": payload["email"], "password": "ValidPassword#2026", "full_name": "Attacker"}
            reg_res = self.client.post("/api/auth/register", json=reg_payload)
            self.assertIn(reg_res.status_code, (400, 422))

        dirty_dict = {
            "normal": "value",
            "$gt": "malicious",
            "$where": "evil_func()",
            "nested": {"$ne": None, "safe": "ok"}
        }
        cleaned = sanitize_mongo_dict(dirty_dict)
        self.assertNotIn("$gt", cleaned)
        self.assertNotIn("$where", cleaned)
        self.assertNotIn("$ne", cleaned.get("nested", {}))
        self.assertEqual(cleaned.get("normal"), "value")

    def test_04_rbac_and_least_privilege(self):
        """Vector 4: Role-Based Access Control and Privilege Escalation Prevention."""
        user_email = f"rbac_test_{int(time.time()*1000)}@awssecurity.io"
        reg_user = self.client.post("/api/auth/register", json={
            "email": user_email,
            "password": "UserPass#2026!",
            "full_name": "Standard Priv User",
            "fingerprint": {"browser": "Chrome", "os": "Windows NT 10.0"}
        })
        self.assertEqual(reg_user.status_code, 201)

        login_res = self.client.post("/api/auth/login", json={
            "email": user_email,
            "password": "UserPass#2026!",
            "fingerprint": {"browser_id": "std_browser_001", "browser": "Chrome", "os": "Windows NT 10.0"}
        })
        self.assertEqual(login_res.status_code, 200)
        user_token = login_res.json().get("token")
        self.assertIsNotNone(user_token)
        user_headers = {"Authorization": f"Bearer {user_token}"}

        forbidden_endpoints = [
            ("DELETE", "/api/cms/users/target@awssecurity.io"),
            ("POST", "/api/system/maintenance?enable=true"),
            ("POST", "/api/system/database-reset"),
            ("POST", "/api/system/watchdog/run-now"),
            ("GET", "/api/cms/users"),
            ("GET", "/api/cms/approvals"),
            ("POST", "/api/cms/approvals/dummy_id/approve"),
            ("POST", "/api/cms/approvals/dummy_id/reject"),
        ]
        for method, ep in forbidden_endpoints:
            if method == "GET":
                r = self.client.get(ep, headers=user_headers)
            elif method == "POST":
                r = self.client.post(ep, headers=user_headers)
            elif method == "DELETE":
                r = self.client.delete(ep, headers=user_headers)
            self.assertIn(r.status_code, (401, 403), f"Endpoint {ep} improperly permitted status {r.status_code}")

        # Unauthenticated endpoints check
        unauth_endpoints = [
            ("GET", "/api/auth/me"),
            ("GET", "/api/auth/sessions"),
            ("GET", "/api/security/dispatched-notifications"),
            ("POST", "/api/auth/sessions/kill-others")
        ]
        for method, ep in unauth_endpoints:
            if method == "GET":
                r = self.client.get(ep)
            elif method == "POST":
                r = self.client.post(ep)
            self.assertEqual(r.status_code, 401)

        # Cleanup
        db.users.delete_many({"email": user_email})
        db.active_sessions.delete_many({"user_email": user_email})

    def test_05_device_tier_isolation_and_zero_leakage(self):
        """Vector 5: Primary Device Authority and Zero Data Leakage to Secondary Devices."""
        shivu_email = f"leak_test_{int(time.time()*1000)}@awssecurity.io"
        reg_shivu = self.client.post("/api/auth/register", json={
            "email": shivu_email,
            "password": "Password#2026!",
            "full_name": "Device Tester"
        })
        self.assertEqual(reg_shivu.status_code, 201)

        # Primary device login
        prim_res = self.client.post("/api/auth/login", json={
            "email": shivu_email,
            "password": "Password#2026!",
            "fingerprint": {
                "browser_id": "primary_laptop_001",
                "browser": "Chrome",
                "os": "Windows",
                "canvas_hash": "canvas_secret_hash_987",
                "screen_resolution": "1920x1080"
            },
            "spoofed_ip": "203.0.113.195"
        })
        self.assertEqual(prim_res.status_code, 200)
        prim_token = prim_res.json()["token"]
        prim_headers = {"Authorization": f"Bearer {prim_token}"}

        # Secondary device login
        sec_res = self.client.post("/api/auth/login", json={
            "email": shivu_email,
            "password": "Password#2026!",
            "fingerprint": {
                "browser_id": "secondary_phone_002",
                "browser": "Safari",
                "os": "iOS"
            },
            "spoofed_ip": "198.51.100.50"
        })
        self.assertIn(sec_res.json().get("status"), ("MFA_REQUIRED", "CHALLENGED", "SUCCESS"))

        if sec_res.json().get("status") == "MFA_REQUIRED":
            temp_token = sec_res.json()["temp_token"]
            prim_alerts = self.client.get("/api/security/user-alerts", headers=prim_headers).json()["alerts"]
            otp = None
            for a in prim_alerts:
                if a.get("verification_code"):
                    otp = a["verification_code"]
                    break
            self.assertIsNotNone(otp, "Primary device must receive OTP")

            verify_res = self.client.post("/api/auth/verify-mfa", json={
                "email": shivu_email,
                "temp_token": temp_token,
                "mfa_code": otp
            })
            self.assertEqual(verify_res.status_code, 200)
            sec_token = verify_res.json()["token"]
        else:
            sec_token = sec_res.json()["token"]

        sec_headers = {"Authorization": f"Bearer {sec_token}"}

        # TEST 1: Secondary device queries sessions - ZERO PRIMARY DATA LEAKAGE
        sec_sessions = self.client.get("/api/auth/sessions", headers=sec_headers).json()["sessions"]
        for s in sec_sessions:
            if s.get("is_primary"):
                self.assertNotIn("203.0.113.195", s.get("ip_address", ""))
                self.assertNotIn("canvas_secret_hash_987", str(s))
                self.assertEqual(s.get("ip_address"), "•••.•••.•••.•• (Protected)")

        # TEST 2: Secondary device queries alerts - NO OTP OR CHALLENGE TOKENS
        sec_alerts = self.client.get("/api/security/user-alerts", headers=sec_headers).json()["alerts"]
        for a in sec_alerts:
            self.assertFalse(bool(a.get("verification_code")))
            self.assertNotIn("temp_token", a)

        # TEST 3: Secondary device attempts mass kill-switch - MUST BE BLOCKED
        kill_res = self.client.post("/api/auth/sessions/kill-others", headers=sec_headers)
        self.assertEqual(kill_res.status_code, 403)

        # Cleanup
        db.users.delete_many({"email": shivu_email})
        db.active_sessions.delete_many({"user_email": shivu_email})

    def test_06_watchdog_daemon_and_service_worker(self):
        """Vector 6: System Watchdog Daemon & Service Worker Root Scope."""
        sw_res = self.client.get("/sw.js")
        self.assertEqual(sw_res.status_code, 200)
        self.assertIn("Service-Worker-Allowed", sw_res.headers)
        self.assertEqual(sw_res.headers["Service-Worker-Allowed"], "/")

        wd_status = self.client.get("/api/system/watchdog/status").json()
        self.assertTrue(wd_status.get("watchdog_active"))
        self.assertEqual(wd_status.get("interval_seconds"), 3600)

        wd_audit = self.client.post("/api/system/watchdog/run-now").json()
        self.assertIn(wd_audit.get("overall_status"), ("HEALTHY", "DEGRADED"))
        self.assertEqual(wd_audit.get("components", {}).get("database", {}).get("status"), "HEALTHY")
        self.assertEqual(wd_audit.get("components", {}).get("sessions", {}).get("status"), "HEALTHY")

    def test_07_zero_hardcoded_secrets_and_backdoors(self):
        """Vector 7: Automated Secrets & Backdoor Zero-Tolerance Probe.
        Guarantees that no raw database connection strings, live cloud credentials,
        or unauthenticated backdoor endpoints exist in the repository.
        """
        forbidden_patterns = [
            (re.compile(r"mongodb\+srv://[^:]+:[^@]+@", re.IGNORECASE), "Exposed live MongoDB Atlas URI with credentials"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "Hardcoded AWS Access Key ID"),
            (re.compile(r"/api/temp-reset"), "Rogue backdoor /api/temp-reset endpoint"),
            (re.compile(r"V33Ryxrh8VtUD83I"), "Leaked legacy database password"),
            (re.compile(r"likitha@2005"), "Hardcoded administrator password"),
        ]

        scanned_extensions = (".py", ".js", ".json", ".bat", ".ps1", ".md", ".sh")
        ignore_dirs = {".git", "__pycache__", "venv", ".venv", "env", "node_modules"}

        violations = []

        for root, dirs, files in os.walk(PROJECT_ROOT):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                # Do not scan scanner scripts or this test file itself for literal regex definitions
                if file in ("test_deep_security_probe.py", "pre_commit_secrets_check.py", "audit_security.py"):
                    continue
                if file.endswith(scanned_extensions):
                    fpath = os.path.join(root, file)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            for idx, line in enumerate(f, 1):
                                for pattern, desc in forbidden_patterns:
                                    if pattern.search(line):
                                        violations.append(f"{os.path.relpath(fpath, PROJECT_ROOT)}:{idx} -> {desc}")
                    except Exception:
                        pass

        self.assertEqual(len(violations), 0, f"Critical Security Leak Detected!\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
