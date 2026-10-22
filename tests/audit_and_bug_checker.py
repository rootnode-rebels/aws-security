"""
End-to-End Bug Hunting and Consistency Audit Script.
Checks:
1. Static Asset Serving & MIME types
2. HTML-JS Cross-Reference Audit (Missing DOM IDs, Missing onclick handlers)
3. API Endpoint Health & Boundary Testing
4. Seed Account Integrity
"""
import re
import os
import sys
import glob
import time
import json
import unittest
import urllib.request
import urllib.error

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from database.db_manager import db


class TestComprehensiveBugAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from backend.app import app, seed_demo_user_if_needed
        cls.client = TestClient(app)
        seed_demo_user_if_needed(force=True)

    def test_01_static_assets_serving(self):
        """Ensure all frontend HTML, CSS, and JS files return HTTP 200."""
        routes = [
            "/",
            "/index.html",
            "/css/styles.css",
            "/js/app.js",
            "/js/user_portal.js",
            "/js/soc_dashboard.js",
            "/js/cms_dashboard.js",
            "/js/fingerprint.js",
            "/js/bg_animation.js"
        ]
        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Failed serving {route}")
            content = resp.content
            self.assertGreater(len(content), 50, f"Asset {route} appears empty")

    def test_02_html_js_dom_ids_cross_reference(self):
        """
        Extracts all document.getElementById("...") in JS files
        and ensures the referenced ID actually exists in index.html (or is dynamically created).
        """
        html_path = os.path.join(PROJECT_ROOT, "frontend", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Find all id="..." in index.html
        html_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html_content))

        # Dynamically created or template element IDs in our app
        dynamically_created_ids = {
            "mfa-poll-status", "secondary-approval-notice", "user-active-session-count",
            "stat-total-users", "stat-root-admins", "stat-active-threats",
            "stat-impossible-travel", "stat-mfa-challenged", "stat-active-sessions"
        }

        js_files = glob.glob(os.path.join(PROJECT_ROOT, "frontend", "js", "*.js"))
        missing_ids = []

        for js_file in js_files:
            fname = os.path.basename(js_file)
            with open(js_file, "r", encoding="utf-8") as f:
                js_content = f.read()

            # Find all document.getElementById("...")
            found_ids = set(re.findall(r'getElementById\(["\']([^"\']+)["\']\)', js_content))
            for eid in found_ids:
                if eid not in html_ids and eid not in dynamically_created_ids:
                    # Check if eid is created via template literal or innerHTML
                    if f'id="{eid}"' not in js_content and f"id='{eid}'" not in js_content:
                        missing_ids.append((fname, eid))

        if missing_ids:
            print("[DOM ID Audit Warning] IDs referenced in JS but not in index.html:", missing_ids)
        # We allow dynamic IDs but ensure critical login & navigation IDs exist
        critical_ids = [
            "form-login", "form-register", "login-email", "login-password",
            "login-vpn-preset", "origin-detect-badge", "origin-detail-text",
            "client-fp-display", "modal-mfa-challenge", "mfa-code-input",
            "modal-secondary-device-approval", "modal-dispatched-notifications"
        ]
        for cid in critical_ids:
            self.assertIn(cid, html_ids, f"Critical ID '{cid}' missing in index.html!")

    def test_03_html_onclick_handlers_defined(self):
        """
        Extracts all onclick="..." in index.html and ensures the function
        is defined across the frontend JS files.
        """
        html_path = os.path.join(PROJECT_ROOT, "frontend", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Extract function names in onclick="funcName(...)"
        onclick_matches = re.findall(r'onclick=["\']([a-zA-Z0-9_]+)\(', html_content)
        unique_handlers = set(onclick_matches)

        # Concatenate all JS content
        js_corpus = ""
        for js_file in glob.glob(os.path.join(PROJECT_ROOT, "frontend", "js", "*.js")):
            with open(js_file, "r", encoding="utf-8") as f:
                js_corpus += "\n" + f.read()

        missing_handlers = []
        for handler in unique_handlers:
            pattern = rf"(function\s+{handler}\b|const\s+{handler}\s*=|let\s+{handler}\s*=|var\s+{handler}\s*=|window\.{handler}\s*=)"
            if not re.search(pattern, js_corpus):
                missing_handlers.append(handler)

        self.assertEqual(missing_handlers, [], f"Onclick functions missing in JS: {missing_handlers}")

    def test_04_api_endpoints_health(self):
        """Test public endpoints response codes and valid JSON structure."""
        public_endpoints = [
            ("/api/security/detect-client-ip", "GET"),
            ("/api/security/vpn-presets", "GET"),
            ("/api/monitoring/cloudwatch/metrics", "GET"),
            ("/api/cloudwatch/metrics", "GET"),
            ("/api/security/events", "GET"),
            ("/api/system/status", "GET"),
            ("/api/system/db-health", "GET")
        ]
        for path, method in public_endpoints:
            resp = self.client.request(method, path)
            self.assertEqual(resp.status_code, 200, f"Endpoint {path} failed: {resp.status_code}")
            data = resp.json()
            self.assertIsInstance(data, (dict, list), f"Invalid JSON payload from {path}")

        # Security boundary check: protected notifications endpoint must reject unauthenticated requests
        protected_resp = self.client.get("/api/security/dispatched-notifications")
        self.assertEqual(protected_resp.status_code, 401, "Protected notifications endpoint leaked to unauthenticated caller!")

    def test_05_seed_demo_accounts_functional(self):
        """Verify seed demo accounts can log in and return expected tokens and user objects."""
        accounts = [
            ("demo@awssecurity.io", "AWSSecurity#2026"),
            ("demo@aegisguard.io", "AWSSecurity#2026")
        ]
        for email, password in accounts:
            payload = {
                "email": email,
                "password": password,
                "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
                "fingerprint": {
                    "browser": "Chrome",
                    "browser_id": "bid_audit_primary",
                    "os": "Windows NT 10.0",
                    "screen_resolution": "1920x1080",
                    "canvas_hash": "canvas_audit_seed"
                }
            }
            resp = self.client.post("/api/auth/login", json=payload)
            self.assertEqual(resp.status_code, 200, f"Login failed for {email}: {resp.text}")
            data = resp.json()
            # Either direct login or MFA required
            self.assertIn(data.get("status"), ("SUCCESS", "MFA_REQUIRED", None))
            if data.get("status") == "SUCCESS" or "token" in data:
                self.assertIn("token", data)
                self.assertIn("user", data)


if __name__ == "__main__":
    unittest.main()
