"""
Primary vs Secondary Device Flow & Portal Preservation Verification Test
Tests:
1. First login prompt for primary device designation.
2. Designation of primary device.
3. Secondary device login with same credentials (tagged as SECONDARY, alert generated).
4. Secondary device restricted from killing primary session (403 Forbidden).
5. Primary portal terminates secondary session while remaining logged in.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi.testclient import TestClient
from backend.app import app
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter

client = TestClient(app)

def test_primary_device_full_flow():
    print("\n=======================================================")
    print("[TEST] PRIMARY VS SECONDARY DEVICE WORKFLOW VERIFICATION")
    print("=======================================================")

    test_email = "test_device_tier@awssecurity.io"
    test_password = "SecurePassword#2026"

    # 1. Clean up & register fresh user
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})
    rate_limiter.clear_all()

    reg_resp = client.post("/api/auth/register", json={
        "email": test_email,
        "full_name": "Device Tester",
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_primary_001",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary"
        }
    })
    assert reg_resp.status_code == 201, f"Registration failed: {reg_resp.text}"
    print("[Step 1] User registered successfully.")

    # 2. First login from Browser 1 (Chrome)
    login1_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_primary_001",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary"
        }
    })
    assert login1_resp.status_code == 200, f"Login 1 failed: {login1_resp.text}"
    data1 = login1_resp.json()
    token1 = data1["token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    print(f"[Step 2] Browser 1 login -> device_tier: {data1.get('device_tier')}, is_primary: {data1.get('is_primary_device')}")
    assert data1.get("device_tier") == "PRIMARY"
    assert data1.get("is_primary_device") is True

    # 3. Designate / Update Browser 1 as Primary Device with Secondary Password
    set_prim_resp = client.post("/api/auth/devices/set-primary", headers=headers1, json={
        "is_primary": True,
        "device_label": "Primary Security Portal (Chrome on Windows)",
        "secondary_password": "MasterKey#2026"
    })
    assert set_prim_resp.status_code == 200, f"Set primary failed: {set_prim_resp.text}"
    print(f"[Step 3] Verified Browser 1 as primary device: {set_prim_resp.json()['message']}")

    # Verify user profile reflects primary device
    me1 = client.get("/api/auth/me", headers=headers1).json()
    assert me1.get("primary_device") is not None
    assert me1.get("device_tier") == "PRIMARY"
    assert me1.get("is_primary_device") is True
    print(f"  -> Profile verified: device_tier={me1['device_tier']}, is_primary_device={me1['is_primary_device']}")

    # 4. Same machine, different browser instance -> Cross-Device MFA Challenge dispatched to Primary Device!
    print("\n[Step 4] Logging into Browser 2 (Same PC, Chrome Incognito with same canvas_hash)...")
    login2_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_incognito_002",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary" # Identical canvas on same physical PC!
        }
    })
    assert login2_resp.status_code == 200, f"Login 2 failed: {login2_resp.text}"
    data2 = login2_resp.json()
    assert data2.get("status") == "MFA_REQUIRED", "Secondary device sign-in must trigger MFA challenge!"
    temp_token = data2["temp_token"]
    print(f"  -> Browser 2 received MFA challenge (temp_token: {temp_token})")

    # 5. Primary Device (Browser 1) receives approval request with verification code
    alerts_b1 = client.get("/api/security/user-alerts", headers=headers1).json()["alerts"]
    sec_alert = next((a for a in alerts_b1 if a.get("type") == "SECONDARY_DEVICE_APPROVAL_REQUEST" and a.get("temp_token") == temp_token), None)
    assert sec_alert is not None, "SECONDARY_DEVICE_APPROVAL_REQUEST alert missing on Primary Device!"
    print(f"[Step 5] Primary Device received approval alert! Verification Code: {sec_alert['verification_code']}")

    # Browser 1 approves secondary device
    approve_res = client.post("/api/auth/devices/approve-secondary", headers=headers1, json={
        "temp_token": temp_token,
        "approved": True
    })
    assert approve_res.status_code == 200

    # Browser 2 polling succeeds and obtains session token
    poll_res = client.get(f"/api/auth/mfa-poll/{temp_token}").json()
    assert poll_res.get("status") == "APPROVED"
    token2 = poll_res["token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # 6. Secondary Device (Browser 2) attempts to terminate Primary Session -> Must be 403 Forbidden!
    sessions_b2 = client.get("/api/auth/sessions", headers=headers2).json()["sessions"]
    print(f"\n[Step 6] Browser 2 views active sessions: {len(sessions_b2)} total")
    primary_sess = next((s for s in sessions_b2 if s.get("device_tier") == "PRIMARY"), None)
    assert primary_sess is not None, "Primary session not visible in sessions list"

    print(f"  -> Browser 2 attempting to kill Primary Session ({primary_sess['session_id']})...")
    kill_attempt = client.post("/api/auth/sessions/kill", headers=headers2, json={
        "session_id": primary_sess["session_id"]
    })
    print(f"  -> Response Status Code: {kill_attempt.status_code}")
    assert kill_attempt.status_code == 403, f"Expected 403 Forbidden, got {kill_attempt.status_code}: {kill_attempt.text}"
    print(f"  -> Correctly blocked by policy: {kill_attempt.json().get('detail')}")

    # 7. Primary Device (Browser 1) terminates other sessions
    print("\n[Step 7] Browser 1 terminates other sessions...")
    kill_others = client.post("/api/auth/sessions/kill-others", headers=headers1)
    assert kill_others.status_code == 200
    print(f"  -> Terminate others result: {kill_others.json()['message']}")

    # 8. Verify Primary Portal is STILL LOGGED IN (Preserved!)
    check_b1 = client.get("/api/auth/me", headers=headers1)
    assert check_b1.status_code == 200, f"Primary portal was unexpectedly logged out! Got {check_b1.status_code}"
    print("  -> Browser 1 (Primary Portal) is STILL ACTIVE (HTTP 200 OK)!")

    # 9. Verify Secondary Device is REVOKED
    check_b2 = client.get("/api/auth/me", headers=headers2)
    assert check_b2.status_code == 401, f"Secondary session was not revoked! Got {check_b2.status_code}"
    print("  -> Browser 2 (Secondary Device) was successfully revoked (HTTP 401 Unauthorized)!")

    # Clean up test user
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})

    print("\n[SUCCESS] PRIMARY VS SECONDARY DEVICE WORKFLOW VERIFIED 100% WORKING!")
    print("=======================================================\n")


def test_secondary_device_verify_mfa_resolves_approval_alert():
    """Verify entering the verification code on the secondary device marks the approval alert resolved."""
    test_email = "test_mfa_popup_dismiss@awssecurity.io"
    test_pwd = "MfaPopupPassword#2026"

    # Cleanup
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})
    rate_limiter.clear_all()

    # Register
    reg = client.post("/api/auth/register", json={
        "email": test_email,
        "full_name": "Popup Dismiss Tester",
        "password": test_pwd,
        "fingerprint": {"browser": "Chrome", "browser_id": "b1_primary_fp", "os": "Windows NT 10.0"}
    })
    assert reg.status_code == 201

    # Login Primary Device
    login1 = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_pwd,
        "fingerprint": {"browser": "Chrome", "browser_id": "b1_primary_fp", "os": "Windows NT 10.0"}
    })
    assert login1.status_code == 200
    token1 = login1.json()["token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # Set as Primary Device
    set_prim = client.post("/api/auth/devices/set-primary", headers=headers1, json={
        "is_primary": True,
        "device_label": "Primary Security Portal (Desktop)",
        "secondary_password": "MasterKey#2026"
    })
    assert set_prim.status_code == 200

    # Secondary Device signs in -> triggers MFA_REQUIRED
    login2 = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_pwd,
        "fingerprint": {"browser": "Firefox", "browser_id": "b2_secondary_fp", "os": "Linux"}
    })
    assert login2.status_code == 200
    data2 = login2.json()
    assert data2["status"] == "MFA_REQUIRED"
    temp_token = data2["temp_token"]

    # Primary Device gets the approval request alert containing the 6-digit code
    alerts1 = client.get("/api/security/user-alerts", headers=headers1).json()["alerts"]
    sec_alert = next((a for a in alerts1 if a.get("temp_token") == temp_token and a.get("type") == "SECONDARY_DEVICE_APPROVAL_REQUEST"), None)
    assert sec_alert is not None
    assert sec_alert["status"] == "PENDING_APPROVAL"
    code = sec_alert["verification_code"]
    assert len(code) == 6

    # Secondary Device enters code into /api/auth/verify-mfa
    verify_res = client.post("/api/auth/verify-mfa", json={
        "email": test_email,
        "temp_token": temp_token,
        "mfa_code": code
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "SUCCESS"
    token2 = verify_res.json()["token"]

    # Verify that the alert is now marked RESOLVED_VERIFIED in the DB
    updated_alerts = client.get("/api/security/user-alerts", headers=headers1).json()["alerts"]
    resolved_alert = next((a for a in updated_alerts if a.get("temp_token") == temp_token), None)
    assert resolved_alert is not None
    assert resolved_alert["status"] == "RESOLVED_VERIFIED"

    # Verify there are NO pending approval alerts left
    pending_alerts = [a for a in updated_alerts if a.get("type") == "SECONDARY_DEVICE_APPROVAL_REQUEST" and a.get("status") == "PENDING_APPROVAL"]
    assert len(pending_alerts) == 0

    # Cleanup
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})


if __name__ == "__main__":
    test_primary_device_full_flow()
    test_secondary_device_verify_mfa_resolves_approval_alert()
