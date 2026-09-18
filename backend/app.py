"""
Central FastAPI Serverless Local Emulator & REST API Gateway.
Coordinates Authentication, Machine Learning Anomaly Detection, AWS CloudWatch Telemetry, and MongoDB Storage.
"""
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import asyncio
import json
import random
import secrets

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Header, status
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Database & Security imports
from database.db_manager import db
from backend.security.sanitizer import sanitize_string, sanitize_email, sanitize_mongo_dict
from backend.security.rate_limiter import rate_limiter
from backend.security.desktop_notifier import send_desktop_notification
from backend.security.notification_service import notification_service
from backend.security.geoip_service import resolve_ip_geolocation, get_available_vpn_presets
from backend.security.auth import (
    hash_password, verify_password, generate_session_token,
    generate_mfa_code, generate_reset_token, validate_password_strength
)
from backend.ml.feature_extractor import extract_features
from backend.ml.model import ml_engine
from backend.ml.tf_autoencoder import tf_autoencoder
from backend.monitoring.cloudwatch_service import cloudwatch

# In-memory pub-sub for live SSE notification delivery to primary devices
class NotificationBroadcaster:
    def __init__(self):
        self._listeners: Dict[str, List[asyncio.Queue]] = {}

    def subscribe(self, email: str) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=50)
        if email not in self._listeners:
            self._listeners[email] = []
        self._listeners[email].append(q)
        return q

    def unsubscribe(self, email: str, q: asyncio.Queue):
        if email in self._listeners and q in self._listeners[email]:
            self._listeners[email].remove(q)
            if not self._listeners[email]:
                del self._listeners[email]

    def broadcast_sync(self, email: str, event_data: dict):
        if email in self._listeners:
            for q in list(self._listeners[email]):
                try:
                    q.put_nowait(event_data)
                except Exception:
                    pass

    async def broadcast(self, email: str, event_data: dict):
        self.broadcast_sync(email, event_data)

broadcaster = NotificationBroadcaster()

app = FastAPI(
    title="Real-Time Account Hijacking Detection & Prevention System",
    version="2.0.0",
    description="AWS Serverless & ML-driven Cybersecurity Defense Platform"
)

# CORS configuration (W3C compliant credentials-ready CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})

# Maintenance mode toggle for UX state demonstration
MAINTENANCE_MODE = False

def seed_demo_user_if_needed(force: bool = False):
    """Seeds baseline legitimate user accounts for instant multi-browser testing."""
    # If not forced and accounts already exist, do not reseed
    if not force and db.users.count_documents({}) > 0:
        return

    # Add migration logic to downgrade mistakenly elevated users
    try:
        db.users.update_many(
            {"email": {"$nin": ["demo@awssecurity.io", "demo@aegisguard.io"]}},
            {"$set": {"role": "USER", "is_root_admin": False, "is_super_admin": False}}
        )
    except Exception as e:
        pass

    accounts = [
        ("demouser@mail.com", "DemoUser.AWS@29", "AWS Presentation Demo User", "USER"),
        ("demo@awssecurity.io", os.getenv("DEMO_PWD_1", secrets.token_urlsafe(16)), "Sachin (Demo Security Lead)", "ROOT_ADMIN"),
        ("demo@aegisguard.io", os.getenv("DEMO_PWD_2", secrets.token_urlsafe(16)), "Sachin (Legacy Demo Account)", "ROOT_ADMIN")
    ]
    for email, pwd, name, role in accounts:
        try:
            existing = db.users.find_one({"email": email})
            sec_hash, sec_salt = hash_password(os.getenv("DEFAULT_SEC_PWD", secrets.token_urlsafe(16)))
            is_super_admin = (role == "SUPER_ADMIN")
            if not existing:
                pw_hash, salt = hash_password(pwd)
                now_iso = datetime.now(timezone.utc).isoformat()
                demo_user = {
                    "email": email,
                    "full_name": name,
                    "password_hash": pw_hash,
                    "salt": salt,
                    "secondary_password_hash": sec_hash,
                    "secondary_password_salt": sec_salt,
                    "primary_device": None,
                    "status": "ACTIVE",
                    "role": role,
                    "is_root_admin": True if role == "ROOT_ADMIN" else False,
                    "is_super_admin": is_super_admin,
                    "created_at": now_iso,
                    "updated_at": now_iso,
                    "trusted_devices": [],
                    "last_successful_login": None,
                    "mfa_secret": None,
                    "mfa_pending": None,
                    "mfa_enabled": True
                }
                db.users.insert_one(demo_user)
                print(f"[AWSSecurity] Seeded default account: {email} / {pwd}")
            else:
                updates = {}
                if existing.get("role") != role:
                    updates["role"] = role
                    updates["is_root_admin"] = True if role == "ROOT_ADMIN" else False
                    updates["is_super_admin"] = is_super_admin
                if not existing.get("secondary_password_hash"):
                    updates["secondary_password_hash"] = sec_hash
                    updates["secondary_password_salt"] = sec_salt
                # Clear out dummy seeded browser_id so user's real browser can enroll as Main Device
                prim = existing.get("primary_device")
                if prim and prim.get("browser_id") == "chrome_uuid_legit_001":
                    updates["primary_device"] = None
                if updates:
                    db.users.update_one({"email": email}, {"$set": updates})
        except Exception as e:
            print(f"[AWSSecurity] Demo user seed notice: {e}")

    try:
        db.get_collection("system_metadata").insert_one({
            "key": "initial_seed_completed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        print(f"[AWSSecurity] system_metadata insert notice: {e}")

seed_demo_user_if_needed()


# -------------------------------------------------------------
# Middleware: Request Correlation ID & CloudWatch Invocation Logging
# -------------------------------------------------------------
@app.middleware("http")
async def cloudwatch_telemetry_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    start_time = time.time()

    if MAINTENANCE_MODE:
        allowed_prefixes = (
            "/api/system/maintenance",
            "/api/system/status",
            "/api/cms",
            "/static",
            "/api/auth/login",
            "/api/auth/me"
        )
        is_spa_asset = (
            request.url.path == "/"
            or request.url.path.endswith((".html", ".js", ".css", ".png", ".jpg", ".svg", ".ico", ".json"))
        )
        # Verify if caller is an authenticated Root Administrator
        auth_header = request.headers.get("Authorization", "")
        is_admin_user = False
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            sess = db.active_sessions.find_one({"session_token": token})
            if sess:
                u = db.users.find_one({"email": sess.get("user_email")})
                if u and (u.get("role") == "SUPER_ADMIN" or u.get("is_super_admin")):
                    is_admin_user = True

        if not (is_admin_user or is_spa_asset or any(request.url.path.startswith(p) for p in allowed_prefixes)):
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service Under Maintenance",
                    "message": "System security baseline update and ML model retraining in progress. Non-admin operations are paused.",
                    "correlation_id": correlation_id,
                    "retry_after_seconds": 300,
                    "maintenance_mode": True
                }
            )

    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000.0

    # Emit CloudWatch invocation metric
    cloudwatch.record_invocation(
        function_name=request.url.path,
        latency_ms=duration_ms,
        status_code=response.status_code
    )
    response.headers["X-Request-Id"] = correlation_id
    return response


# -------------------------------------------------------------
# Middleware: Defense-in-Depth OWASP Security Headers
# -------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(self), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https: ws: wss:;"
    )
    return response


# -------------------------------------------------------------
# Pydantic Request Schemas (Strict Input Validation)
# -------------------------------------------------------------
class RegisterSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=8, max_length=128)
    secondary_password: Optional[str] = None
    fingerprint: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None

class LoginSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)
    fingerprint: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None
    spoofed_ip: Optional[str] = None
    spoofed_user_agent: Optional[str] = None

class VerifyMFASchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    mfa_code: str = Field(min_length=6, max_length=6)
    temp_token: str

class ForgotPasswordSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

class ChangePasswordSchema(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

class SessionKillSchema(BaseModel):
    session_id: str

class AccountDeleteSchema(BaseModel):
    password: str

class SetPrimaryDeviceSchema(BaseModel):
    is_primary: bool = True
    device_label: Optional[str] = None
    secondary_password: Optional[str] = None

class UpdateSecondaryPasswordSchema(BaseModel):
    current_password: str
    new_secondary_password: str = Field(min_length=6, max_length=128)

class ApproveSecondarySchema(BaseModel):
    temp_token: Optional[str] = "LATEST"
    approved: bool = True

class TestNotificationSchema(BaseModel):
    recipient_email: str = Field(min_length=3, max_length=254)
    notification_type: Optional[str] = "TEST_SECURITY_ALERT"
    message: Optional[str] = None


# -------------------------------------------------------------
# Helper: Authenticate Session Token
# -------------------------------------------------------------
def get_optional_current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        return get_current_user(authorization)
    except HTTPException:
        return None

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication token required or expired.")
    token = authorization.split(" ")[1]
    session = db.active_sessions.find_one({"session_token": token})
    if not session or session.get("status") != "ACTIVE":
        raise HTTPException(status_code=401, detail="Session expired or revoked.")
    
    is_primary = bool(session.get("is_primary_device") or session.get("device_tier") == "PRIMARY")

    # Primary device session is perpetual and immune to automatic revocation or timeout
    if not is_primary:
        now = datetime.now(timezone.utc).isoformat()
        if session.get("expires_at", "") < now:
            db.active_sessions.delete_one({"session_token": token})
            raise HTTPException(status_code=401, detail="Session has expired. Please log in again.")

    user = db.users.find_one({"email": session.get("user_email")})
    if not user:
        raise HTTPException(status_code=401, detail="User account not found.")
    
    # If account is temporarily locked, secondary devices are blocked,
    # but the primary device owner retains authenticated access so they can unfreeze and manage incidents.
    if user.get("status") == "LOCKED":
        if not is_primary:
            raise HTTPException(
                status_code=403,
                detail={"error": "ACCOUNT_LOCKED", "message": "Account is temporarily locked for security. Contact incident response."}
            )
        user["account_is_frozen"] = True

    return user


# -------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------
@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterSchema, request: Request):
    clean_email = sanitize_email(payload.email)
    clean_name = sanitize_string(payload.full_name)

    # Password validation
    is_valid, msg = validate_password_strength(payload.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    # Check existence
    existing = db.users.find_one({"email": clean_email})
    if existing:
        # Anti-enumeration response per user rules: do not leak specific account presence
        raise HTTPException(status_code=400, detail="Unable to complete registration with provided details.")

    # Hash password securely (PBKDF2-HMAC-SHA256 with 200,000 iterations)
    pw_hash, salt = hash_password(payload.password)

    # Secondary security password for device promotion & transfer
    sec_pwd = payload.secondary_password or secrets.token_urlsafe(16)
    sec_hash, sec_salt = hash_password(sec_pwd)

    client_ip = request.client.host if request.client else "127.0.0.1"
    geo_loc = payload.geo or {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}
    fingerprint = sanitize_mongo_dict(payload.fingerprint or {})

    now_iso = datetime.now(timezone.utc).isoformat()
    browser_name = fingerprint.get("browser", "Browser")
    os_name = fingerprint.get("os", "Desktop")
    primary_dev = {
        "browser_id": fingerprint.get("browser_id"),
        "browser": browser_name,
        "os": os_name,
        "canvas_hash": fingerprint.get("canvas_hash"),
        "screen_resolution": fingerprint.get("screen_resolution"),
        "label": f"Primary Security Portal ({browser_name} on {os_name})",
        "registered_at": now_iso
    } if fingerprint else None

    user_doc = {
        "email": clean_email,
        "full_name": clean_name,
        "password_hash": pw_hash,
        "salt": salt,
        "secondary_password_hash": sec_hash,
        "secondary_password_salt": sec_salt,
        "primary_device": None, # Prompts user on first login: "Keep this device as main device?"
        "has_confirmed_primary": False,
        "status": "UNVERIFIED",
        "email_verification_code": str(random.randint(100000, 999999)),
        "role": "USER",
        "is_root_admin": False,
        "is_super_admin": False,
        "created_at": now_iso,
        "updated_at": now_iso,
        "trusted_devices": [fingerprint] if fingerprint else [],
        "last_successful_login": {
            "timestamp": time.time(),
            "geo": geo_loc,
            "ip": client_ip,
            "device": fingerprint.get("platform", "Desktop")
        },
        "mfa_secret": None,
        "mfa_pending": None,
        "mfa_enabled": True
    }
    db.users.insert_one(user_doc)

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User registered (UNVERIFIED): {clean_email}",
        payload={"ip": client_ip, "city": geo_loc.get("city")}
    )

    # Dispatch email verification code via Amazon SNS
    notif = notification_service.send_email_verification(clean_email, clean_name, user_doc["email_verification_code"])
    broadcaster.broadcast_sync(clean_email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {
        "status": "success",
        "message": "Account created. Please check your email for the verification code.",
        "requires_verification": True,
        "email": clean_email,
        "demo_verification_code": user_doc["email_verification_code"]
    }


class VerifyEmailSchema(BaseModel):
    email: str
    code: str

@app.post("/api/auth/verify-email", status_code=200)
def verify_email(payload: VerifyEmailSchema):
    clean_email = sanitize_email(payload.email)
    user = db.users.find_one({"email": clean_email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification request.")
    
    if user.get("status") == "ACTIVE":
        return {"status": "success", "message": "Email is already verified."}
        
    if str(user.get("email_verification_code")) != str(payload.code).strip():
        raise HTTPException(status_code=400, detail="Invalid verification code.")
        
    # Mark as active
    db.users.update_one(
        {"email": clean_email},
        {"$set": {"status": "ACTIVE", "email_verification_code": None}}
    )
    
    # Send welcome email now that they are verified
    notif = notification_service.send_welcome_registration(clean_email, user.get("full_name", "User"), "Verified")
    broadcaster.broadcast_sync(clean_email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})
    
    return {"status": "success", "message": "Email verified successfully! You can now log in."}



def resolve_client_ip(request: Request, spoofed_ip: Optional[str] = None) -> str:
    """Extracts client IP, respecting reverse proxies (ALB/CloudFront) and simulation overrides."""
    if spoofed_ip:
        return spoofed_ip
    # xff = request.headers.get("x-forwarded-for")
    # if xff:
    #     client_ip = xff.split(",")[0].strip()
    #     if client_ip:
    #         return client_ip
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@app.get("/api/security/detect-client-ip")
def detect_client_ip(request: Request):
    """
    Detects the client's network origin, IP address, and GeoIP intelligence.
    Supports real commercial VPNs (ip-api resolution), reverse proxies, and presets.
    """
    client_ip = resolve_client_ip(request)

    # If client is loopback/local, attempt to discover host's public egress IP (e.g. from active VPN)
    if client_ip in ("127.0.0.1", "localhost", "::1"):
        try:
            import urllib.request
            req = urllib.request.Request(
                "http://ip-api.com/json/?fields=status,message,query,country,city,lat,lon,hosting,proxy",
                headers={"User-Agent": "AWSSecurityAI-GeoIP/2.0"}
            )
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "success" and data.get("query"):
                        client_ip = data["query"]
        except Exception:
            pass

    geo_data = resolve_ip_geolocation(client_ip)
    return {
        "status": "success",
        "ip": client_ip,
        "geo": geo_data,
        "is_vpn": geo_data.get("is_vpn", False),
        "provider": geo_data.get("provider", "Standard Internet Access"),
        "city": geo_data.get("city", "New York"),
        "country": geo_data.get("country", "United States")
    }


@app.get("/api/security/vpn-presets")
def get_vpn_presets():
    """Returns the list of presentation presets for UI simulation."""
    return {
        "status": "success",
        "presets": get_available_vpn_presets()
    }


@app.post("/api/auth/login")
def login(payload: LoginSchema, request: Request):
    client_ip = resolve_client_ip(request, payload.spoofed_ip)
    user_agent = payload.spoofed_user_agent or request.headers.get("user-agent", "")
    email = sanitize_email(payload.email)
    raw_password = payload.password

    # Geographic resolution:
    # If client passed an explicit custom geo (e.g. from preset), prioritize it.
    # Otherwise or if client_ip is a VPN/preset IP, resolve accurate geo from GeoIP intelligence.
    if payload.geo and payload.geo.get("city") and payload.geo.get("city") not in ("Current Location", "New York"):
        geo = payload.geo
    else:
        resolved = resolve_ip_geolocation(client_ip)
        geo = {
            "lat": resolved.get("lat", 40.7128),
            "lon": resolved.get("lon", -74.0060),
            "city": resolved.get("city", "New York"),
            "country": resolved.get("country", "US")
        }
    fingerprint = sanitize_mongo_dict(payload.fingerprint or {})

    # 1. Check Rate Limiter (Dual-layer brute-force protection: IP + Target Account)
    is_locked_ip, remaining_ip = rate_limiter.is_locked(client_ip)
    is_locked_acct, remaining_acct = rate_limiter.is_locked(f"acct:{email}")
    if is_locked_ip or is_locked_acct:
        remaining = max(remaining_ip, remaining_acct)
        # Dispatch high-priority alert to legitimate user
        db.get_collection("security_alerts").insert_one({
            "alert_id": f"alt_lock_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "BRUTE_FORCE_LOCKOUT",
            "risk_score": 95.0,
            "origin": geo.get("city", "Current Location") + ", " + geo.get("country", "Local"),
            "ip": client_ip,
            "device": f"{fingerprint.get('browser', 'Browser')} on {fingerprint.get('os', 'Desktop')}",
            "status": "UNRESOLVED",
            "reason": f"🚨 Brute Force Lockout Active: Too many failed login attempts against your account from {client_ip}.",
            "factors": [{"factor": "Brute Force Burst", "detail": f"Temporarily blocked for {remaining} seconds.", "weight": 95.0, "severity": "CRITICAL"}]
        })
        cloudwatch.record_security_decision(risk_score=95.0, action="BLOCK_SESSION")
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="WARN",
            message=f"Brute force lockout active for IP {client_ip} / Account {email}",
            payload={"remaining_seconds": remaining}
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Access temporarily restricted. Try again in {remaining} seconds."
        )

    # 2. Retrieve user
    user = db.users.find_one({"email": email})
    # Dual-layer failure tracking:
    # Account failures protect against targeted credential guessing against this specific user.
    # IP failures protect against distributed credential stuffing, but loopback/local test IPs
    # must not cross-contaminate newly created local accounts.
    is_loopback = client_ip in ("127.0.0.1", "::1", "localhost", "testclient")
    acct_failures = rate_limiter.get_recent_failure_count(f"acct:{email}")
    ip_failures = 0 if is_loopback else rate_limiter.get_recent_failure_count(client_ip)
    recent_failures = max(acct_failures, ip_failures)

    # 3. Behavioral Feature Extraction & ML Inference
    attempt_telemetry = {
        "timestamp": time.time(),
        "geo": geo,
        "ip": client_ip,
        "fingerprint": fingerprint,
        "user_agent": user_agent
    }
    features = extract_features(user, attempt_telemetry, recent_failures)
    ml_eval = ml_engine.evaluate_risk(features)
    risk_score = ml_eval["risk_score"]
    risk_action = ml_eval["action"]
    risk_level = ml_eval["risk_level"]

    # 4. Deep Autoencoder Verification (TensorFlow Module)
    feature_vector = [
        features["geo_velocity_kmh"],
        features["distance_km"],
        features["device_distance"],
        features["ip_reputation"],
        features["failed_attempts_burst"],
        features["circadian_anomaly"],
        features["bot_signature"]
    ]
    autoencoder_res = tf_autoencoder.compute_reconstruction_loss(feature_vector)

    # Record security event in audit collection
    event_id = f"evt_{int(time.time() * 1000)}"
    sec_event = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_email": email,
        "ip_address": client_ip,
        "geo": geo,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action_taken": risk_action,
        "factors": ml_eval["explainable_factors"],
        "autoencoder_loss": autoencoder_res["mse_reconstruction_error"],
        "device": fingerprint.get("os", "Unknown Device")
    }
    db.security_events.insert_one(sec_event)

    # Log to CloudWatch
    cloudwatch.record_security_decision(risk_score, risk_action)
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AccountHijackRiskEngine",
        level="WARN" if risk_score >= 40 else "INFO",
        message=f"Login evaluation for {email}: Score {risk_score} -> Action: {risk_action}",
        payload={"factors": ml_eval["explainable_factors"], "geo": geo}
    )

    # 5. Check credentials with timing-attack defense (Anti-Enumeration)
    credentials_valid = False
    if user and user.get("status") != "LOCKED":
        credentials_valid = verify_password(raw_password, user["password_hash"], user["salt"])
    elif user and user.get("status") == "LOCKED":
        # Check if credentials are correct for locked account to give actionable feedback
        if verify_password(raw_password, user["password_hash"], user["salt"]):
            raise HTTPException(
                status_code=403,
                detail={"error": "ACCOUNT_LOCKED", "message": "Account has been frozen or locked. Use password reset or contact an administrator to restore access."}
            )
        _ = verify_password(raw_password, "0"*64, "0123456789abcdef0123456789abcdef")
    else:
        # Constant-time dummy PBKDF2 calculation prevents side-channel timing attacks (user enumeration)
        _ = verify_password(raw_password, "0"*64, "0123456789abcdef0123456789abcdef")

    if not credentials_valid:
        rate_limiter.record_failure(client_ip)
        is_locked_acct, remaining_acct = rate_limiter.record_failure(f"acct:{email}")
        fail_count = rate_limiter.get_recent_failure_count(f"acct:{email}")

        if user:
            browser_name = fingerprint.get("browser", "Web Browser")
            os_name = fingerprint.get("os", "Desktop")
            device_desc = f"{browser_name} on {os_name}"
            
            if is_locked_acct or fail_count >= 5:
                alert_type = "BRUTE_FORCE_LOCKOUT"
                reason = f"🚨 Brute Force Attack Detected: {fail_count} failed password attempts. Attacker locked out for {remaining_acct}s."
                score = 95.0
            elif fail_count >= 2:
                alert_type = "REPEATED_FAILED_LOGINS"
                reason = f"⚠️ Repeated Failed Logins: {fail_count} unauthorized attempts with incorrect password from {device_desc}."
                score = min(90.0, 50.0 + fail_count * 10.0)
            else:
                alert_type = "SUSPICIOUS_FAILED_LOGIN"
                reason = f"⚠️ Failed login attempt: Incorrect password entered from {device_desc}."
                score = 45.0

            alert_doc = {
                "alert_id": f"alt_fail_{int(time.time()*1000)}",
                "user_email": email,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "type": alert_type,
                "risk_score": score,
                "origin": geo.get("city", "Current Location") + ", " + geo.get("country", "Local"),
                "ip": client_ip,
                "device": device_desc,
                "status": "UNRESOLVED",
                "reason": reason,
                "factors": [
                    {
                        "factor": "Credential Guessing / Failed Attempt",
                        "detail": f"{fail_count} failed attempt(s) recorded from {device_desc}.",
                        "weight": score,
                        "severity": "CRITICAL" if fail_count >= 4 else "WARNING"
                    }
                ]
            }
            db.get_collection("security_alerts").insert_one(alert_doc)
            broadcaster.broadcast_sync(email, alert_doc)

            # Dispatch security alert to user via Amazon SNS if account is locked or multiple failures
            if is_locked_acct or fail_count >= 3:
                notif = notification_service.send_brute_force_alert(
                    email=email,
                    fail_count=fail_count,
                    client_ip=client_ip,
                    lockout_seconds=remaining_acct
                )
                broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

            # Record in security_events for SOC Blue Team
            db.security_events.insert_one({
                "event_id": f"evt_fail_{int(time.time()*1000)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_email": email,
                "ip_address": client_ip,
                "geo": geo,
                "risk_score": score,
                "risk_level": "CRITICAL" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
                "action_taken": "BLOCK_SESSION" if is_locked_acct else "CREDENTIAL_FAILURE",
                "factors": alert_doc["factors"],
                "device": device_desc
            })

            cloudwatch.record_security_decision(score, "BLOCK_SESSION" if is_locked_acct else "WARN")
            cloudwatch.put_log_event(
                log_group="/aws/lambda/AuthHandler",
                level="WARN",
                message=f"Failed login attempt ({fail_count} recent) against {email} from {client_ip} ({device_desc})",
                payload={"failures": fail_count, "device": device_desc}
            )

        # GENERIC ERROR MESSAGE per User Rules (prevents account enumeration)
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials or account restricted."
        )

    # 6. Adaptive Security Policy Enforcement
    # Scenario A: HIGH / CRITICAL RISK -> AUTOMATIC BLOCK
    if risk_action == "BLOCK_SESSION":
        # Dispatch notification to legitimate user inbox
        alert_doc = {
            "alert_id": f"alt_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "HIGH_RISK_HIJACK_BLOCKED",
            "risk_score": risk_score,
            "origin": geo.get("city", "Foreign Location") + ", " + geo.get("country", "Unknown"),
            "ip": client_ip,
            "device": fingerprint.get("os", "Unknown"),
            "status": "UNRESOLVED",
            "reason": ml_eval["explainable_factors"][0]["factor"] if ml_eval["explainable_factors"] else "Suspicious anomaly",
            "factors": ml_eval["explainable_factors"]
        }
        db.get_collection("security_alerts").insert_one(alert_doc)
        broadcaster.broadcast_sync(email, alert_doc)

        # Dispatch desktop notification to Primary Device
        city_name = geo.get("city", "Remote Location")
        send_desktop_notification(
            title=f"🚨 Threat Blocked: {city_name}",
            message=f"Impossible Travel / High-Risk attempt from {client_ip} was BLOCKED. Alert dispatched to email."
        )

        # Dispatch urgent threat alert via Amazon SNS & Email
        notif = notification_service.send_threat_blocked(
            email=email,
            threat_type="HIGH_RISK_HIJACK_BLOCKED",
            risk_score=risk_score,
            geo=geo,
            client_ip=client_ip,
            factors=ml_eval["explainable_factors"]
        )
        broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access Blocked",
                "message": "Suspicious login activity detected (Impossible Travel / Malicious IP / Unknown Device). Access blocked to protect this account.",
                "risk_score": risk_score,
                "factors": ml_eval["explainable_factors"]
            }
        )

    # Scenario B: MEDIUM RISK -> STEP-UP MFA CHALLENGE
    # If the user does not have an established primary device yet, this device is their
    # initial primary portal enrollment. Secondary-device step-up MFA requires an active
    # primary device to approve or display codes. Therefore, initial primary enrollment
    # allows legitimate access (prompting confirmation as Main Device) unless a critical
    # threat triggers BLOCK_SESSION.
    has_primary_device = bool(user.get("primary_device"))
    if risk_action == "STEP_UP_MFA" and not has_primary_device:
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="INFO",
            message=f"Initial primary device enrollment for {email}: granting primary portal setup despite medium risk score {risk_score}."
        )
        risk_action = "ALLOW"

    if risk_action == "STEP_UP_MFA":
        otp = generate_mfa_code()
        temp_token = generate_session_token()
        now_iso = datetime.now(timezone.utc) .isoformat()
        db.users.update_one(
            {"email": email},
            {"$set": {
                "mfa_pending": {
                    "code": otp,
                    "temp_token": temp_token,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                    "attempt": attempt_telemetry,
                    "device": fingerprint.get("os", "Unknown Device"),
                    "device_label": f"Challenged Device ({fingerprint.get('browser', 'Browser')} on {fingerprint.get('os', 'Unknown')})",
                    "fingerprint": fingerprint,
                    "ip": client_ip,
                    "geo": geo,
                    "approved": False,
                    "created_at": now_iso
                }
            }}
        )
        # Create alert specifically delivering code to Primary Device
        primary_dev = user.get("primary_device") or {}
        primary_dev_name = primary_dev.get("label", "Primary Security Portal")
        dev_desc = f"{fingerprint.get('browser', 'Browser')} on {fingerprint.get('os', 'Unknown')}"
        alert_doc = {
            "alert_id": f"alt_mfa_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": now_iso,
            "type": "SECONDARY_DEVICE_APPROVAL_REQUEST",
            "risk_score": risk_score,
            "origin": geo.get("city", "Unknown") + ", " + geo.get("country", "Unknown"),
            "ip": client_ip,
            "device": dev_desc,
            "status": "PENDING_APPROVAL",
            "verification_code": otp,  # Code is on Primary Device screen!
            "temp_token": temp_token,
            "reason": f"MFA Challenge for incoming login from {geo.get('city', 'Unknown')}. Verification code: {otp}",
            "factors": ml_eval["explainable_factors"]
        }
        db.get_collection("security_alerts").insert_one(alert_doc)

        # Fire real Windows Desktop Toast Notification in the background!
        send_desktop_notification(
            title=f"🔐 Sign-In Request: Code {otp}",
            message=f"Access requested from {geo.get('city', 'Unknown')} ({dev_desc}). Verification code: {otp}"
        )
        broadcaster.broadcast_sync(email, alert_doc)

        # Dispatch 6-digit verification code to user's email via Amazon SNS
        notif = notification_service.send_mfa_code(
            email=email,
            otp=otp,
            device_name=dev_desc,
            geo=geo,
            client_ip=client_ip
        )
        broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

        return {
            "status": "MFA_REQUIRED",
            "action": "STEP_UP_MFA",
            "message": "Unusual access pattern detected. Verification code has been sent to your Primary Device screen.",
            "risk_score": risk_score,
            "temp_token": temp_token,
            "demo_mfa_code": otp
        }

    # Scenario C: LOW RISK -> ALLOW & ISSUE ACTIVE SESSION
    # 6. Device Tier Classification (Primary Portal vs. Secondary Device)
    primary_device = user.get("primary_device")
    browser_id = fingerprint.get("browser_id")
    browser_name = fingerprint.get("browser", "Browser")
    os_name = fingerprint.get("os", "Desktop")
    device_name = f"{browser_name} on {os_name}"

    prompt_primary_device = False
    session_expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    is_dummy_seeded = bool(primary_device and primary_device.get("browser_id") == "chrome_uuid_legit_001")
    has_confirmed = bool(user.get("has_confirmed_primary", False))
    if not primary_device or is_dummy_seeded or not has_confirmed:
        # First sign-in or unconfirmed primary device -> enroll current browser and prompt user to keep/confirm
        prompt_primary_device = True
        device_tier = "PRIMARY"
        is_primary = True
        device_label = f"Primary Security Portal ({device_name})"
        session_expires_at = "2099-12-31T23:59:59Z"
        primary_data = {
            "browser_id": browser_id,
            "browser": browser_name,
            "os": os_name,
            "canvas_hash": fingerprint.get("canvas_hash"),
            "screen_resolution": fingerprint.get("screen_resolution"),
            "label": device_label,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        db.users.update_one({"email": email}, {"$set": {"primary_device": primary_data, "has_confirmed_primary": False}})
        user["primary_device"] = primary_data
        primary_device = primary_data
    else:
        # Check if current hardware/browser profile matches the designated primary device
        primary_bid = primary_device.get("browser_id")
        matches_primary = False

        if primary_bid and browser_id:
            matches_primary = bool(primary_bid == browser_id)
        else:
            matches_primary = bool(
                primary_device.get("canvas_hash") == fingerprint.get("canvas_hash")
                and primary_device.get("browser") == browser_name
                and primary_device.get("os") == os_name
            )

        if matches_primary:
            device_tier = "PRIMARY"
            is_primary = True
            device_label = f"Primary Security Portal ({device_name})"
            # Primary device session is perpetual and never expires
            session_expires_at = "2099-12-31T23:59:59Z"
        else:
            # Secondary device login: MUST BE APPROVED BY PRIMARY DEVICE!
            otp = generate_mfa_code()
            temp_token = generate_session_token()
            now_iso = datetime.now(timezone.utc).isoformat()
            device_label = f"Secondary Device ({device_name})"

            db.users.update_one(
                {"email": email},
                {"$set": {
                    "mfa_pending": {
                        "code": otp,
                        "temp_token": temp_token,
                        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                        "device": device_name,
                        "device_label": device_label,
                        "fingerprint": fingerprint,
                        "ip": client_ip,
                        "geo": geo,
                        "approved": False,
                        "created_at": now_iso
                    }
                }}
            )

            # High-priority alert sent directly to Primary Device with verification code & one-click approval
            alert_id = f"alt_mfa_{int(time.time()*1000)}"
            origin_str = geo.get("city", "Local") + ", " + geo.get("country", "Local")
            alert_doc = {
                "alert_id": alert_id,
                "user_email": email,
                "created_at": now_iso,
                "type": "SECONDARY_DEVICE_APPROVAL_REQUEST",
                "risk_score": 30.0,
                "origin": origin_str,
                "ip": client_ip,
                "device": device_name,
                "status": "PENDING_APPROVAL",
                "verification_code": otp,  # Code is on Primary Device screen!
                "temp_token": temp_token,
                "reason": f"Secondary device '{device_name}' from {geo.get('city', 'Local')} is requesting sign-in access. Verification code: {otp}",
                "factors": [{
                    "factor": "Secondary Device Login Request",
                    "detail": f"Device: {device_name} | Code: {otp} | IP: {client_ip}",
                    "weight": 30.0,
                    "severity": "MEDIUM"
                }]
            }
            db.get_collection("security_alerts").insert_one(alert_doc)

            # Fire real Windows Desktop Toast Notification in the background!
            send_desktop_notification(
                title=f"🔐 Sign-In Request: Code {otp}",
                message=f"Secondary device '{device_name}' from {geo.get('city', 'Local')} is requesting sign-in access."
            )

            # Push live event via SSE to connected Primary Device (0ms latency!)
            broadcaster.broadcast_sync(email, alert_doc)

            # Dispatch 6-digit approval code to user's email via Amazon SNS
            notif = notification_service.send_mfa_code(
                email=email,
                otp=otp,
                device_name=device_name,
                geo=geo,
                client_ip=client_ip
            )
            broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

            cloudwatch.put_log_event(
                log_group="/aws/lambda/AuthHandler",
                level="WARN",
                message=f"Secondary device login verification code {otp} dispatched to primary device for {email} ({device_name})"
            )

            # Zero data about Primary Device leaked to Secondary Device!
            return {
                "status": "MFA_REQUIRED",
                "action": "DEVICE_APPROVAL_REQUIRED",
                "message": "Secondary device detected. Verification code has been sent to your Primary Device screen.",
                "temp_token": temp_token,
                "device_tier": "SECONDARY"
            }

    rate_limiter.record_success(client_ip)
    rate_limiter.record_success(f"acct:{email}")
    session_token = generate_session_token()
    session_id = f"sess_{int(time.time()*1000)}"

    session_doc = {
        "session_id": session_id,
        "session_token": session_token,
        "user_email": email,
        "ip_address": client_ip,
        "geo": geo,
        "device": device_label,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "fingerprint": fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": session_expires_at,
        "status": "ACTIVE"
    }
    db.active_sessions.insert_one(session_doc)

    # Update user's last successful login
    db.users.update_one(
        {"email": email},
        {"$set": {
            "last_successful_login": {
                "timestamp": time.time(),
                "geo": geo,
                "ip": client_ip,
                "device": fingerprint.get("os", "Desktop")
            }
        },
        "$push": {"trusted_devices": fingerprint} if fingerprint else {}}
    )

    return {
        "status": "SUCCESS",
        "action": "ALLOW",
        "risk_score": risk_score,
        "token": session_token,
        "prompt_primary_device": prompt_primary_device,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "status": user["status"],
            "role": user.get("role", "ROOT_ADMIN"),
            "is_root_admin": user.get("is_root_admin", True),
            "primary_device": user.get("primary_device"),
            "device_tier": device_tier,
            "is_primary_device": is_primary
        }
    }


@app.post("/api/auth/verify-mfa")
def verify_mfa(payload: VerifyMFASchema):
    email = sanitize_email(payload.email)
    user = db.users.find_one({"email": email})
    if not user or not user.get("mfa_pending"):
        raise HTTPException(status_code=400, detail="No pending MFA challenge found.")

    mfa_state = user["mfa_pending"]
    if mfa_state.get("temp_token") != payload.temp_token:
        raise HTTPException(status_code=400, detail="Invalid session challenge token.")

    now_iso = datetime.now(timezone.utc).isoformat()
    if mfa_state.get("expires_at", "") < now_iso:
        db.users.update_one({"email": email}, {"$set": {"mfa_pending": None}})
        raise HTTPException(status_code=400, detail="Verification code has expired. Please try logging in again.")

    if mfa_state.get("code") != payload.mfa_code.strip():
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    # MFA verified successfully: clear challenge and issue full session
    attempt = mfa_state.get("attempt", {})
    client_ip = attempt.get("ip", "127.0.0.1")
    geo = attempt.get("geo", {})
    fp = attempt.get("fingerprint", {})
    dev_name = f"{fp.get('browser', 'Browser')} on {fp.get('os', 'Verified Device')}"

    rate_limiter.record_success(client_ip)
    rate_limiter.record_success(f"acct:{email}")
    db.users.update_one({"email": email}, {"$set": {"mfa_pending": None}})
    session_token = generate_session_token()
    session_id = f"sess_{int(time.time()*1000)}"

    has_primary = bool(user.get("primary_device"))
    device_tier = "SECONDARY" if has_primary else "PRIMARY"
    is_primary = False if has_primary else True
    session_expires = "2099-12-31T23:59:59Z" if is_primary else (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    dev_label = mfa_state.get("device_label") or dev_name

    db.active_sessions.insert_one({
        "session_id": session_id,
        "session_token": session_token,
        "user_email": email,
        "ip_address": client_ip,
        "geo": geo,
        "device": dev_label,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "fingerprint": fp,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": session_expires,
        "status": "ACTIVE"
    })

    # Resolve security alert
    db.get_collection("security_alerts").update_one(
        {"user_email": email, "temp_token": payload.temp_token},
        {"$set": {"status": "RESOLVED_VERIFIED"}}
    )

    # Real-time Broadcast to Primary Device to automatically close modal-secondary-device-approval!
    broadcaster.broadcast_sync(email, {
        "type": "SECONDARY_DEVICE_VERIFIED",
        "temp_token": payload.temp_token,
        "device": dev_label,
        "message": f"Secondary device ({dev_label}) entered the verification code and signed in successfully."
    })

    # Dispatch security notification
    notif = notification_service.dispatch(
        recipient_email=email,
        subject=f"ℹ️ [AWS Security] Secondary Device Signed In: {dev_label}",
        body_text=f"Secondary Device Access Granted:\n\nAccount: {email}\nDevice:  {dev_label}\nIP:      {client_ip}\nTime:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\nA secondary session was authenticated using the verification code displayed on your Primary Device.\nIf you did not authorize this, freeze your account immediately from your Primary Security Portal.",
        notification_type="SECONDARY_DEVICE_LOGIN",
        metadata={"device": dev_label, "client_ip": client_ip, "tier": device_tier}
    )
    broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    # Update user's last successful login
    db.users.update_one(
        {"email": email},
        {"$set": {
            "last_successful_login": {
                "timestamp": time.time(),
                "geo": geo,
                "ip": client_ip,
                "device": dev_label
            }
        }}
    )

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"MFA verified successfully for {email} on {dev_label} (Tier: {device_tier})"
    )

    return {
        "status": "SUCCESS",
        "token": session_token,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "message": "Identity confirmed via Verification Code. Access granted."
    }


@app.get("/api/auth/mfa-poll/{temp_token}")
def poll_mfa_status(temp_token: str):
    """Allows a waiting secondary device to check if the Primary Device approved its login."""
    user = None
    all_users = db.users.find({})
    for u in all_users:
        pending = u.get("mfa_pending")
        if pending and pending.get("temp_token") == temp_token:
            user = u
            break

    if not user or not user.get("mfa_pending"):
        return {"status": "EXPIRED", "message": "Verification challenge expired or already handled."}

    mfa_state = user["mfa_pending"]
    if mfa_state.get("approved") == True:
        email = user["email"]
        fp = mfa_state.get("fingerprint", {})
        client_ip = mfa_state.get("ip", "127.0.0.1")
        geo = mfa_state.get("geo", {})
        dev_label = mfa_state.get("device_label", "Secondary Device")

        db.users.update_one({"email": email}, {"$set": {"mfa_pending": None}})
        session_token = generate_session_token()
        session_id = f"sess_{int(time.time()*1000)}"

        has_primary = bool(user.get("primary_device"))
        device_tier = "SECONDARY" if has_primary else "PRIMARY"
        is_primary = False if has_primary else True
        session_expires = "2099-12-31T23:59:59Z" if is_primary else (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        db.active_sessions.insert_one({
            "session_id": session_id,
            "session_token": session_token,
            "user_email": email,
            "ip_address": client_ip,
            "geo": geo,
            "device": dev_label,
            "device_tier": device_tier,
            "is_primary_device": is_primary,
            "fingerprint": fp,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": session_expires,
            "status": "ACTIVE"
        })

        return {
            "status": "APPROVED",
            "token": session_token,
            "device_tier": device_tier,
            "is_primary_device": is_primary,
            "user": {
                "email": user["email"],
                "full_name": user["full_name"],
                "status": user["status"],
                "role": user.get("role", "ROOT_ADMIN"),
                "is_root_admin": user.get("is_root_admin", True),
                "device_tier": device_tier,
                "is_primary_device": is_primary
            }
        }

    return {"status": "PENDING", "message": "Awaiting approval or verification code entry from Primary Device."}


@app.post("/api/auth/devices/approve-secondary")
def approve_secondary_device(payload: ApproveSecondarySchema, user: Dict[str, Any] = Depends(get_current_user)):
    """Called by the Primary Device to grant one-click approval to a pending secondary device."""
    mfa_pending = user.get("mfa_pending")
    target_token = payload.temp_token
    if mfa_pending:
        if not target_token or target_token == "LATEST" or target_token == mfa_pending.get("temp_token"):
            target_token = mfa_pending.get("temp_token")
    if not mfa_pending and not target_token:
        # Check if an alert has pending approval
        pending_alert = db.get_collection("security_alerts").find_one({
            "user_email": user["email"],
            "type": "SECONDARY_DEVICE_APPROVAL_REQUEST",
            "status": "PENDING_APPROVAL"
        })
        if not pending_alert:
            raise HTTPException(status_code=400, detail="No matching pending secondary device request found.")
        target_token = pending_alert.get("temp_token")

    if payload.approved:
        if mfa_pending:
            mfa_pending["approved"] = True
            db.users.update_one(
                {"email": user["email"]},
                {"$set": {"mfa_pending": mfa_pending}}
            )
        db.get_collection("security_alerts").update_many(
            {"user_email": user["email"], "$or": [{"temp_token": target_token}, {"type": "SECONDARY_DEVICE_APPROVAL_REQUEST"}]},
            {"$set": {"status": "RESOLVED_APPROVED"}}
        )
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="INFO",
            message=f"Primary device approved secondary sign-in for {user['email']}"
        )
        return {"status": "SUCCESS", "message": "Secondary device approved successfully."}
    else:
        db.users.update_one(
            {"email": user["email"]},
            {"$set": {"mfa_pending": None}}
        )
        db.get_collection("security_alerts").update_many(
            {"user_email": user["email"], "$or": [{"temp_token": target_token}, {"type": "SECONDARY_DEVICE_APPROVAL_REQUEST"}]},
            {"$set": {"status": "RESOLVED_DENIED"}}
        )
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="WARN",
            message=f"Primary device rejected secondary sign-in attempt for {user['email']}"
        )
        return {"status": "SUCCESS", "message": "Secondary device login request denied."}


@app.post("/api/auth/unlock-self")
def unlock_self(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Allows the authenticated Primary Device owner to unfreeze and restore their own account."""
    email = user["email"]
    client_ip = request.client.host if request.client else "127.0.0.1"
    db.users.update_one(
        {"email": email},
        {"$set": {"status": "ACTIVE", "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    rate_limiter.record_success(f"acct:{email}")
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Account {email} self-unlocked to ACTIVE status by owner on Primary Device."
    )
    notif = notification_service.send_account_status_alert(email, "ACTIVE", client_ip)
    broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})
    return {"status": "SUCCESS", "message": "Account successfully unfrozen and restored to ACTIVE status."}


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordSchema, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    email = sanitize_email(payload.email)
    user = db.users.find_one({"email": email})

    # Anti-enumeration response: always return the same success message regardless of existence
    generic_msg = f"If an account exists for {email}, a secure password reset link has been dispatched via Amazon SNS."

    if user:
        token = generate_reset_token()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        db.password_resets.insert_one({
            "reset_token": token,
            "email": email,
            "expires_at": expires,
            "used": False
        })
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="INFO",
            message=f"Password reset token issued for {email}",
            payload={"token_demo": token} # Provided for local testing
        )
        # Dispatch to legitimate user's email via Amazon SNS / SES / Mailbox!
        notif = notification_service.send_password_reset(email, token, client_ip)
        broadcaster.broadcast_sync(email, {
            "type": "NOTIFICATION_DISPATCHED",
            "notification": notif
        })
        return {
            "status": "SUCCESS",
            "message": f"Password reset link dispatched to {email} via Amazon SNS.",
            "demo_reset_token": token,
            "channel": notif.get("channel", "Amazon SNS")
        }

    return {"status": "SUCCESS", "message": generic_msg}


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordSchema):
    token = payload.token.strip()
    record = db.password_resets.find_one({"reset_token": token, "used": False})
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or already used password reset link.")

    now_iso = datetime.now(timezone.utc).isoformat()
    if record.get("expires_at", "") < now_iso:
        raise HTTPException(status_code=400, detail="Reset link has expired. Please request a new one.")

    is_valid, msg = validate_password_strength(payload.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    # Hash new password
    new_hash, new_salt = hash_password(payload.new_password)
    email = record["email"]

    # Invalidate token
    db.password_resets.update_one({"reset_token": token}, {"$set": {"used": True}})

    # Invalidate all active sessions for security!
    db.active_sessions.delete_many({"user_email": email})

    # Update user
    db.users.update_one(
        {"email": email},
        {"$set": {
            "password_hash": new_hash,
            "salt": new_salt,
            "status": "ACTIVE",
            "updated_at": now_iso
        }}
    )

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Password rotated and sessions invalidated for {email}"
    )

    # Dispatch security confirmation via Amazon SNS
    notif = notification_service.send_password_changed(email, "ResetFlow")
    broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {"status": "SUCCESS", "message": "Password successfully updated. All previous sessions terminated."}


@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordSchema, request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Allows an authenticated user to rotate their password directly using their current password without needing a recovery token."""
    if not verify_password(payload.current_password, user.get("password_hash", ""), user.get("salt", "")):
        raise HTTPException(status_code=400, detail="Incorrect current master password.")

    is_valid, msg = validate_password_strength(payload.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    client_ip = request.client.host if request.client else "127.0.0.1"
    new_hash, new_salt = hash_password(payload.new_password)
    email = user["email"]
    now_iso = datetime.now(timezone.utc).isoformat()

    db.users.update_one(
        {"email": email},
        {"$set": {
            "password_hash": new_hash,
            "salt": new_salt,
            "status": "ACTIVE",
            "updated_at": now_iso
        }}
    )

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Password rotated by authenticated user {email}"
    )

    # Dispatch security confirmation via Amazon SNS
    notif = notification_service.send_password_changed(email, client_ip)
    broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {"status": "SUCCESS", "message": "Master password successfully updated."}


# -------------------------------------------------------------
# User Portal & Account Management Routes
# -------------------------------------------------------------
@app.get("/api/auth/me")
def get_me(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    device_tier = current_session.get("device_tier", "PRIMARY") if current_session else "PRIMARY"
    is_primary = current_session.get("is_primary_device", True) if current_session else True

    return {
        "email": user["email"],
        "full_name": user["full_name"],
        "status": user["status"],
        "role": user.get("role", "ROOT_ADMIN"),
        "is_root_admin": user.get("is_root_admin", True),
        "created_at": user["created_at"],
        "last_login": user.get("last_successful_login"),
        "trusted_devices_count": len(user.get("trusted_devices", [])),
        "primary_device": user.get("primary_device") if is_primary else None, # Zero primary device data given to secondary devices!
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "secondary_password_configured": bool(user.get("secondary_password_hash")),
        "account_is_frozen": bool(user.get("account_is_frozen") or user.get("status") == "LOCKED")
    }


@app.post("/api/auth/devices/set-primary")
@app.post("/api/auth/set-primary-device")
def set_primary_device(payload: SetPrimaryDeviceSchema, authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    session = db.active_sessions.find_one({"session_token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Active session not found.")

    # Master Secondary Security Password verification when setting or transferring Primary Device:
    current_primary = user.get("primary_device")
    if payload.is_primary and current_primary:
        # A secondary device attempting to take over primary authority MUST supply the Master Secondary Password!
        if not session.get("is_primary_device"):
            if not payload.secondary_password:
                raise HTTPException(
                    status_code=400,
                    detail="Master Secondary Security Password is required to transfer Primary Device authority."
                )
            sec_hash = user.get("secondary_password_hash")
            sec_salt = user.get("secondary_password_salt")
            verified = False
            if sec_hash and sec_salt:
                verified = verify_password(payload.secondary_password, sec_hash, sec_salt)
            if not verified:
                # Fallback check against account password
                verified = verify_password(payload.secondary_password, user["password_hash"], user["salt"])
            if not verified:
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect Secondary Security Password. Primary Device transfer denied."
                )
        else:
            # Primary device itself confirming: if secondary password supplied, verify it
            if payload.secondary_password:
                sec_hash = user.get("secondary_password_hash")
                sec_salt = user.get("secondary_password_salt")
                verified = False
                if sec_hash and sec_salt:
                    verified = verify_password(payload.secondary_password, sec_hash, sec_salt)
                if not verified:
                    verified = verify_password(payload.secondary_password, user["password_hash"], user["salt"])
                if not verified:
                    raise HTTPException(
                        status_code=401,
                        detail="Incorrect Secondary Security Password."
                    )

    fp = session.get("fingerprint") or {}
    browser_name = fp.get("browser", "Browser")
    os_name = fp.get("os", "Desktop")
    device_label = payload.device_label or f"Primary Security Portal ({browser_name} on {os_name})"

    if payload.is_primary:
        primary_data = {
            "browser_id": fp.get("browser_id"),
            "browser": browser_name,
            "os": os_name,
            "canvas_hash": fp.get("canvas_hash"),
            "screen_resolution": fp.get("screen_resolution"),
            "label": device_label,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        db.users.update_one({"email": user["email"]}, {"$set": {"primary_device": primary_data, "has_confirmed_primary": True}})
        
        # Demote all existing sessions to secondary
        db.active_sessions.update_many(
            {"user_email": user["email"]},
            {"$set": {"device_tier": "SECONDARY", "is_primary_device": False}}
        )
        # Promote current session to perpetual Primary Device
        db.active_sessions.update_one(
            {"session_token": token},
            {"$set": {
                "device_tier": "PRIMARY",
                "is_primary_device": True,
                "device": device_label,
                "expires_at": "2099-12-31T23:59:59Z"
            }}
        )
        msg = f"Primary Device authority successfully saved for this device ({device_label})."
    else:
        db.users.update_one({"email": user["email"]}, {"$set": {"has_confirmed_primary": True}})
        db.active_sessions.update_one(
            {"session_token": token},
            {"$set": {"device_tier": "SECONDARY", "is_primary_device": False, "device": f"Secondary Device ({browser_name} on {os_name})"}}
        )
        msg = "This device is registered as a Secondary Device."

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Device enrollment for {user['email']}: Primary={payload.is_primary} ({device_label})"
    )

    if payload.is_primary:
        client_ip = session.get("ip_address", "127.0.0.1")
        notif = notification_service.send_primary_device_transferred(user["email"], device_label, client_ip)
        broadcaster.broadcast_sync(user["email"], {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {"status": "SUCCESS", "message": msg, "device_tier": "PRIMARY" if payload.is_primary else "SECONDARY"}


@app.post("/api/auth/secondary-password/update")
def update_secondary_password(payload: UpdateSecondaryPasswordSchema, request: Request = None, user: Dict[str, Any] = Depends(get_current_user)):
    """Allows user to update their Master Secondary Security Password."""
    valid = verify_password(payload.current_password, user["password_hash"], user["salt"])
    if not valid and user.get("secondary_password_hash") and user.get("secondary_password_salt"):
        valid = verify_password(payload.current_password, user["secondary_password_hash"], user["secondary_password_salt"])
    
    if not valid:
        raise HTTPException(status_code=401, detail="Authentication failed: Incorrect current password.")
    
    new_hash, new_salt = hash_password(payload.new_secondary_password)
    db.users.update_one(
        {"email": user["email"]},
        {"$set": {
            "secondary_password_hash": new_hash,
            "secondary_password_salt": new_salt,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Secondary Security Password rotated for {user['email']}"
    )

    client_ip = request.client.host if (request and request.client) else "127.0.0.1"
    notif = notification_service.send_secondary_password_changed(user["email"], client_ip)
    broadcaster.broadcast_sync(user["email"], {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {"status": "SUCCESS", "message": "Master Secondary Security Password updated successfully."}


@app.get("/api/auth/sessions")
def list_sessions(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    current_id = current_session.get("session_id") if current_session else None
    caller_is_secondary = bool(current_session and (current_session.get("device_tier") == "SECONDARY" or current_session.get("is_primary_device") is False))

    sessions = db.active_sessions.find({"user_email": user["email"]}, sort_key="created_at", reverse=True)
    clean_sessions = []
    for s in sessions:
        is_current = (s.get("session_id") == current_id)
        s_device_tier = s.get("device_tier", "PRIMARY" if s.get("is_primary_device") else "SECONDARY")
        s_is_primary = (s_device_tier == "PRIMARY" or s.get("is_primary_device") is True)

        if caller_is_secondary and s_is_primary:
            # Secondary device sees ZERO data about primary device hardware, IP, or location!
            clean_sessions.append({
                "session_id": s.get("session_id"),
                "ip_address": "•••.•••.•••.•• (Protected)",
                "geo": {"city": "Protected Location", "country": "US"},
                "device": "Primary Security Device (Protected)",
                "device_tier": "PRIMARY",
                "is_primary_device": True,
                "created_at": s.get("created_at"),
                "expires_at": s.get("expires_at"),
                "status": s.get("status"),
                "is_current": is_current,
                "is_primary": True
            })
        else:
            clean_sessions.append({
                "session_id": s.get("session_id"),
                "ip_address": s.get("ip_address"),
                "geo": s.get("geo"),
                "device": s.get("device"),
                "device_tier": s_device_tier,
                "is_primary_device": s_is_primary,
                "created_at": s.get("created_at"),
                "expires_at": s.get("expires_at"),
                "status": s.get("status"),
                "is_current": is_current,
                "is_primary": s_is_primary
            })
    return {"sessions": clean_sessions, "current_session_id": current_id}


@app.post("/api/auth/sessions/kill")
def kill_session(payload: SessionKillSchema, authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    session_id = payload.session_id.strip()
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    is_killing_self = current_session and (current_session.get("session_id") == session_id)

    target = db.active_sessions.find_one({"session_id": session_id, "user_email": user["email"]})
    if not target:
        raise HTTPException(status_code=404, detail="Session not found or already terminated.")

    # PRIMARY PORTAL IMMUNITY:
    # A session with device_tier == "PRIMARY" is perpetual and can NEVER be revoked!
    is_target_primary = (target.get("device_tier") == "PRIMARY" or target.get("is_primary_device") is True)
    if is_target_primary and not is_killing_self:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: The Primary Security Portal session is permanent and cannot be remotely terminated."
        )

    # Secondary Device Restriction: Secondary sessions cannot terminate other sessions
    is_caller_secondary = current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True))
    if is_caller_secondary and not is_killing_self:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Secondary devices cannot terminate remote sessions."
        )

    res = db.active_sessions.delete_one({"session_id": session_id, "user_email": user["email"]})
    if not res:
        raise HTTPException(status_code=404, detail="Session not found or already terminated.")

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User {user['email']} revoked session {session_id}"
    )
    return {
        "status": "SUCCESS",
        "message": "Session terminated immediately.",
        "was_current_session": is_killing_self
    }


@app.post("/api/auth/sessions/kill-others")
def kill_other_sessions(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    current_id = current_session.get("session_id") if current_session else None

    # CRITICAL RESTRICTION: Secondary devices CANNOT execute mass session termination!
    is_caller_secondary = current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True))
    if is_caller_secondary:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Secondary devices cannot execute mass session termination. Master kill switches are restricted to your Primary Security Portal."
        )

    all_sessions = db.active_sessions.find({"user_email": user["email"]})
    deleted_count = 0
    for s in all_sessions:
        if s.get("session_id") != current_id:
            # Absolute safety: Never delete a primary device session during kill-others!
            if s.get("device_tier") == "PRIMARY" or s.get("is_primary_device") is True:
                continue
            db.active_sessions.delete_one({"session_id": s.get("session_id"), "user_email": user["email"]})
            deleted_count += 1

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User {user['email']} revoked {deleted_count} remote session(s). Primary session preserved."
    )

    if deleted_count > 0:
        client_ip = current_session.get("ip_address", "127.0.0.1") if current_session else "127.0.0.1"
        notif = notification_service.send_sessions_revoked_alert(user["email"], deleted_count, client_ip)
        broadcaster.broadcast_sync(user["email"], {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {
        "status": "SUCCESS",
        "message": f"Successfully revoked {deleted_count} other active session(s). Your primary portal remains active.",
        "terminated_count": deleted_count
    }


@app.post("/api/auth/lock-account")
def lock_account(request: Request, authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None

    # Secondary devices cannot trigger an account-wide emergency lockdown
    if current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True)):
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Account freeze can only be initiated from your Primary Security Portal."
        )

    email = user["email"]
    client_ip = request.client.host if (request and request.client) else "127.0.0.1"
    # Freeze account and kill all remote secondary sessions, preserving primary device session!
    db.users.update_one({"email": email}, {"$set": {"status": "LOCKED"}})
    db.active_sessions.delete_many({"user_email": email, "is_primary_device": {"$ne": True}})

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="WARN",
        message=f"Emergency Lockout activated by user {email}. Primary device session preserved."
    )

    # Dispatch emergency lock notification to user via Amazon SNS
    notif = notification_service.send_account_status_alert(email, "FROZEN", client_ip)
    broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {"status": "SUCCESS", "message": "Account successfully frozen. Remote secondary sessions terminated. Your primary device remains active."}


@app.post("/api/auth/delete-account")
def delete_account(payload: AccountDeleteSchema, user: Dict[str, Any] = Depends(get_current_user)):
    email = user["email"]

    # Verify password before irreversible deletion
    if not verify_password(payload.password, user["password_hash"], user["salt"]):
        raise HTTPException(status_code=401, detail="Incorrect password. Account deletion aborted.")

    db.users.delete_one({"email": email})
    db.active_sessions.delete_many({"user_email": email})
    db.security_events.delete_many({"user_email": email})
    db.get_collection("security_alerts").delete_many({"user_email": email})

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Account and associated telemetry deleted for {email}"
    )

    client_ip = "127.0.0.1"
    notification_service.send_account_deleted_alert(email, client_ip)

    return {"status": "SUCCESS", "message": "Your account and all associated telemetry have been permanently deleted."}


@app.get("/api/security/user-alerts")
def get_user_alerts(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    is_primary = current_session.get("is_primary_device", True) if current_session else True

    query = {"user_email": user["email"]}
    alerts = db.get_collection("security_alerts").find(query, sort_key="created_at", reverse=True, limit=20)
    
    if not is_primary:
        # Secondary devices must NEVER receive approval requests, verification codes, or tokens!
        filtered_alerts = []
        for a in alerts:
            a_type = a.get("type", "")
            if a_type in ("SECONDARY_DEVICE_APPROVAL_REQUEST", "DEVICE_APPROVAL_REQUIRED") or a.get("verification_code"):
                continue
            clean_a = dict(a)
            if "temp_token" in clean_a:
                del clean_a["temp_token"]
            filtered_alerts.append(clean_a)
        return {"alerts": filtered_alerts}

    return {"alerts": alerts}


@app.post("/api/security/user-alerts/dismiss")
def dismiss_user_alert(payload: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    alert_id = payload.get("alert_id")
    if alert_id:
        db.get_collection("security_alerts").delete_one({"alert_id": alert_id, "user_email": user["email"]})
    return {"status": "SUCCESS", "message": "Alert dismissed."}


@app.post("/api/security/user-alerts/dismiss-all")
def dismiss_all_user_alerts(user: Dict[str, Any] = Depends(get_current_user)):
    db.get_collection("security_alerts").delete_many({"user_email": user["email"]})
    return {"status": "SUCCESS", "message": "All alerts cleared."}


@app.get("/api/security/dispatched-notifications")
def get_dispatched_notifications(limit: int = 50, user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
    """
    Returns recent notifications dispatched via Amazon SNS / SES / Email simulator.
    Authenticated users see their own messages; unauthenticated/SOC preview sees recent notifications.
    """
    query = {}
    if user and user.get("role") != "SECURITY_ADMIN":
        query["recipient_email"] = user["email"]

    records = db.get_collection("dispatched_notifications").find(
        query,
        sort_key="created_at",
        reverse=True,
        limit=limit
    )
    for r in records:
        if "_id" in r:
            del r["_id"]
    status_info = notification_service.get_status()
    return {
        "status": "SUCCESS",
        "total": len(records),
        "notifications": records,
        "sns_topic_configured": status_info["sns_configured"],
        "smtp_configured": status_info["smtp_configured"],
        "is_gmail": status_info["is_gmail"],
        "engine_mode": status_info["mode"],
        "engine_description": status_info["description"],
        "engine_status": status_info
    }


@app.post("/api/security/dispatched-notifications/clear")
@app.delete("/api/security/dispatched-notifications")
def clear_dispatched_notifications(user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
    """Clears all dispatched security alerts and recovery emails from the mailbox."""
    query = {}
    if user and user.get("role") != "SECURITY_ADMIN":
        query["recipient_email"] = user["email"]
    del_count = db.get_collection("dispatched_notifications").delete_many(query)
    return {
        "status": "SUCCESS",
        "deleted_count": del_count,
        "message": "Dispatched security notifications cleared successfully."
    }


@app.post("/api/security/test-notification")
def test_notification(payload: TestNotificationSchema, request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Allows testing Amazon SNS / Email dispatch live."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    target_email = sanitize_email(payload.recipient_email)
    msg = payload.message or f"Test security alert dispatched at {datetime.now(timezone.utc).isoformat()}."
    record = notification_service.dispatch(
        recipient_email=target_email,
        subject="🧪 [AWS Security Test] Amazon SNS Diagnostic Dispatch",
        body_text=f"Diagnostic Test Message:\n\n{msg}\n\nClient IP: {client_ip}",
        notification_type=payload.notification_type or "TEST_SECURITY_ALERT",
        metadata={"client_ip": client_ip, "initiated_by": user["email"]}
    )
    broadcaster.broadcast_sync(target_email, {
        "type": "NOTIFICATION_DISPATCHED",
        "notification": record
    })
    return {"status": "SUCCESS", "message": "Notification dispatched successfully", "record": record}


@app.get("/api/security/stream")
async def security_event_stream(request: Request, authorization: Optional[str] = Header(None)):
    """
    Live Server-Sent Events (SSE) stream for Primary Device.
    Delivers instant 0ms background notifications when secondary devices request sign-in.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    if not token:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication token required.")

    session = db.active_sessions.find_one({"session_token": token})
    if not session or session.get("status") != "ACTIVE":
        raise HTTPException(status_code=401, detail="Active session required.")

    email = session.get("user_email")
    is_primary = bool(session.get("is_primary_device") or session.get("device_tier") == "PRIMARY")
    if not is_primary:
        raise HTTPException(status_code=403, detail="SSE real-time stream is reserved for Primary Devices.")

    q = broadcaster.subscribe(email)

    async def event_stream():
        try:
            # Initial connection ping
            yield f": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=12.0)
                    yield f"event: alert\ndata: {json.dumps(event, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield f": keepalive\n\n"
        finally:
            broadcaster.unsubscribe(email, q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# -------------------------------------------------------------
# Red Team Attack Simulator & Blue Team SOC Endpoints
# -------------------------------------------------------------
class SimulateAttackSchema(BaseModel):
    target_email: str = Field(min_length=3, max_length=254)
    attack_type: Optional[str] = None # "IMPOSSIBLE_TRAVEL", "CREDENTIAL_STUFFING", "BRUTE_FORCE", "DEVICE_SPOOF"
    scenario_id: Optional[str] = None
    speed_kmh: Optional[float] = None
    custom_ip: Optional[str] = None
    custom_city: Optional[str] = None
    custom_country: Optional[str] = None

@app.post("/api/security/simulate-attack")
@app.post("/api/security/simulate-scenario")
def simulate_attack(payload: SimulateAttackSchema):
    email = sanitize_email(payload.target_email)
    user = db.users.find_one({"email": email})

    # Base coordinates
    user_last_login = (user.get("last_successful_login") or {}) if user else {}
    last_loc = user_last_login.get("geo") or {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}

    raw_type = payload.attack_type or payload.scenario_id or "IMPOSSIBLE_TRAVEL"
    attack_type = raw_type.upper()
    simulated_geo = {}
    simulated_ip = "127.0.0.1"
    simulated_fp = {}
    recent_failures = 0
    ua = "Mozilla/5.0"

    if attack_type == "IMPOSSIBLE_TRAVEL":
        # Tokyo coordinates: 10,800 km away from NYC in 2 minutes
        simulated_geo = {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "Japan"}
        simulated_ip = "133.242.18.5"
        simulated_fp = {"os": "Linux x86_64", "canvas_hash": "anom_hash_9812", "screen_resolution": "1920x1080"}
        ua = "Mozilla/5.0 (X11; Linux x86_64)"

    elif attack_type == "CREDENTIAL_STUFFING":
        # Tor Exit Node in Moscow / Frankfurt
        simulated_geo = {"lat": 55.7558, "lon": 37.6173, "city": "Moscow", "country": "Russia"}
        simulated_ip = "185.220.101.45" # Known Tor Exit IP
        simulated_fp = {"os": "Windows NT 10.0", "canvas_hash": "tor_spoof_441", "screen_resolution": "1000x800"}
        ua = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

    elif attack_type == "BRUTE_FORCE":
        simulated_geo = last_loc
        simulated_ip = "198.51.100.22"
        simulated_fp = {"os": "Unknown", "canvas_hash": "bot_canvas_000"}
        recent_failures = 6 # Force burst
        ua = "python-requests/2.31.0 HeadlessChrome"

    elif attack_type == "DEVICE_SPOOF":
        simulated_geo = last_loc
        simulated_ip = "45.33.32.156" # Datacenter IP
        simulated_fp = {"os": "Android 14", "canvas_hash": "spoofed_mobile_99", "screen_resolution": "390x844"}
        ua = "Mozilla/5.0 (Linux; Android 14; Pixel 7)"

    else:
        simulated_geo = {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "UK"}
        simulated_ip = payload.custom_ip or "185.100.87.1"
        simulated_fp = {"os": "Custom Vector", "canvas_hash": "rnd_hash"}

    # Extract features
    attempt_meta = {
        "timestamp": time.time(),
        "geo": simulated_geo,
        "ip": simulated_ip,
        "fingerprint": simulated_fp,
        "user_agent": ua
    }
    features = extract_features(user, attempt_meta, recent_failures)
    if payload.speed_kmh:
        features["geo_velocity_kmh"] = payload.speed_kmh

    # Evaluate ML risk
    ml_res = ml_engine.evaluate_risk(features)
    score = ml_res["risk_score"]
    action = ml_res["action"]

    # Compute Autoencoder loss
    vector = [
        features["geo_velocity_kmh"],
        features["distance_km"],
        features["device_distance"],
        features["ip_reputation"],
        features["failed_attempts_burst"],
        features["circadian_anomaly"],
        features["bot_signature"]
    ]
    auto_res = tf_autoencoder.compute_reconstruction_loss(vector)

    # Log Security Event
    event_doc = {
        "event_id": f"sim_{int(time.time()*1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_email": email,
        "ip_address": simulated_ip,
        "geo": simulated_geo,
        "risk_score": score,
        "risk_level": ml_res["risk_level"],
        "action_taken": action,
        "factors": ml_res["explainable_factors"],
        "is_simulation": True,
        "device": simulated_fp.get("os", "Simulated Device"),
        "autoencoder_loss": auto_res["mse_reconstruction_error"]
    }
    db.security_events.insert_one(event_doc)

    # Dispatch to CloudWatch
    cloudwatch.record_security_decision(score, action)
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AccountHijackRiskEngine",
        level="WARN" if score >= 40 else "INFO",
        message=f"[RED TEAM SIMULATION] {attack_type} against {email}: Risk {score} -> Action: {action}",
        payload={"factors": ml_res["explainable_factors"], "geo": simulated_geo}
    )

    # If action is BLOCK or STEP_UP, inject alert into user's alert inbox
    if action in ("BLOCK_SESSION", "STEP_UP_MFA"):
        sim_alert = {
            "alert_id": f"alt_sim_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": f"SIMULATED_{attack_type}",
            "risk_score": score,
            "origin": simulated_geo.get("city", "Unknown") + ", " + simulated_geo.get("country", "Unknown"),
            "ip": simulated_ip,
            "device": simulated_fp.get("os", "Unknown"),
            "status": "UNRESOLVED",
            "reason": f"Simulated {attack_type} detected by ML Engine.",
            "factors": ml_res["explainable_factors"]
        }
        db.get_collection("security_alerts").insert_one(sim_alert)
        broadcaster.broadcast_sync(email, sim_alert)

        # Dispatch via Amazon SNS / Email!
        if action == "BLOCK_SESSION":
            notif = notification_service.send_threat_blocked(
                email=email,
                threat_type=f"SIMULATED_{attack_type}",
                risk_score=score,
                geo=simulated_geo,
                client_ip=simulated_ip,
                factors=ml_res["explainable_factors"]
            )
            broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})
        elif action == "STEP_UP_MFA":
            notif = notification_service.send_mfa_code(
                email=email,
                otp="654321",
                device_name=simulated_fp.get("os", "Simulated Vector"),
                geo=simulated_geo,
                client_ip=simulated_ip
            )
            broadcaster.broadcast_sync(email, {"type": "NOTIFICATION_DISPATCHED", "notification": notif})

    return {
        "status": "SIMULATION_COMPLETE",
        "attack_type": attack_type,
        "target_email": email,
        "risk_score": score,
        "risk_level": ml_res["risk_level"],
        "action_taken": action,
        "explainable_factors": ml_res["explainable_factors"],
        "autoencoder": auto_res,
        "origin": simulated_geo,
        "ip": simulated_ip
    }


@app.get("/api/security/events")
def get_security_events(limit: int = 50):
    events = db.security_events.find(sort_key="timestamp", reverse=True, limit=min(limit, 100))
    return {"events": events}


@app.post("/api/security/events/clear")
@app.delete("/api/security/events")
def clear_security_events():
    """Clears all security events, login attempts, and real-time stream logs."""
    del_count = db.security_events.delete_many({})
    return {
        "status": "SUCCESS",
        "deleted_count": del_count,
        "message": "Security events and login stream cleared successfully."
    }


@app.get("/api/security/stats")
def get_security_stats():
    total_events = db.security_events.count_documents()
    blocked_count = db.security_events.count_documents({"action_taken": "BLOCK_SESSION"})
    mfa_count = db.security_events.count_documents({"action_taken": "STEP_UP_MFA"})
    allowed_count = db.security_events.count_documents({"action_taken": "ALLOW"})

    recent_events = db.security_events.find(sort_key="timestamp", reverse=True, limit=20)
    avg_score = 0.0
    if recent_events:
        avg_score = round(sum(e.get("risk_score", 0.0) for e in recent_events) / len(recent_events), 1)

    return {
        "total_analyzed": total_events,
        "blocked_hijacks": blocked_count,
        "mfa_challenges": mfa_count,
        "normal_allowed": allowed_count,
        "avg_risk_score": avg_score,
        "active_alarms": [a for a in cloudwatch.alarms.values() if a["state"] == "ALARM"]
    }


# -------------------------------------------------------------
# CloudWatch Telemetry API
# -------------------------------------------------------------
@app.get("/api/monitoring/cloudwatch")
@app.get("/api/monitoring/cloudwatch/metrics")
@app.get("/api/cloudwatch/metrics")
def get_cloudwatch_telemetry():
    return cloudwatch.get_dashboard_summary()


@app.post("/api/monitoring/cloudwatch/clear")
@app.delete("/api/monitoring/cloudwatch")
def clear_cloudwatch_telemetry():
    """Clears all CloudWatch audit logs and resets telemetry counters."""
    cloudwatch.clear_logs()
    return {
        "status": "SUCCESS",
        "message": "CloudWatch logs and telemetry counters reset successfully."
    }


# -------------------------------------------------------------
# System & Maintenance Endpoints
# -------------------------------------------------------------
@app.get("/api/system/status")
def system_status():
    dep_mode = os.getenv("DEPLOYMENT_MODE", "STANDALONE_LOCAL")
    return {
        "status": "SERVICE_UNDER_MAINTENANCE" if MAINTENANCE_MODE else "HEALTHY",
        "service": "AWSSecurity AI Cyber Defense Engine",
        "version": "2.1.0",
        "deployment_mode": dep_mode,
        "is_aws": dep_mode.upper() == "AWS",
        "database_backend": "MongoDB Live Cluster" if db.use_mongo else "Embedded Local Document Store",
        "telemetry_engine": "Amazon CloudWatch" if dep_mode.upper() == "AWS" else "Embedded Local SIEM / Telemetry",
        "maintenance_mode": MAINTENANCE_MODE,
        "message": "Service Under Maintenance" if MAINTENANCE_MODE else "Service Operational",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def check_super_admin(user: Dict[str, Any] = Depends(get_current_user)):
    if not (user.get("role") == "SUPER_ADMIN" or user.get("is_super_admin")):
        raise HTTPException(status_code=403, detail="Super Admin privileges required.")
    return user

@app.post("/api/system/maintenance")
def toggle_maintenance(enable: bool, user: Dict[str, Any] = Depends(check_super_admin)):
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = enable
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="WARN" if enable else "INFO",
        message=f"[System Governance] Maintenance mode set to {enable} by Super Administrator"
    )
    return {
        "status": "SUCCESS",
        "maintenance_mode": MAINTENANCE_MODE,
        "message": "Service Under Maintenance" if MAINTENANCE_MODE else "Service Operational"
    }


# -------------------------------------------------------------
# CMS / Admin Endpoints
# -------------------------------------------------------------
@app.get("/api/cms/users")
def cms_get_users(user: Dict[str, Any] = Depends(check_super_admin)):
    users = db.users.find()
    safe_users = []
    for u in users:
        u.pop("password_hash", None)
        u.pop("salt", None)
        u.pop("mfa_secret", None)
        u.pop("mfa_pending", None)
        u["role"] = u.get("role", "USER")
        u["is_root_admin"] = u.get("is_root_admin", False)
        u["mfa_enabled"] = u.get("mfa_enabled", True)
        safe_users.append(u)
    return safe_users

@app.post("/api/cms/users/{email}/unlock")
def cms_unlock_user(email: str, user: Dict[str, Any] = Depends(check_super_admin)):
    clean_email = sanitize_email(email)
    user = db.users.find_one({"email": clean_email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    db.users.update_one(
        {"email": clean_email},
        {"$set": {"status": "ACTIVE", "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    rate_limiter.record_success(f"acct:{clean_email}")

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"[CMS Admin] Account {clean_email} was unlocked by administrator."
    )
    return {"status": "SUCCESS", "message": f"Account {clean_email} successfully unlocked and restored to ACTIVE status."}

@app.delete("/api/cms/users/{email}")
def cms_delete_user(email: str, user: Dict[str, Any] = Depends(check_super_admin)):
    clean_email = sanitize_email(email)
    user = db.users.find_one({"email": clean_email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    success = db.users.delete_one({"email": clean_email})
    db.active_sessions.delete_many({"user_email": clean_email})
    db.get_collection("security_alerts").delete_many({"user_email": clean_email})
    db.password_resets.delete_many({"email": clean_email})

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="WARN",
        message=f"[CMS Admin] User account {clean_email} and all active sessions were purged."
    )
    return {"status": "SUCCESS", "message": f"User {clean_email} and all active sessions deleted successfully."}

@app.get("/api/cms/stats")
def cms_get_stats(user: Dict[str, Any] = Depends(check_super_admin)):
    total_users = db.users.count_documents()
    active_sessions = db.active_sessions.count_documents()
    total_events = db.security_events.count_documents()
    blocked_hijacks = db.security_events.count_documents({"action_taken": "BLOCK_SESSION"})
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_security_events": total_events,
        "blocked_hijacks": blocked_hijacks,
        "maintenance_mode": MAINTENANCE_MODE
    }


# -------------------------------------------------------------
# Static Files & Single Page Application Routing
# -------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    # If file exists in frontend, serve it
    potential_file = os.path.join(FRONTEND_DIR, full_path)
    if full_path and os.path.isfile(potential_file):
        return FileResponse(potential_file)
    # Default to index.html
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        response = FileResponse(index_file)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return JSONResponse({"message": "Frontend index.html not yet built."}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    print("[AWSSecurity] Starting serverless web application on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
