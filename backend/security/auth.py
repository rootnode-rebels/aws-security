"""
Authentication and Password Security Service.
Implements PBKDF2-HMAC-SHA256 hashing, generic error handling, and token management.
"""
import os
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone, timedelta
import base64
import struct
from urllib.parse import quote
from typing import Dict, Any, Optional, Tuple, List

PBKDF2_ITERATIONS = 200_000

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and cryptographic per-user salt."""
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        PBKDF2_ITERATIONS
    )
    return dk.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a password against the stored PBKDF2 hash using constant-time comparison."""
    if not password or not stored_hash or not salt:
        return False
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)

def generate_session_token() -> str:
    """Generates a high-entropy URL-safe session token."""
    return secrets.token_urlsafe(32)

def generate_mfa_code() -> str:
    """Generates a 6-digit cryptographic OTP code."""
    return f"{secrets.randbelow(900000) + 100000}"

def generate_reset_token() -> str:
    """Generates a 32-byte cryptographic token for password recovery."""
    return secrets.token_urlsafe(32)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Strictly validates password complexity without leaking specifics to attackers."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password exceeds maximum allowable length."
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if sum([has_upper, has_lower, has_digit, has_special]) < 3:
        return False, "Password must include a mix of uppercase, lowercase, numbers, or special characters."
    return True, "Valid"


# ============================================================================
# RFC 6238 TIME-BASED ONE-TIME PASSWORD (TOTP) ENGINE
# Compatible with Google Authenticator, Microsoft Authenticator, Authy, Apple Keychain
# ============================================================================

def generate_totp_secret() -> str:
    """Generates a cryptographically secure 160-bit (20 bytes) Base32 secret."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode('utf-8').rstrip('=')


def generate_totp_uri(secret: str, email: str, issuer: str = "AWSSecurity") -> str:
    """Builds an RFC 6238 otpauth:// URI for mobile authenticator enrollment."""
    clean_email = email.strip()
    encoded_issuer = quote(issuer)
    encoded_account = quote(f"{issuer}:{clean_email}")
    return f"otpauth://totp/{encoded_account}?secret={secret}&issuer={encoded_issuer}&algorithm=SHA1&digits=6&period=30"


def compute_totp(secret: str, time_step: Optional[int] = None, timestamp: Optional[float] = None) -> str:
    """Computes a 6-digit TOTP code according to RFC 6238 / RFC 4226."""
    if time_step is None:
        ts = timestamp if timestamp is not None else time.time()
        time_step = int(ts // 30)

    clean_secret = secret.strip().replace(" ", "").upper()
    pad_len = (8 - len(clean_secret) % 8) % 8
    padded = clean_secret + ('=' * pad_len)
    key = base64.b32decode(padded, casefold=True)

    msg = struct.pack(">Q", time_step)
    h = hmac.new(key, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F
    binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    otp = binary % 1_000_000
    return f"{otp:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1, tolerance: Optional[int] = None) -> bool:
    """
    Validates a 6-digit TOTP code using constant-time comparison and
    a +/- window (default 1 step = 30s) to tolerate mobile clock drift.
    """
    if tolerance is not None:
        window = tolerance
    if not secret or not code:
        return False
    clean_code = str(code).strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    current_step = int(time.time() // 30)
    for offset in range(-window, window + 1):
        expected = compute_totp(secret, current_step + offset)
        if hmac.compare_digest(clean_code, expected):
            return True
    return False


def generate_backup_codes(count: int = 8) -> List[Dict[str, Any]]:
    """Generates single-use emergency recovery codes. Returns a list of dicts with code, hash, used."""
    codes = []
    for _ in range(count):
        code = f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        codes.append({
            "code": code,
            "hash": hashlib.sha256(code.encode('utf-8')).hexdigest(),
            "used": False
        })
    return codes


def verify_and_consume_backup_code(arg1: Any, arg2: Any) -> Tuple[bool, List[Any]]:
    """
    Validates an emergency backup code and single-use consumes it.
    Supports both argument orderings and both dict lists and string lists.
    """
    if isinstance(arg1, str):
        candidate_code = arg1
        backup_codes = list(arg2) if arg2 else []
    else:
        backup_codes = list(arg1) if arg1 else []
        candidate_code = str(arg2)

    clean = candidate_code.strip().upper().replace(" ", "")
    candidate_hash = hashlib.sha256(clean.encode('utf-8')).hexdigest()

    for i, item in enumerate(backup_codes):
        if isinstance(item, dict):
            if item.get("used", False):
                continue
            item_hash = item.get("hash")
            if not item_hash and item.get("code"):
                item_hash = hashlib.sha256(item["code"].strip().upper().encode('utf-8')).hexdigest()
            if item_hash and hmac.compare_digest(candidate_hash, item_hash):
                updated = [dict(c) for c in backup_codes]
                updated[i]["used"] = True
                updated[i]["used_at"] = time.time()
                return True, updated
        elif isinstance(item, str):
            if hmac.compare_digest(candidate_hash, item):
                remaining = [c for j, c in enumerate(backup_codes) if j != i]
                return True, remaining

    return False, backup_codes


def generate_totp_qr_svg(data_str: str) -> str:
    """
    Generates a pure-Python, zero-dependency SVG QR Code (Version 5, Byte Mode, Level L).
    Compatible with camera scanning in Google Authenticator and Microsoft Authenticator.
    """
    # GF(2^8) Galois Field arithmetic
    gf_exp = [0] * 512
    gf_log = [0] * 256
    x = 1
    for i in range(255):
        gf_exp[i] = x
        gf_exp[i + 255] = x
        gf_log[x] = i
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1D

    def gf_mul(a, b):
        if a == 0 or b == 0:
            return 0
        return gf_exp[gf_log[a] + gf_log[b]]

    def rs_poly_mul(p1, p2):
        res = [0] * (len(p1) + len(p2) - 1)
        for j, c2 in enumerate(p2):
            for i, c1 in enumerate(p1):
                if c1 and c2:
                    res[i + j] ^= gf_exp[gf_log[c1] + gf_log[c2]]
        return res

    def rs_generator_poly(nsym):
        g = [1]
        for i in range(nsym):
            g = rs_poly_mul(g, [1, gf_exp[i]])
        return g

    def rs_encode(data, nsym):
        gen = rs_generator_poly(nsym)
        res = list(data) + [0] * nsym
        for i in range(len(data)):
            coef = res[i]
            if coef != 0:
                for j in range(len(gen)):
                    res[i + j] ^= gf_mul(gen[j], coef)
        return res[len(data):]

    raw_bytes = data_str.encode('utf-8')[:106]
    bits = [0, 1, 0, 0]  # Byte mode
    count = len(raw_bytes)
    for i in range(7, -1, -1):
        bits.append((count >> i) & 1)
    for b in raw_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    bits.extend([0] * min(4, 108 * 8 - len(bits)))
    while len(bits) % 8 != 0:
        bits.append(0)

    data_cw = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        data_cw.append(byte_val)

    pad_bytes = [0xEC, 0x11]
    pad_idx = 0
    while len(data_cw) < 108:
        data_cw.append(pad_bytes[pad_idx % 2])
        pad_idx += 1

    ec_cw = rs_encode(data_cw, 26)
    all_cw = data_cw + ec_cw

    all_bits = []
    for b in all_cw:
        for i in range(7, -1, -1):
            all_bits.append((b >> i) & 1)
    all_bits.extend([0] * 7)  # Remainder bits for v5

    size = 37
    matrix = [[None] * size for _ in range(size)]

    def add_finder(r0, c0):
        for r in range(7):
            for c in range(7):
                if r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4):
                    matrix[r0 + r][c0 + c] = 1
                else:
                    matrix[r0 + r][c0 + c] = 0
        for r in range(-1, 8):
            for c in range(-1, 8):
                if r in (-1, 7) or c in (-1, 7):
                    rr, cc = r0 + r, c0 + c
                    if 0 <= rr < size and 0 <= cc < size:
                        matrix[rr][cc] = 0

    add_finder(0, 0)
    add_finder(0, size - 7)
    add_finder(size - 7, 0)

    # Alignment pattern at (30, 30)
    for r in range(-2, 3):
        for c in range(-2, 3):
            if abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0):
                matrix[30 + r][30 + c] = 1
            else:
                matrix[30 + r][30 + c] = 0

    # Timing patterns
    for i in range(8, size - 8):
        if matrix[6][i] is None:
            matrix[6][i] = 1 if i % 2 == 0 else 0
        if matrix[i][6] is None:
            matrix[i][6] = 1 if i % 2 == 0 else 0

    matrix[size - 8][8] = 1

    # Format info reserved
    for i in range(9):
        if matrix[8][i] is None: matrix[8][i] = 0
        if matrix[i][8] is None: matrix[i][8] = 0
    for i in range(size - 8, size):
        if matrix[8][i] is None: matrix[8][i] = 0
        if matrix[i][8] is None: matrix[i][8] = 0

    format_bits = [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0]
    fb_top = [
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)
    ]
    fb_side = [
        (size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8), (size - 6, 8), (size - 7, 8),
        (8, size - 8), (8, size - 7), (8, size - 6), (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)
    ]
    for bit, (r, c) in zip(format_bits, fb_top):
        matrix[r][c] = bit
    for bit, (r, c) in zip(format_bits, fb_side):
        matrix[r][c] = bit

    bit_idx = 0
    right = size - 1
    up = True
    while right > 0:
        if right == 6:
            right -= 1
        cols = [right, right - 1]
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for c in cols:
                if matrix[r][c] is None:
                    b = all_bits[bit_idx] if bit_idx < len(all_bits) else 0
                    bit_idx += 1
                    if (r + c) % 2 == 0:
                        b ^= 1
                    matrix[r][c] = b
        right -= 2
        up = not up

    svg_paths = []
    margin = 4
    total_size = size + margin * 2
    for r in range(size):
        for c in range(size):
            if matrix[r][c] == 1:
                svg_paths.append(f"M{c + margin},{r + margin}h1v1h-1z")
    path_d = "".join(svg_paths)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_size} {total_size}" '
        f'shape-rendering="crispEdges" style="background:#ffffff; border-radius:10px; padding:10px; width:220px; height:220px;">'
        f'<path d="{path_d}" fill="#0b1329"/>'
        f'</svg>'
    )

