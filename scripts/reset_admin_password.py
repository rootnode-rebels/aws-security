"""
Admin Password Reset Script.
Safely resets or initializes passwords for administrator accounts across MongoDB and local document storage.
"""
import sys
import os
import argparse
import secrets

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.security.auth import hash_password
from database.db_manager import DatabaseManager

def reset_admin_password(email: str, password: str = None, role: str = "SUPER_ADMIN", full_name: str = None):
    email = email.strip().lower()
    if not password:
        password = secrets.token_urlsafe(16)
        generated = True
    else:
        generated = False

    pwd_hash, salt = hash_password(password)

    db_mgr = DatabaseManager()
    users_col = db_mgr.users

    existing_user = users_col.find_one({"email": email})
    display_name = full_name or (existing_user.get("full_name") if existing_user else email.split("@")[0].title())

    update_payload = {
        "email": email,
        "full_name": display_name,
        "password_hash": pwd_hash,
        "salt": salt,
        "role": role,
        "is_super_admin": True if role == "SUPER_ADMIN" else False,
        "is_root_admin": True if role in ("ROOT_OWNER", "ROOT_ADMIN") else False,
        "status": "ACTIVE",
        "mfa_pending": None,
        "account_is_frozen": False,
        "failed_attempts": 0
    }

    if existing_user:
        users_col.update_one({"email": email}, {"$set": update_payload})
        action = "Updated existing"
    else:
        update_payload["registered_at"] = 1690000000000
        users_col.insert_one(update_payload)
        action = "Created new"

    return {
        "email": email,
        "role": role,
        "password": password,
        "is_generated": generated,
        "action": action
    }

def main():
    parser = argparse.ArgumentParser(description="Reset administrator account password.")
    parser.add_argument("--email", required=True, help="Administrator email address")
    parser.add_argument("--password", default=None, help="New password (generates secure token if omitted)")
    parser.add_argument("--role", default="SUPER_ADMIN", help="Role (SUPER_ADMIN, ROOT_OWNER, etc.)")
    parser.add_argument("--name", default=None, help="Display full name")

    args = parser.parse_args()
    res = reset_admin_password(args.email, args.password, args.role, args.name)
    print(f"[{res['action']}] {res['email']} ({res['role']})")
    print(f"New Password: {res['password']}")

if __name__ == "__main__":
    main()
