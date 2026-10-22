import json
import os
import sys
from pymongo import MongoClient
import urllib.parse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.security.auth import hash_password

uri = os.getenv("MONGODB_URI")
if not uri:
    print("[ERROR] MONGODB_URI environment variable is not set. Please set MONGODB_URI in your .env before seeding.")
    sys.exit(1)

client = MongoClient(uri)
db_name = os.getenv("MONGODB_DB_NAME", "account_security_db")
db = client.get_database(db_name)
users = db['users']

print(f"Connected to MongoDB. Seeding configured administrator accounts into {db_name}...")

import secrets

super_email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@awssecurity.io").strip().lower()
super_pwd = os.getenv("SUPER_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
pwd_hash, salt = hash_password(super_pwd)

users.update_one(
    {"email": super_email},
    {"$set": {
        "email": super_email,
        "full_name": "Super Administrator",
        "password_hash": pwd_hash,
        "salt": salt,
        "role": "SUPER_ADMIN",
        "is_root_admin": False,
        "is_super_admin": True,
        "status": "ACTIVE"
    }},
    upsert=True
)

root_email = os.getenv("ROOT_OWNER_EMAIL", "root@awssecurity.io").strip().lower()
root_pwd = os.getenv("ROOT_OWNER_PASSWORD") or secrets.token_urlsafe(16)
pwd_hash2, salt2 = hash_password(root_pwd)

users.update_one(
    {"email": root_email},
    {"$set": {
        "email": root_email,
        "full_name": "System Root Administrator",
        "password_hash": pwd_hash2,
        "salt": salt2,
        "role": "ROOT_OWNER",
        "is_root_admin": True,
        "status": "ACTIVE"
    }},
    upsert=True
)

print(f"✅ Administrator accounts configured: {super_email} and {root_email}")
if not os.getenv("SUPER_ADMIN_PASSWORD"):
    print(f"   [Generated Super Admin Password]: {super_pwd}")
if not os.getenv("ROOT_OWNER_PASSWORD"):
    print(f"   [Generated Root Owner Password]: {root_pwd}")
