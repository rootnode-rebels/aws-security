import json
import os
import sys
import secrets

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
from backend.security.auth import hash_password

filepath = os.path.join(PROJECT_ROOT, 'data', 'db.json')

if not os.path.exists(filepath):
    print(f"[DB] No db.json found at {filepath}")
    sys.exit(0)

with open(filepath, 'r', encoding='utf-8') as f:
    data = json.load(f)

users = data.get('users', [])

super_email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@awssecurity.io").strip().lower()
super_pwd = os.getenv("SUPER_ADMIN_PASSWORD") or secrets.token_urlsafe(16)

root_email = os.getenv("ROOT_OWNER_EMAIL", "root@awssecurity.io").strip().lower()
root_pwd = os.getenv("ROOT_OWNER_PASSWORD") or secrets.token_urlsafe(16)

# Remove duplicates of these admin accounts
users = [u for u in users if u.get('email', '').lower() not in [super_email, root_email]]

# Add Super Admin
pwd_hash, salt = hash_password(super_pwd)
users.append({
    '_id': 'user_superadmin',
    'email': super_email,
    'full_name': 'Super Administrator',
    'password_hash': pwd_hash,
    'salt': salt,
    'role': 'SUPER_ADMIN',
    'is_root_admin': False,
    'is_super_admin': True,
    'registered_at': 1690000000000,
    'status': 'ACTIVE'
})

# Add Root Owner
pwd_hash2, salt2 = hash_password(root_pwd)
users.append({
    '_id': 'user_godmode',
    'email': root_email,
    'full_name': 'System Root Administrator',
    'password_hash': pwd_hash2,
    'salt': salt2,
    'role': 'ROOT_OWNER',
    'is_root_admin': True,
    'is_root_owner': True,
    'registered_at': 1690000000000,
    'status': 'ACTIVE'
})

data['users'] = users

with open(filepath, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)

print(f"Database sanitized with configured Super Admin ({super_email}) and Root Owner ({root_email}).")
