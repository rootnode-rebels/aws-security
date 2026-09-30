import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from backend.security.auth import hash_password

filepath = 'd:/RootNode-Rebels/AWS Project/data/db.json'

with open(filepath, 'r', encoding='utf-8') as f:
    data = json.load(f)

users = data.get('users', [])

# Remove existing accounts to prevent duplicates
users = [u for u in users if u.get('email') not in ['adhiam@outlook.in', 'anushree2k5@gmail.com']]

# Add Super Admin
pwd_hash, salt = hash_password('TempAdmin#2026')
users.append({
    '_id': 'user_superadmin',
    'email': 'anushree2k5@gmail.com',
    'full_name': 'Anushree K',
    'password_hash': pwd_hash,
    'salt': salt,
    'role': 'SUPER_ADMIN',
    'is_root_admin': False,
    'registered_at': 1690000000000,
    'status': 'ACTIVE'
})

# Add God Mode
pwd_hash2, salt2 = hash_password('UltimateAdmin#2026')
users.append({
    '_id': 'user_godmode',
    'email': 'adhiam@outlook.in',
    'full_name': 'Adhi AM (God Mode)',
    'password_hash': pwd_hash2,
    'salt': salt2,
    'role': 'ROOT_OWNER',
    'is_root_admin': True,
    'registered_at': 1690000000000,
    'status': 'ACTIVE'
})

data['users'] = users

with open(filepath, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)

print("Database fixed with both Super Admin and God Mode credentials.")
