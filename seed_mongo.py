import json
import os
import sys
from pymongo import MongoClient
import urllib.parse

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from backend.security.auth import hash_password

uri = "mongodb+srv://anushree2k5_db_user:V33Ryxrh8VtUD83I@cluster0.utejvsm.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(uri)
db = client['test'] # Atlas default DB is often 'test' if not specified, wait, let's use 'aws_security'
db = client.get_default_database('aws_security')
users = db['users']

print("Connected to MongoDB Atlas. Seeding admin accounts...")

users.delete_many({"email": {"$in": ['adhiam@outlook.in', 'anushree2k5@gmail.com']}})

pwd_hash, salt = hash_password('TempAdmin#2026')
users.insert_one({
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

pwd_hash2, salt2 = hash_password('UltimateAdmin#2026')
users.insert_one({
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

print("✅ God Mode and Super Admin injected into live MongoDB!")
