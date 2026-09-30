import sys
import json
import os

filepath = 'd:/RootNode-Rebels/AWS Project/data/db.json'

try:
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Keep only the Super Admin account
    super_admin = [u for u in data.get('users', []) if u.get('email') == 'anushree2k5@gmail.com']

    # Reset all collections
    data['users'] = super_admin
    data['active_sessions'] = []
    data['security_events'] = []
    data['password_resets'] = []
    data['cloudwatch_logs'] = []
    data['security_alerts'] = []

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    print("✅ Database successfully wiped! All data destroyed except the Super Admin (anushree2k5@gmail.com).")
except Exception as e:
    print(f"❌ Failed to reset database: {e}")
