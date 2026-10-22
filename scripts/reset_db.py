import sys
import json
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
filepath = os.path.join(PROJECT_ROOT, 'data', 'db.json')

super_admin_email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@awssecurity.io").strip().lower()

try:
    if not os.path.exists(filepath):
        print(f"[DB] No db.json found at {filepath}")
        sys.exit(0)

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Keep configured admin and baseline presentation demo accounts, unlocking them
    retained_roles = {'SUPER_ADMIN', 'ROOT_OWNER', 'ROOT_ADMIN'}
    retained_emails = {super_admin_email, 'demouser@mail.com', 'demo@awssecurity.io', 'demo@aegisguard.io'}
    
    preserved_users = []
    for u in data.get('users', []):
        if not isinstance(u, dict):
            continue
        e = u.get('email', '').lower()
        if e in retained_emails or u.get('role') in retained_roles:
            u['status'] = 'ACTIVE'
            u['mfa_pending'] = None
            if 'account_is_frozen' in u:
                u['account_is_frozen'] = False
            preserved_users.append(u)

    # Reset transient collections
    data['users'] = preserved_users
    data['active_sessions'] = []
    data['security_events'] = []
    data['password_resets'] = []
    data['cloudwatch_logs'] = []
    data['security_alerts'] = []

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    print(f"[DB RESET] Local document database successfully reset! Retained clean accounts: {[u.get('email') for u in preserved_users]}.")
except Exception as e:
    print(f"[DB RESET ERROR] Failed to reset database: {e}")
