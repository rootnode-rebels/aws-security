#!/usr/bin/env python3
"""
Pre-commit hook & automated scanner to prevent accidental leaks of:
- MongoDB Atlas URIs with embedded passwords
- AWS Access Keys
- Hardcoded sensitive credentials
- Temporary backdoor endpoints
"""
import sys
import os
import re
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

FORBIDDEN_PATTERNS = [
    (re.compile(r"mongodb\+srv://[^:]+:[^@]+@", re.IGNORECASE), "Live MongoDB Atlas URI with credentials"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"/api/temp-reset"), "Rogue backdoor /api/temp-reset route"),
    (re.compile(r"V33Ryxrh8VtUD83I"), "Leaked legacy database password"),
    (re.compile(r"likitha@2005"), "Hardcoded administrator password"),
    (re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? PRIVATE KEY-----"), "Private cryptographic key"),
]

def check_staged_files():
    try:
        # Get list of staged files
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
        output = subprocess.check_output(cmd, text=True, errors="ignore").splitlines()
    except Exception as e:
        print(f"[PRE-COMMIT SCANNER] Warning: Failed to query git status: {e}")
        return 0

    violations = []
    scanned_exts = (".py", ".js", ".json", ".bat", ".ps1", ".md", ".sh", ".yml", ".yaml", ".env")
    excluded_files = ("pre_commit_secrets_check.py", "test_deep_security_probe.py")

    for filepath in output:
        filepath = filepath.strip()
        if not filepath or not os.path.exists(filepath):
            continue
        
        # Never allow committing actual .env files
        base = os.path.basename(filepath)
        if base == ".env" or (base.startswith(".env.") and not base.endswith(".example")):
            violations.append(f"{filepath} -> Staging .env files is strictly forbidden by policy!")

        if filepath.endswith(scanned_exts) and not filepath.endswith(excluded_files):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, 1):
                        for pattern, desc in FORBIDDEN_PATTERNS:
                            if pattern.search(line):
                                violations.append(f"{filepath}:{line_idx} -> {desc}")
            except Exception:
                pass

    if violations:
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        print("\n" + "=" * 70)
        print("[!] [SECURITY ALERT] COMMIT ABORTED: Sensitive credentials detected!")
        print("=" * 70)
        for v in violations:
            print(f"  • {v}")
        print("\nPlease remove the credentials, use environment variables (.env), and re-stage.")
        print("=" * 70 + "\n")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(check_staged_files())
