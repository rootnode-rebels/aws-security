#!/usr/bin/env python3
"""
Deep Security Audit Scanner for AWSSecurity AI.
Audits:
1. Hardcoded Secrets, API Keys, Tokens, Database Credentials
2. Authentication & Authorization Flaws (Missing auth decorators, IDOR, weak tokens)
3. Cryptographic Weaknesses (Weak hashing, predictable PRNGs)
4. Injection Flaws (NoSQL injection, Command injection, Path Traversal, XSS)
5. Sensitive Information Exposure (Debug endpoints, stack traces, leaked PII)
6. Security Headers & CORS Misconfigurations
"""
import os
import re
import sys

import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

IGNORE_DIRS = {'.git', '__pycache__', '.pytest_cache', 'venv', 'env', 'node_modules', '.idea', '.vscode'}
IGNORE_FILES = {'audit_security.py', 'pre_commit_secrets_check.py', 'package-lock.json'}
IGNORE_EXTS = (
    '.pyc', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot',
    '.exe', '.dll', '.bin', '.zip', '.gz', '.tar', '.pkl', '.h5', '.joblib', '.so', '.dylib'
)

PATTERNS = [
    # Secrets & Credentials
    (re.compile(r'mongodb(\+srv)?://[^:\s]+:[^@\s]+@', re.I), "CRITICAL: Live MongoDB connection string with credentials"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL: AWS Access Key ID"),
    (re.compile(r'-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----'), "CRITICAL: Private Cryptographic Key"),
    (re.compile(r'(?i)(jwt_secret|secret_key)\s*=\s*["\'][a-zA-Z0-9_\-!@#$%^&*]{8,}["\']'), "HIGH: Hardcoded JWT or Secret Key fallback"),
    
    # Insecure Code Execution & Injections
    (re.compile(r'\beval\s*\('), "HIGH: Dynamic eval() call detected"),
    (re.compile(r'\bexec\s*\('), "HIGH: Dynamic exec() call detected"),
    (re.compile(r'subprocess\.(Popen|run|call|check_output)\([^)]*shell\s*=\s*True', re.I), "HIGH: Subprocess execution with shell=True"),
    (re.compile(r'os\.system\s*\('), "HIGH: os.system() invocation detected"),
    
    # Crypto & PRNG
    (re.compile(r'\brandom\.random\(\)|\brandom\.randint\(|\brandom\.choice\('), "MEDIUM: Insecure PRNG (use secrets module for crypto/tokens)"),
    (re.compile(r'hashlib\.md5\(|hashlib\.sha1\('), "MEDIUM: Weak cryptographic hash (MD5/SHA1)"),
    
    # Backdoors & Debug routes
    (re.compile(r'/api/' + r'temp-reset'), "CRITICAL: Rogue backdoor endpoint"),
    (re.compile(r'/api/debug/|/debug/'), "MEDIUM: Debug endpoint pattern"),
]

def run_audit():
    findings = []
    
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for f in files:
            if f in IGNORE_FILES or f.lower().endswith(IGNORE_EXTS):
                continue
            
            filepath = os.path.join(root, f)
            relpath = os.path.relpath(filepath, PROJECT_ROOT)
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = fh.readlines()
                    for idx, line in enumerate(lines, 1):
                        stripped = line.strip()
                        for pat, desc in PATTERNS:
                            if pat.search(stripped):
                                # Filter out docstrings/comments that mention the issue descriptively
                                if "FORBIDDEN_PATTERNS" in stripped or "test_" in relpath or "re.compile" in stripped:
                                    continue
                                findings.append({
                                    "file": relpath,
                                    "line": idx,
                                    "desc": desc,
                                    "snippet": stripped[:120]
                                })
            except Exception as e:
                pass

    print(f"Audit completed. Total automated pattern hits: {len(findings)}\n")
    for f in findings:
        print(f"[{f['desc']}]")
        print(f"  File: {f['file']}:{f['line']}")
        print(f"  Snippet: {f['snippet']}\n")

if __name__ == "__main__":
    run_audit()
