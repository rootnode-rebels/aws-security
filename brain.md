# AWSSecurity AI Brain Context (Project Memory)

This file serves as the permanent memory store for the project context, critical architectural decisions, security patches, and live configurations. It ensures no context is lost between sessions.

## 🏗️ Core Architecture & Configurations
- **Database:** MongoDB Atlas Cloud (ccount_security_db)
- **Backend:** Python FastAPI (ackend/app.py)
- **Frontend:** HTML/JS/CSS (rontend/)
- **Containerization:** Docker (Dockerfile)
- **Deployment Platform:** AWS App Runner (eu-central-1)
- **Notification Services:** Amazon SNS & Desktop Toast Notifications
- **Machine Learning:** TensorFlow Deep Autoencoder (ackend/security/ml_engine.py)

## 🔐 Master Credentials
The following God Mode and Super Admin accounts are actively seeded in the live ccount_security_db:
1. **God Mode Admin (ROOT_OWNER):** dhiam@outlook.in | UltimateAdmin#2026
2. **Super Admin (SUPER_ADMIN):** nushree2k5@gmail.com | TempAdmin#2026

## 🛡️ Critical Security Patches Applied
1. **PyMongo Cursor Serialization Bug (FIXED):** Fixed a 500 error in the SNS inbox caused by an inability to len() or serialize MongoDB Cursor objects.
2. **Cross-Region SNS Dispatches (FIXED):** Implemented dynamic ARN parsing to resolve the AWS SDK us-east-1 vs eu-central-1 region mismatch.
3. **Database Seed Target Bug (FIXED):** Fixed seed_mongo.py injecting God Mode accounts into ws_security instead of the active ccount_security_db, which was causing unauthorized lockouts.
4. **MFA Hardware Fingerprint Bypass (FIXED):** Removed a fallback vulnerability where a secondary device (e.g., an incognito window) could bypass the MFA step-up challenge if its hardware fingerprint (canvas_hash, os, rowser) collided with the Primary Device. Primary Device authentication now strictly requires the cryptographic rowser_id token from LocalStorage.

## 🧹 Repository State
- Cleaned up obsolete AWS JSON configurations (pprunner-mumbai.json, etc.).
- Safely purged local credentials (tlas-credentials.env) to prevent GitHub leaks.
- All automation scripts migrated to /scripts.
