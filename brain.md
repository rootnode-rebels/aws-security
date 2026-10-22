# AWSSecurity AI Brain Context (Project Memory)

This file serves as the permanent memory store for the project context, critical architectural decisions, security patches, and live configurations. It ensures no context is lost between sessions.

## 🏗️ Core Architecture & Configurations
- **Database:** MongoDB Atlas Cloud / Local Document Store (`account_security_db`)
- **Backend:** Python FastAPI (`backend/app.py`)
- **Frontend:** HTML/JS/CSS (`frontend/`)
- **Containerization:** Docker (`Dockerfile`)
- **Deployment Platform:** AWS App Runner
- **Notification Services:** Amazon SNS & Desktop Toast Notifications
- **Machine Learning:** Scikit-learn / TensorFlow Deep Autoencoder (`backend/ml/`)

## 🔐 Administrative Access
Administrative accounts are managed dynamically via environment variables:
- `SUPER_ADMIN_EMAIL` and `SUPER_ADMIN_PASSWORD`
- `ROOT_OWNER_EMAIL` and `ROOT_OWNER_PASSWORD`

No administrative credentials or personal emails are stored in repository documentation or version control.

## 🛡️ Critical Security Patches Applied
1. **PyMongo Cursor Serialization Bug (FIXED):** Fixed a 500 error in the SNS inbox caused by an inability to len() or serialize MongoDB Cursor objects.
2. **Cross-Region SNS Dispatches (FIXED):** Implemented dynamic ARN parsing to resolve the AWS SDK us-east-1 vs eu-central-1 region mismatch.
3. **Database Seed Target Bug (FIXED):** Fixed seed target to inject into the active `account_security_db`.
4. **MFA Hardware Fingerprint Bypass (FIXED):** Removed a fallback vulnerability where a secondary device could bypass the MFA step-up challenge if its hardware fingerprint collided with the Primary Device. Primary Device authentication strictly requires the cryptographic `browser_id` token from LocalStorage.
5. **Backdoor Removal & Credential Sanitization (FIXED):** Removed unauthenticated legacy temp-reset backdoor, stripped hardcoded Atlas URI and plaintext credentials from scripts, and parameterized all administrative setup.

## 🧹 Repository State
- Purged local sensitive artifacts from scripts and tests.
- Replaced hardcoded connection strings with dynamic environment variables.
- All automation scripts migrated to `/scripts` with secure cleanup routines.
