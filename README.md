# 🛡️ Real-Time Account Hijacking Detection and Prevention System (AWSSecurity AI)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![AWS Serverless](https://img.shields.io/badge/AWS-Serverless%20SAM-FF9900.svg)](https://aws.amazon.com/serverless/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 10 Suites Passing](https://img.shields.io/badge/Tests-10%20Suites%20Passing-brightgreen.svg)](#-automated-testing-suite)

A cloud-native cybersecurity platform built on AWS Serverless architecture that leverages **Continuous Behavioral Authentication** and a **Hybrid Machine Learning Pipeline** to detect, analyze, alert, and automatically block account takeover and session hijacking attempts in real time.

---

## 🏗️ System Architecture & Workflow

Rather than trusting static passwords alone, incoming telemetry is evaluated on every session by an ensemble ML inference pipeline. The architecture enforces **Primary Device Authority**, **Zero-Data Leakage Challenges**, **Single-Device Super Admin Governance**, and **Tiered Intelligent Alert Routing**.

`mermaid
flowchart TD
    subgraph CLIENT["Multi-Persona Cyber Suite"]
        U1["🛡️ User Security Portal<br/>(Primary Device, Siren & Remote Kill Switch)"]
        U2["⚡ Red Team Attack Studio<br/>(VPN Simulation, Tokyo Travel, Tor, Brute Force)"]
        U3["🛰️ Blue Team SOC Visualizer<br/>(Real-time SVG Gauge & Haversine Flight Map)"]
        U4["👑 CMS Governance & Super Admin Console<br/>(User Management, Unlock/Delete, Maintenance Mode)"]
        U5["📊 CloudWatch SIEM<br/>(Metrics, Audit Logs, Clear/Purge Controls)"]
    end

    subgraph GATEWAY["Amazon API Gateway & Hardening"]
        GW["REST API Gateway (CORS Enabled)"]
        V["Pydantic Validation • XSS & NoSQL Sanitizer<br/>Dual-Layer Sliding-Window Rate Limiter"]
    end

    subgraph COMPUTE["AWS Lambda Serverless Microservices"]
        L1["Auth & Session Handler<br/>(PBKDF2-SHA256, Zero-Leakage MFA, Kill Switch)"]
        L2["ML Risk Engine<br/>(Hybrid Behavioral Inference Pipeline)"]
        L3["Tiered Alert Dispatcher<br/>(Primary Device Inbox vs Out-of-Band Email)"]
        L4["CMS & Governance Engine<br/>(Emergency Maintenance & Device Session Revocation)"]
    end

    subgraph ML["Hybrid Machine Learning Pipeline"]
        M1["Scikit-Learn Random Forest (Supervised Compromise Risk)"]
        M2["Scikit-Learn Isolation Forest (Zero-Day Outlier Detection)"]
        M3["TensorFlow Deep Autoencoder (Reconstruction MSE Loss)"]
    end

    subgraph STORAGE["Telemetry & Storage Layer"]
        CW["Amazon CloudWatch (Metrics: BlockedHijacks, Alarms, Logs)"]
        SNS["Amazon SNS / Out-of-Band Email Dispatcher"]
        DB["MongoDB 7.0 / Transparent Local Document Store"]
    end

    CLIENT -->|HTTPS / REST| GW --> V --> COMPUTE
    L2 --> ML
    COMPUTE --> STORAGE
    L3 -.->|All Security Events / Live Siren| U1
    L3 -.->|Critical Threats Only: Travel > 900km/h, Tor, Bursts| SNS
`

---

## 👑 Super Admin Governance & Session Control

The platform implements privileged enterprise governance for the SUPER_ADMIN role:

1. **Privileged Immunity & Zero Lockout:**
   - Immune to failed login rate-limiting, IP lockouts, and brute-force lockouts.
   - Bypasses geofencing and geographical location restrictions.
2. **Single-Device Session Governance:**
   - Super Admin accounts are restricted to **one active device at a time**.
   - If credentials are submitted from a new/second device, the system automatically detects the conflict and prompts the administrator to revoke/log out previous sessions before authorizing access.
3. **CMS Platform Management (/api/cms/*):**
   - **User Directory:** View all registered accounts, roles, registration dates, and security statuses.
   - **Account Unlock:** One-click unbanning of user accounts locked out by automated defenses.
   - **Purge / Delete:** Instant deletion of compromised or decommissioned accounts.
   - **Emergency Maintenance Mode:** Platform-wide lockdown preventing regular user access during security incidents.

---

## 🧠 Multi-Layer Machine Learning Risk Engine

### 7-Dimensional Behavioral Feature Vector
Incoming sessions are transformed into a normalized behavioral vector comparing current telemetry against historical user baselines:

| Feature | Description | Anomaly Trigger |
| :--- | :--- | :--- |
| **geo_velocity_kmh** | Haversine velocity between successive logins | $> 900\text{ km/h}$ (Impossible Travel) |
| **distance_km** | Physical geographic distance from baseline | Sudden intercontinental shift |
| **device_distance** | Canvas fingerprint, OS, browser audio/WebGL divergence | Unrecognized hardware canvas ($> 0.5$) |
| **ip_reputation** | Tor exit relays, VPN endpoints, and datacenter proxies | Verified Tor exit node / Datacenter IP ($= 1.0$) |
| **ailed_attempts_burst** | Velocity of recent failed password attempts | $> 3\text{ failed attempts in 10 min}$ |
| **circadian_anomaly** | Deviation from historical active login hours | Activity during anomalous off-hours ($> 0.6$) |
| **ot_signature** | Headless browser markers (
avigator.webdriver, missing plugins) | Automated bot signature ($= 1.0$) |

### Hybrid Models & Inference Pipeline
1. **Scikit-Learn Random Forest Classifier**: Evaluates supervised compromise probability ( - 100\%$) trained on historical attack telemetry.
2. **Scikit-Learn Isolation Forest**: Identifies unsupervised zero-day behavioral anomalies and unrecognized vectors.
3. **TensorFlow Deep Neural Autoencoder (7-4-2-4-7)**: Measures reconstruction Mean Squared Error ($\text{MSE} > 0.12$) to flag subtle multi-variable drifts.
4. **Explainable AI (XAI)**: Generates human-readable factor attribution weights for every security event, identifying the exact root-cause drivers.

---

## ⚡ Adaptive Policy & Tiered Notification Architecture

To prevent notification fatigue while guaranteeing immediate reaction to genuine cyber threats, the system implements a **Human-Coverable Velocity Policy** and **Multi-Tier Notification Routing**:

`
+-----------------------------------------------------------------------------------+
|                            INCOMING SESSION TELEMETRY                             |
+-----------------------------------------------------------------------------------+
                                          |
                         [ Hybrid ML Risk Engine Evaluation ]
                                          |
            +-----------------------------+-----------------------------+
            |                                                           |
   Risk Score: 0 – 39                                          Risk Score: 40 – 69
[ Human-Coverable Distance / Normal ]                   [ Moderate Anomaly / New Device ]
            |                                                           |
       Action: ALLOW                                          Action: STEP_UP_MFA
  • Granted normal access                                • Adaptive 6-digit OTP challenge
  • Primary inbox logged (Silent)                        • Primary inbox notified
                                                         • Zero hardware leakage to client
                                                                        |
                                                                        v
                                                               Risk Score: 70 – 100
                                                        [ Critical Threat: Impossible Travel,
                                                          Tor Exit Node, Credential Stuffing ]
                                                                        |
                                                              Action: BLOCK_SESSION
                                                         • Session terminated instantly
                                                         • CloudWatch BlockedHijacks ++
                                                         • 🔊 Audible Siren on Primary Device
                                                         • 🚨 Primary Device Inbox Alert
                                                         • 📧 Out-of-Band Email to User
`

---

## 🔒 Security Hardening & Zero-Trust Features

- **Primary Device Authority**: Users register their master workstation. Secondary devices cannot kill or alter primary sessions; only the primary device holds the remote **Kill Switch** to revoke secondary sessions.
- **Zero-Data-Leakage MFA**: Challenge endpoints return only an opaque challenge ID and device type; hardware canvas fingerprints and master device labels are strictly withheld from unauthenticated callers.
- **Direct Instant Registration**: New accounts are activated immediately upon registration with instant local authentication, bypassing verification email delays for smooth onboarding.
- **Password Visibility Control**: Built-in interactive eye icon (👁️) toggle on login and registration forms.
- **Essential Storage Consent**: Built-in GDPR/CCPA compliance banner with persistent local consent storage.
- **PBKDF2-HMAC-SHA256**: 200,000 hashing rounds with 16-byte cryptographically secure per-user salts (secrets.token_hex).
- **Sliding-Window Rate Limiting**: Dual-layer rate limiting locks out brute-force guessing after 5 failures in 10 minutes while preserving loopback demo stability.
- **XSS & NoSQL Sanitization**: Recursive input sanitizer strips <script> tags, HTML event handlers, and NoSQL injection operators ($where, $gt, $ne, prototype pollution).

---

## 🚀 Quick Start (Running Locally & Live Sharing)

Zero AWS cloud dependencies or external databases required—includes a built-in local document database and CloudWatch SIEM telemetry emulator.

### 1. Installation
`ash
git clone https://github.com/rootnode-rebels/aws-security.git
cd aws-security

# Install dependencies
pip install -r requirements.txt
`

### 2. Start the Application
`ash
python run_standalone.py
`
Open **http://127.0.0.1:8000** in your browser.

- **Localhost URL:** http://127.0.0.1:8000
- **LAN Wi-Fi URL:** http://<YOUR_LOCAL_IP>:8000 (e.g. http://192.168.1.19:8000 for testing across phones/laptops on the same network)

### 3. Share Live Publicly (Cloudflare Quick Tunnel)
To share the live application with remote users or friends without port-forwarding, IP passwords, or interstitial warning screens:
`ash
cloudflared tunnel --url http://127.0.0.1:8000
`
This generates a clean HTTPS link (e.g., https://<subdomain>.trycloudflare.com) accessible directly from any device.

---

## 👥 Seeded Demonstration Accounts

| Persona | Role | Email | Password | Baseline Location |
| :--- | :--- | :--- | :--- | :--- |
| **Super Admin** | SUPER_ADMIN | likhithadm@gmail.com | likitha@2005 | Anywhere (Immune) |
| **Demo Security Lead** | ROOT_ADMIN | demo@awssecurity.io | MasterKey#2026 / Demo Token | New York, US |
| **Demo User** | USER | demouser@mail.com | DemoUser.AWS@29 | New York, US |
| **Demo Account** | ROOT_ADMIN | demo@aegisguard.io | MasterKey#2026 | New York, US |

*(New user registration is fully supported on the portal with instant activation and password visibility toggling).*

---

## 🎯 Live Demonstration Guide (Two-Browser / Remote Test)

Demonstrate real-time account hijacking detection, impossible travel, and automated blocking across two browsers or devices:

`
+------------------------------------+------------------------------------+
|   BROWSER 1: CHROME (PRIMARY)      |   BROWSER 2: EDGE / REMOTE         |
|   Account: demo@awssecurity.io     |   Using Stolen Master Credentials  |
|   Location: New York (Baseline)    |   Location: Tokyo (VPN / Spoofed)  |
|   Role: Master Security Device     |   Action: Rogue Hijack Attempt     |
+------------------------------------+------------------------------------+
`

### Step 1: Legitimate User Baseline (Browser 1)
1. Open http://127.0.0.1:8000 in **Browser 1**.
2. Click **👤 Fill Demo User** and authenticate.
3. When the Primary Device modal appears, click **🛡️ Yes, Register as My Primary Device**.
4. The dashboard displays **🛡️ Primary Security Portal (Master Device)** with 🔊 Sound: ON and active session monitoring.

### Step 2: Attacker Simulation (Browser 2 or Attack Studio)
**Option A — Using the Red Team Attack Studio:**
1. In Browser 2 (or a separate tab), navigate to the **⚡ Attack Simulator** tab.
2. Select demo@awssecurity.io and click **Launch Scenario** under **Impossible Travel (Tokyo, 8,500 km/h)**.

**Option B — Live Remote / Second Device Test:**
1. Open the public Cloudflare tunnel or LAN URL on a second phone or computer.
2. Attempt login using demo@awssecurity.io.

### Step 3: Observe Automated Defense in Browser 1
- **Audible Siren Alarm**: Browser 1 immediately sounds an audio siren.
- **Red Alert Banner**: A pulsing crimson threat banner drops down with attacker velocity details.
- **Security Inbox**: An alert appears with full **XAI Factor Attribution** (geo_velocity_kmh: 99%, distance: 98%).
- **Blue Team SOC**: The SVG risk needle spikes to 98/100, and the world map traces the impossible flight path.
- **Attacker Blocked**: The rogue session in Browser 2 receives an immediate **403 Forbidden** rejection.

---

## 🧪 Automated Testing Suite

The repository contains 10 comprehensive test suites covering unit tests, integration tests, impossible travel detection, multi-device governance, and security audits:

`ash
# Run all test suites
python -m unittest discover tests

# Or run individual specialized suites:
python -m unittest tests/test_backend.py                  # Core REST API & rate limiting
python -m unittest tests/test_vpn_impossible_travel_flow.py # Live VPN & travel velocity tests
python -m unittest tests/test_primary_device_flow.py      # Master device kill switch & tokens
python -m unittest tests/test_primary_and_mfa.py         # Step-up MFA & zero-leakage challenges
python -m unittest tests/test_notification_service.py    # Primary inbox & out-of-band email dispatch
python -m unittest tests/test_background_notifications.py# Async notification queuing
python -m unittest tests/test_root_admin_demo_delete.py  # User deletion & admin reset controls
python -m unittest tests/test_user_reported_fixes.py     # Security hardening regression tests
`

---

## ☁️ AWS Cloud Production Deployment

Deploy the complete serverless architecture to AWS using AWS SAM (ws/template.yaml):

`ash
cd aws
sam build
sam deploy --guided
`

### AWS Cloud Resources Provisioned:
- **Amazon API Gateway**: REST API with CORS, rate-limiting, and validation.
- **AWS Lambda Microservices**:
  - AuthHandler: PBKDF2 authentication, token signing, and session revocation.
  - MLRiskEngine: Hybrid behavioral scoring and anomaly detection.
  - AlertDispatcher: SNS notification routing and CloudWatch alarms.
- **Amazon CloudWatch**: Log group (/aws/lambda/AccountHijackRiskEngine), custom metrics (BlockedHijacks, StepUpMFA, AllowSessions), and HighRiskRateAlarm.
- **Amazon SNS**: Out-of-band push topic and email subscription dispatcher.

---

## 📁 Repository Structure

`
aws-security-main/
├── README.md                          # Comprehensive system documentation
├── PRACTICE.md                        # Viva defense guide, demo scripts & Q&A
├── requirements.txt                   # Production Python dependencies
├── run_standalone.py                  # Universal zero-AWS standalone runner
├── docker-compose.yml                 # Containerized stack with MongoDB 7.0
├── aws/
│   ├── template.yaml                  # AWS SAM infrastructure as code
│   └── handlers/                      # Lambda serverless microservices
├── backend/
│   ├── app.py                         # FastAPI REST application & endpoints
│   ├── models.py                      # Scikit-Learn RF, Isolation Forest, Autoencoder
│   ├── security.py                    # PBKDF2 hashing, JWT signing, rate limiting
│   ├── sanitizer.py                   # XSS & NoSQL recursive sanitization
│   └── notification_service.py        # Tiered in-app & email notification router
├── database/
│   ├── db.py                          # Transparent local/MongoDB document store
│   └── schemas.py                     # User, session, event & telemetry schemas
├── frontend/
│   ├── index.html                     # Unified cyber defense dashboard
│   ├── css/style.css                  # Modern cyber-defense dark theme & glassmorphic UI
│   ├── js/
│   │   ├── app.js                     # Core state, auth routing & cookie consent
│   │   ├── user_portal.js             # User Portal, Primary Device & Session Kill Switch
│   │   ├── attack_simulator.js        # Red Team scenario launcher & attack builder
│   │   ├── soc_dashboard.js           # Blue Team gauge, SVG map & XAI breakdown
│   │   ├── cloudwatch_view.js         # CloudWatch SIEM telemetry & log purge controls
│   │   ├── cms_dashboard.js           # Super Admin CMS user governance & maintenance
│   │   ├── legal_views.js             # Privacy, cookies & compliance documents
│   │   ├── fingerprint.js             # Client device canvas & hardware telemetry
│   │   └── bg_animation.js            # Ambient cyber-grid background rendering
│   └── assets/                        # Audio siren & cyber defense media
└── tests/                             # 10 automated verification test suites
`

---

## 📄 License
This project is licensed under the **MIT License**.
