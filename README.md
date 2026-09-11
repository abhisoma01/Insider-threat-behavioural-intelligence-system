# Threat AI — Enterprise Insider Threat Behavioral Intelligence Platform

> **An Advanced Full-Stack Cybersecurity Intelligence System with Empirical Behavioral Profiling, Role-Based Access Control (RBAC), and Real-Time Telemetry Analytics.**

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%200.115+-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://reactjs.org)
[![SQLAlchemy](https://img.shields.io/badge/ORM-SQLAlchemy%202.0-D71F00.svg?style=flat)](https://www.sqlalchemy.org)
[![Tests](https://img.shields.io/badge/Tests-100%25%20PASS-success.svg?style=flat)]()
[![Security](https://img.shields.io/badge/RBAC-JWT%20Enforced-critical.svg?style=flat)]()

---

## 🛡️ System Overview

**Threat AI** is an enterprise-grade User and Entity Behavior Analytics (UEBA) platform designed to detect, analyze, and contain insider threats across enterprise environments. Rather than relying on rigid, hardcoded rules, the system extracts multidimensional activity telemetry, builds **empirical statistical baselines** ($\mu, \sigma$) per identity, and flags anomalous behavioral drift with explainable root-cause factors.

---

## 🏛️ High-Level Architecture

```
                               ┌─────────────────────────────────────────┐
                               │       React 18 Dashboard (Port 3000)    │
                               │  - Recharts Dynamic Visualizations      │
                               │  - Light/Dark High-Contrast Themes      │
                               │  - Real-time Notifications Drawer       │
                               │  - CISO Executive Report & CSV Export   │
                               └────────────────────┬────────────────────┘
                                                    │  JSON / Bearer Token
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │       FastAPI Backend API (Port 8000)   │
                               │  - Strict API-Level RBAC (HTTP 403)     │
                               │  - Automatic OpenAPI / Swagger Docs     │
                               │  - CSV Streaming Response Engine        │
                               └───────────┬─────────────────┬───────────┘
                                           │                 │
                  ┌────────────────────────┴─┐             ┌─┴─────────────────────────┐
                  ▼                          │             ▼                           ▼
  ┌──────────────────────────────┐           │  ┌───────────────────────┐  ┌───────────────────────┐
  │  Statistical Profiling Engine│           │  │  SQLAlchemy 2.0 ORM   │  │   Security Auditing   │
  │  - 9 Telemetry Features      │           │  │  - Employees          │  │   - Automated System  │
  │  - Gaussian Baselines (μ, σ) │           │  │  - Alerts             │  │     Notifications     │
  │  - Z-Score Anomaly Detection │           │  │  - Activity Logs      │  │   - Containment Logs  │
  │  - Habitual Clustered IPs/WS │           │  │  - Persistent Notifs  │  └───────────────────────┘
  └──────────────────────────────┘           │  └───────────┬───────────┘
                                             │              │
                                             └──────────────┼────────────┐
                                                            ▼            ▼
                                                   ┌───────────────────────────┐
                                                   │ SQLite Threat Intel DB    │
                                                   │ (threat_intel.db)         │
                                                   └───────────────────────────┘
```

---

## ✨ Key Enterprise Capabilities

### 1. Empirical Behavioral Profiling & Anomaly Engine (AI/ML)
* **Telemetry Feature Extraction:** Extracts 9 core behavioral indicators from telemetry logs:
  * `daily_action_count`, `off_hours_activity_ratio`, `failed_login_count`
  * `data_transfer_volume_mb`, `file_access_frequency`, `sensitive_resource_access_count`
  * `usb_device_events`, `distinct_ip_count`, `distinct_workstation_count`
* **Empirical Baselines:** Models habitual activity windows using Gaussian parametric distributions ($\mu, \sigma$).
* **Z-Score Deviation Evaluation:** Calculates feature deviations ($Z = \frac{x - \mu}{\sigma}$) to detect genuine anomalies and prevent false positives.
* **Explainability Vectors:** Every flagged incident provides plain-text, auditable explanations of why an action was anomalous.

### 2. Strict API-Level Role-Based Access Control (RBAC)
* All sensitive backend endpoints validate signed JWT role claims and return **`HTTP 403 Forbidden`** on unauthorized access:

| Endpoint | Operation | Authorized Roles | Unauthorized Response |
| :--- | :--- | :--- | :---: |
| `POST /api/v1/activity/ingest` | Ingest Telemetry Stream | `SOC Engineer`, `Administrator` | **403 Forbidden** |
| `POST /api/v1/employees/{id}/lock` | Isolate Endpoint Credentials | `Security Manager`, `Administrator` | **403 Forbidden** |
| `POST /api/v1/employees/{id}/reset-score` | Recalibrate Baseline Score | `Security Manager`, `Administrator` | **403 Forbidden** |
| `POST /api/v1/behavior/recalculate-baseline`| Workforce Model Retraining | `SOC Engineer`, `Administrator` | **403 Forbidden** |
| `PATCH /api/v1/alerts/{id}` | Alert Triage Lifecycle | `Analyst`, `Engineer`, `Manager`, `Admin`| **403 Forbidden** |

### 3. Real Database-Backed Security Notifications
* Notifications are persisted in a dedicated SQLite `notifications` table.
* Operations such as account containment (`POST /lock`) and alert triage automatically emit database audit alerts.
* Endpoints support listing unread alerts, individual read toggles, and bulk read marking.

### 4. Executive CISO Reporting & CSV Export
* **Executive CISO Dossier (`GET /api/v1/reports/executive`):** On-demand intelligence dossier detailing workforce composite posture, department vulnerability matrices, prioritized watchlist, and remediation directives.
* **Direct CSV Export (`GET /api/v1/reports/export/csv`):** Streams downloadable `.csv` audit trails for telemetry activity logs, workforce threat scores, or security alerts.

### 5. Dynamic Risk Trajectory & Threat Vector Analysis
* Eliminated static mock data; daily anomaly counts and mitigation trendlines (`7d`, `30d`, `90d`) are dynamically aggregated from database records based on calendar time intervals.

---

## 🚀 Quick Start Guide

### Prerequisites
* **Python 3.10+**
* **Node.js 16+** and **npm**

### Step 1: Backend Setup
```powershell
# In the project root directory
# Install Python dependencies
pip install fastapi uvicorn sqlalchemy pydantic python-jose passlib bcrypt

# Initialize and seed database with workforce and RBAC accounts
python backend/seed.py

# Start the FastAPI server
uvicorn backend.app.main:app --reload --port 8000
```
* **Backend API:** `http://localhost:8000`
* **Interactive Swagger UI:** `http://localhost:8000/docs`

### Step 2: Frontend Setup
Open a second terminal window:
```powershell
# In the project root directory
# Install React dependencies (first time only)
npm install

# Start the React development server
npm start
```
* The application will open automatically at: `http://localhost:3000`

---

## 🔑 Demo RBAC Test Credentials

All accounts are pre-seeded in the database with password: **`admin123`**

| Role | Email | Permissions |
| :--- | :--- | :--- |
| **System Administrator** | `admin@threat.ai` | Full unrestricted access across all platform capabilities |
| **Security Manager** | `manager@threat.ai` | Account containment (`/lock`, `/reset-score`), alert triage, reports |
| **SOC Lead Engineer** | `engineer@threat.ai` | Telemetry ingestion (`/ingest`), model retraining, alert triage |
| **Security Analyst** | `analyst@threat.ai` | Read-only dashboards, investigation dossiers, alert triage |

---

## 🧪 Verification & Automated Testing

### Run Backend Automated Test Suite
```powershell
python backend/test_api.py
```
> **Result:** **100% PASS** (Verifies health, multi-role JWT logins, 403 Forbidden RBAC checks, containment actions, notifications, CISO reports, CSV downloads, dynamic trajectory, and behavioral Z-score deviations).

### Run Frontend Automated Test Suite
```powershell
npm test -- --watchAll=false
```
> **Result:** **100% PASS** (`PASS src/App.test.js`).

### Run Production Build
```powershell
npm run build
```
> **Result:** **Compiled successfully** with zero errors.

---

## 📁 Repository Directory Structure

```
insider-dashboard/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── activity.py          # Telemetry log ingestion & real-time monitoring
│   │   │   ├── alerts.py            # Incident alerts triage lifecycle
│   │   │   ├── auth.py              # JWT authentication & require_roles RBAC factory
│   │   │   ├── behavior.py          # Behavioral profiling & baseline recalculation
│   │   │   ├── employees.py         # Monitored identity directory & containment actions
│   │   │   ├── notifications.py     # Database-backed notifications router
│   │   │   ├── reports.py           # CISO executive dossier & CSV streaming exports
│   │   │   └── risk.py              # Dynamic risk trajectory & threat vectors
│   │   ├── models/                  # SQLAlchemy 2.0 ORM database models
│   │   ├── schemas/                 # Pydantic v2 validation & response schemas
│   │   ├── services/
│   │   │   └── profiling_engine.py  # UEBA statistical feature extraction & Z-score engine
│   │   ├── utils/
│   │   │   └── security.py          # bcrypt password hashing & JWT token crypto
│   │   ├── config.py                # Environment configuration
│   │   ├── database.py              # Engine setup & DB session generator
│   │   └── main.py                  # FastAPI application entry point
│   ├── seed.py                      # Multi-role database seeder & 14-day telemetry generator
│   └── test_api.py                  # Full automated integration test suite
├── src/
│   ├── components/                  # Reusable UI widgets, badges, navigation drawers
│   ├── context/                     # ThemeContext (Dark/Light), AuthContext
│   ├── data/                        # Baseline datasets & offline resilience fallbacks
│   ├── pages/                       # Overview, Employees, Alerts, Risk Analysis, Analytics/Reports
│   ├── services/
│   │   └── api.js                   # Unified fetch API client with JWT bearer handling
│   ├── App.js                       # Primary root router and state synchronization
│   └── index.js                     # React DOM bootstrap
├── threat_intel.db                  # Local SQLite database
└── README.md
```

---

## 🎓 Academic Defense Notes
* **Deterministic Verification:** The test suites run 100% locally without cloud API keys or external LLM dependencies, ensuring deterministic, reproducible evaluation.
* **Resilient Offline Architecture:** The frontend features resilient optimistic state management with automatic offline fallback, ensuring the interface remains functional even if network latency occurs.
