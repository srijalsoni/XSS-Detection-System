#  Defensive Web Application for XSS Attack Detection, Prevention and Security Monitoring

## Project Status
**Phase 9 Complete — Final Hardening, Packaging & Comprehensive Defense Documentation**

All phases (Phases 0 through 9) have been implemented, tested, and verified.

## Overview
A defensive cybersecurity web application engineered to detect, mitigate, and monitor Cross-Site Scripting (XSS) attack vectors in web environments while providing actionable telemetry.

The system combines:
1. **Server-Side Input Validation & Normalization:** Strips null bytes, decodes entities, and bounds input sizes.
2. **Deterministic XSS Detection Engine:** Authoritative signature and execution sink heuristics (`XSS-001` through `XSS-006`).
3. **Response Policy Engine:** Enforces context-aware responses (`ALLOW`, `LOG_ONLY`, `SAFE_RENDER`, `REJECT` 400, `BLOCK` 403).
4. **Security Telemetry Store:** SQLite persistence with SHA-256 fingerprints, correlation IDs, and zero raw payload logging.
5. **Real-Time Monitoring Dashboard:** Visual analytics using locally-hosted Chart.js under strict Content Security Policy.
6. **Secondary ML Classifier Layer:** Pure-Python Char (3–5) n-gram TF-IDF and Logistic Regression operating in shadow mode with safe JSON serialization.
7. **Automated Security Testing & Burp Integration:** Automated local security runner verifying real runtime telemetry, alongside Burp Suite proxy routing and Repeater request templates.

---

## Technology Stack
* **Language:** Python 3.11.9
* **Framework:** Flask 3.1.3 (Application Factory, Blueprints, Request Hooks)
* **Security Subsystem:** Custom Modular XSS Detection & Prevention Engine (`security/`)
* **Machine Learning Subsystem:** Char n-gram TF-IDF & Logistic Regression (`ml/`, safe JSON model artifacts, shadow mode)
* **Security Testing Subsystem:** Automated local runner with real telemetry collection & Burp proxy integration (`security_testing/`, `scripts/`)
* **Visualization Engine:** Chart.js v4.4.1 (Locally hosted vendor bundle under `static/js/vendor/`, strict CSP compliant)
* **Database Engine:** SQLite 3.45.1 (Standard Library `sqlite3`)
* **Testing:** Pytest 9.1.1 (112 automated test cases)
* **Version Control:** Git 2.51.0

---

## Quick Startup Guide

### 1. Requirements & Setup
- Windows OS with Python 3.11 installed.
- Ensure the local virtual environment `.venv` is configured:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\pip install -r requirements.txt
  ```

### 2. Launch the Application
- **Using Windows Command Prompt / Batch:**
  ```cmd
  run.bat
  ```
- **Using PowerShell:**
  ```powershell
  .\run.ps1
  ```
The application will start locally on: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 3. Verify System Health
In a separate terminal, run:
```powershell
.\.venv\Scripts\python.exe scripts/check_health.py
```

---

## Available Application Features
| URL | Description |
| :--- | :--- |
| `http://127.0.0.1:5000/` | Home Page with architecture and protection status |
| `http://127.0.0.1:5000/search` | Search feature testing reflected XSS defenses and technical prose |
| `http://127.0.0.1:5000/comments` | Discussion board testing stored XSS prevention and safe auto-escaping |
| `http://127.0.0.1:5000/profile` | User profile testing attribute breakouts and URL scheme validation |
| `http://127.0.0.1:5000/dashboard` | Administrative Security Monitoring Dashboard |
| `http://127.0.0.1:5000/health` | System health and service metadata JSON endpoint |

---

## Testing & Verification

### 1. Run Full Pytest Regression Suite
Executes all 112 automated tests across core, database, detection, policy, ML, headers, and security validation:
```powershell
.\.venv\Scripts\pytest.exe -v
```

### 2. Run Automated Local Security Tests
Executes 15 controlled defensive test cases directly against the local application and verifies real SQLite telemetry:
```powershell
.\.venv\Scripts\python.exe scripts/run_security_tests.py
```

### 3. Burp Suite Proxy Testing (Optional)
Start Burp Suite Community edition with proxy listener on `127.0.0.1:8080`, then run:
```powershell
.\.venv\Scripts\python.exe scripts/run_burp_tests.py
```
*(Pre-generated raw HTTP request templates for Burp Repeater are located in `security_testing/burp_requests/`)*

---

## Documentation Index
- `docs/final_project_report.md` — Consolidated final engineering and security report.
- `docs/threat_model.md` — System threat model, trust boundaries, attack vectors, and mitigations.
- `docs/demo_guide.md` — Step-by-step 5–10 minute demonstration walkthrough.
- `docs/final_validation_report.md` — Detailed test execution and control verification metrics.
- `docs/architecture.md` — Comprehensive architectural flow diagrams.
- `docs/security_testing.md` — Security testing methodology and controlled payload corpus.
- `docs/burp_testing.md` — Burp Suite proxy routing and Repeater guide.
- `docs/ml_classifier.md` — Secondary ML classifier architecture and feature design.
- `docs/ml_evaluation_report.md` — Machine learning evaluation metrics on held-out test split.

---

## Scope & Limitations
- **Localhost Boundary:** Operates strictly on `127.0.0.1` for defensive demonstration and verification. No external scanning or exploitation is performed.
- **Curated Corpus:** The ML dataset (112 samples) and security test corpus (15 vectors) are designed for controlled verification rather than unbounded fuzzing.
- **Deterministic Precedence:** The machine learning classifier operates in shadow mode and cannot override or downgrade deterministic rule detections.
