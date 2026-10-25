# Final Project Engineering & Security Report
## P_211 — Defensive Web Application for Cross-Site Scripting (XSS) Detection, Prevention and Security Monitoring

### 1. Project Title & Overview
**Project Title:** HCL P_211 — Cross-Site Scripting (XSS) Attack Detection, Prevention, Response, and Security Monitoring
**Canonical Repository:** `C:\Users\Srijal Soni\Documents\CyberProjects\xss-detection-system`
**Operating System:** Windows, Python 3.11.9, Virtual Environment at `.\.venv`

---

### 2. Problem Statement & Objective
Cross-Site Scripting (XSS) remains one of the most prevalent web application security risks. Traditional applications often rely solely on rudimentary blacklist filters or fail to monitor security telemetry effectively.

The objective of this project was to design, implement, and rigorously validate a defense-in-depth web application that:
1. Normalizes and validates all untrusted inputs across diverse application contexts (HTML text, attributes, URLs).
2. Intercepts exploit patterns using a deterministic rule engine (`XSS-001` through `XSS-006`).
3. Enforces context-aware mitigation actions (`ALLOW`, `LOG_ONLY`, `SAFE_RENDER`, `REJECT` 400, `BLOCK` 403).
4. Logs sanitized threat telemetry into SQLite with zero raw payload disclosure.
5. Visualizes real-time security events on an administrative monitoring dashboard.
6. Enriches event telemetry with a secondary, pure-Python Machine Learning classifier operating in shadow mode.
7. Automates controlled, local-only defensive security testing with Burp Suite proxy integration support.

---

### 3. Complete Architectural Workflow

```
                        User Input
                            |
                            v
               [ Server-Side Validation ]
         (Presence checks, length limits, URI schemes)
                            |
                            v
                 [ Input Normalization ]
         (Null bytes, HTML entities, whitespace, casing)
                            |
            +---------------+---------------+
            |                               |
            v                               v
[ Deterministic Rule Engine ]     [ Secondary ML Classifier ]
    - XSS-001 (Script Tags)           - Char (3-5) TF-IDF
    - XSS-002 (Event Handlers)        - Pure Logistic Regression
    - XSS-003 (URI Schemes)           - Safe JSON Serialization
    - XSS-004 (Dangerous Tags)        - Advisory / Shadow Mode
    - XSS-005 (Breakouts)                   |
    - XSS-006 (JS Sinks)                    |
            |                               |
  (AUTHORITATIVE RESULT)                    v
            |                         ML Probability
            +---------------+---------------+
                            |
                            v
                  [ Policy Engine ]
            - ALLOW        (Status 200)
            - SAFE_RENDER  (Status 200, Auto-Escaped)
            - LOG_ONLY     (Status 200, Logged)
            - REJECT       (Status 400 Bad Request)
            - BLOCK        (Status 403 Forbidden)
                            |
            +---------------+---------------+
            |                               |
            v                               v
[ HTTP Response Handlers ]       [ Telemetry Persistence ]
- Jinja2 Auto-Escaping           - SQLite security_events
- Strict CSP Headers             - SHA-256 Fingerprints
- X-Frame-Options: DENY          - Request Correlation IDs
- X-Content-Type-Options         - Zero Raw Payload Storage
- Sanitized blocked.html                    |
                                            v
                               [ Security Dashboard ]
                               - Real-time Chart.js Analytics
                               - Threat distribution & timeline
```

---

### 4. Technology Stack
- **Backend Framework:** Python 3.11.9, Flask 3.1.3 (Application Factory, Blueprints, Request Hooks)
- **Database Engine:** SQLite 3.45.1 (Standard Library `sqlite3`, parameterized queries, transactions)
- **Machine Learning Layer:** Pure-Python Char (3–5) n-gram TF-IDF vectorizer + L2-regularized Logistic Regression (Zero external binary wheels, safe JSON serialization)
- **Visualization Engine:** Chart.js v4.4.1 (Locally hosted vendor bundle under `static/js/vendor/`, strict CSP compliant)
- **Automated Testing:** Pytest 9.1.1 (112 automated test cases)
- **Security Testing:** Custom local test runner (`security_testing/`) with real telemetry queries & Burp proxy integration support

---

### 5. Summary of Engineering Phases (Phases 0–9)
- **Phase 0:** Python 3.11 environment setup, `.venv`, Git repository initialization.
- **Phase 1:** Application factory, blueprints (`main_bp`, `feature_bp`, `dashboard_bp`), sanitized error handlers.
- **Phase 2:** Feature routes (`/search`, `/comments`, `/profile`) with server-side validation.
- **Phase 3:** SQLite database schema (`comments`, `profile`, `security_events`, `application_events`).
- **Phase 4:** Deterministic XSS detector (`security/detector.py`), normalization, scoring, rules `XSS-001..006`.
- **Phase 5:** Response policy engine (`security/policy.py`), URL scheme validator, HTTP security headers.
- **Phase 6:** Administrative Security Dashboard (`/dashboard`), REST telemetry APIs, locally-hosted Chart.js.
- **Phase 7:** Secondary ML classifier layer (`ml/`), reproducible 112-sample dataset, shadow-mode telemetry.
- **Phase 8:** Automated local security testing runner, 15 controlled test vectors, real SQLite telemetry collection, Burp Repeater request templates.
- **Phase 9:** Startup packaging (`run.bat`, `run.ps1`, `scripts/check_health.py`), threat modeling, final validation report, project closure.

---

### 6. Quantitative Verification Results
- **Automated Test Suite:** **112 / 112 Tests Passed** (100% pass rate in ~10.55s).
- **Controlled Security Suite:** **15 / 15 Vectors Passed** with genuine runtime database telemetry verified.
- **Security Headers:** Enforced and verified on all responses (CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Request-ID`).
- **ML Shadow Telemetry:** Evaluated and confirmed in shadow mode; deterministic rule engine retains absolute precedence.
- **Burp Suite Status:** Proxy runner and 15 RFC 7230 request templates verified; truthfully reported as **NOT VERIFIED (Listener Inactive)** when proxy port 8080 is offline.

---

### 7. Documented Limitations & Scope
- **Localhost Target Boundary:** Operates strictly on `127.0.0.1` for defensive demonstration and verification.
- **Curated Dataset & Test Corpus:** Contains 112 ML training samples and 15 controlled test vectors; not intended as a universal commercial WAF.
- **Advisory ML Role:** The ML layer functions strictly as secondary telemetry and cannot override deterministic decisions.

---

### 8. Final Project Status
**ALL PHASES 0 THROUGH 9 COMPLETE (PASS).**
