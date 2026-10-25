# Interactive Demonstration Guide (5–10 Minutes)
## P_211 Defensive Web Application — Cross-Site Scripting (XSS) Detection & Monitoring

### Demonstration Objective
This walkthrough demonstrates the real-time detection, prevention, telemetry logging, and secondary machine-learning capabilities of the **P_211 XSS Detection System** in a local test environment.

---

### Prerequisites & Startup (1 Minute)
1. Open PowerShell or Command Prompt in the canonical repository:
   `C:\Users\Srijal Soni\Documents\CyberProjects\xss-detection-system`
2. Start the application:
   ```cmd
   run.bat
   ```
   *(Or using PowerShell: `.\run.ps1`)*
3. Verify startup in a second terminal:
   ```powershell
   .\.venv\Scripts\python.exe scripts/check_health.py
   ```
   *Expected:* All endpoints respond `HTTP 200 OK`, database is connected, and security headers are verified.

---

### Step 1: Benign User Submission & False-Positive Resilience (2 Minutes)
1. In your web browser, navigate to: [http://127.0.0.1:5000/search](http://127.0.0.1:5000/search)
2. In the Search query field, submit:
   ```
   JavaScript alert() function usage in cybersecurity tutorials
   ```
3. **Observe Defensive Behavior:**
   - The query matches JavaScript sink pattern `XSS-006` as `MEDIUM` risk.
   - Because the context is HTML prose, the Policy Engine applies `SAFE_RENDER` (`200 OK`).
   - The input is safely rendered via Jinja2 auto-escaping without breaking usability.
4. Try a mathematical comparison:
   ```
   Algorithm check: x < 10 and y > 20
   ```
   - **Observe:** The parser distinguishes math comparison brackets from HTML tags (`NONE` risk -> `ALLOW`).

---

### Step 2: Reflected & Stored Attack Prevention (3 Minutes)
1. In the **Search** feature (`/search`), submit an explicit exploit payload:
   ```html
   <script>alert(1)</script>
   ```
   - **Observe:** Blocked immediately with HTTP `403 Forbidden` and a sanitized block page (`blocked.html`).
   - The raw payload is **not** reflected in the response page.
2. Navigate to **Comments** ([http://127.0.0.1:5000/comments](http://127.0.0.1:5000/comments)):
   - Submit Author: `Attacker`
   - Submit Content:
     ```html
     <img src=x onerror=alert(document.cookie)>
     ```
   - **Observe:** The compound inline event-handler pattern is blocked (`403 Forbidden`).
   - The payload is **not saved** to the database, preventing Stored XSS.
3. Navigate to **Profile** ([http://127.0.0.1:5000/profile](http://127.0.0.1:5000/profile)):
   - In the Website URL field, enter:
     ```
     javascript:alert(window.origin)
     ```
   - **Observe:** The executable URI scheme is intercepted and blocked (`403 Forbidden`).

---

### Step 3: Security Telemetry & Monitoring Dashboard (2 Minutes)
1. Open the **Security Dashboard** at: [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard)
2. **Review Real-Time Analytics:**
   - **Threat Summary Cards:** Displays updated Total Events, Critical Count, and Blocked Count.
   - **Risk Distribution Chart:** Shows proportional distribution of `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` events.
   - **Detection Rule Frequency:** Shows frequency of triggers across `XSS-001` (Script Tags), `XSS-002` (Event Handlers), `XSS-003` (Executable Schemes), etc.
   - **Recent Incident Log Table:** Inspect the latest event rows.
3. **Verify Privacy & Telemetry Integrity:**
   - Note that the incident table displays event timestamps, risk levels, response actions, and request IDs.
   - **Zero Raw Payloads:** Malicious payload strings are never exposed in dashboard API responses or database tables.

---

### Step 4: Machine Learning Advisory Telemetry (1 Minute)
1. In the incident logs, note the secondary ML advisory classification attached to each event:
   - Evaluated using pure-Python Character n-gram TF-IDF and Logistic Regression.
   - Operates in **shadow mode** (`ML_ENFORCEMENT_MODE = "shadow"`).
   - Re-emphasize: If ML predicts `BENIGN` for an obfuscated input while deterministic rules flag `HIGH`/`CRITICAL`, the deterministic rule engine maintains absolute veto power and blocks the attack.

---

### Step 5: Automated Security Regression Test Run (1 Minute)
1. In your terminal, run the automated security testing suite:
   ```powershell
   .\.venv\Scripts\python.exe scripts/run_security_tests.py
   ```
2. **Observe Terminal Output:**
   - 15 controlled test vectors executed against local endpoints.
   - Real telemetry fetched from SQLite via `X-Request-ID`.
   - 15 / 15 Passed (100.0% pass rate).
