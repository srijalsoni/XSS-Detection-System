# Burp Suite Integration & Proxy Testing Guide (Phase 8 Fix-Up)

## 1. Overview
The `P_211` project integrates with **Burp Suite Community Edition** using a local-only proxy architecture. This allows security practitioners and evaluators to inspect intercepted HTTP requests, observe defensive responses in Burp Repeater, and route automated regression payloads through the Burp proxy listener.

### Scope & Verification Status
- **Target:** Strictly `http://127.0.0.1:5000` (Local Flask application).
- **Proxy Listener:** Strictly `http://127.0.0.1:8080` (Burp Suite local proxy).
- **Status:** **NOT VERIFIED — BURP LISTENER NOT ACTIVE**.
  - While the codebase implements proxy routing (`scripts/run_burp_tests.py`), connection handling, and 15 RFC 7230 `.req` request files for Burp Repeater, Burp Suite was not actively running during this automated run.
  - In compliance with defensive evaluation standards, this status is truthfully reported as *NOT VERIFIED (Listener Inactive)* rather than claiming false success.

---

## 2. Burp Suite Configuration (Manual Setup Steps)

To route and inspect traffic using Burp Suite Community Edition:

1. **Launch Burp Suite Community Edition** on your local machine.
2. Select **Temporary Project** and click **Start Burp**.
3. Navigate to **Proxy -> Proxy settings**:
   - Ensure the Proxy Listener is set to interface `127.0.0.1:8080` and state is `Running`.
4. Navigate to **Proxy -> Intercept**:
   - Toggle **Intercept is off** if you want automated test scripts to execute without manual step-by-step approvals.
   - Toggle **Intercept is on** if you wish to manually inspect individual HTTP requests before they reach Flask.

---

## 3. Replaying Pre-Generated Requests in Burp Repeater

Pre-generated, RFC 7230-compliant raw HTTP request files are located in:
`security_testing/burp_requests/`

### How to Replay:
1. Open any `.req` file (e.g., `SEC-ATTACK-01_search.req` or `SEC-BENIGN-01_search.req`) in a text editor.
2. Copy the entire raw HTTP request.
3. In Burp Suite, open the **Repeater** tab.
4. Paste the raw request into the Repeater request panel.
5. Set Target to:
   - Host: `127.0.0.1`
   - Port: `5000`
   - Protocol: `HTTP`
6. Click **Send** and observe:
   - For malicious inputs: HTTP `403 Forbidden` or `400 Bad Request` with sanitized block HTML and security headers.
   - For benign inputs: HTTP `200 OK` with safe rendering.

---

## 4. Running Automated Tests via Burp Proxy

When Burp Suite is running with its proxy listener on `127.0.0.1:8080`, execute:

```powershell
.\.venv\Scripts\python.exe scripts/run_burp_tests.py
```

### Expected Behavior:
- The script probes `127.0.0.1:8080`.
- If Burp is running, it transmits all 15 controlled test payloads through the proxy.
- All requests and responses will be visible in Burp Suite under **Proxy -> HTTP history**.
- If Burp is offline, the script outputs a clear diagnostic message and exits gracefully without reporting false success.
