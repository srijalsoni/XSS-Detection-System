# Automated Controlled Security Testing Documentation (Phase 8 Fix-Up)

## 1. Testing Architecture & Defensive Scope
Phase 8 establishes an automated, controlled, local-only security testing layer engineered to verify the defensive guarantees of the `P_211` XSS detection and prevention engine without destructive exploitation.

### Truthful Evidence & Telemetry Collection
Following the Phase 8 audit, the security runner does **not fabricate** observed security values:
- For every test request, the runner captures the correlation header `X-Request-ID`.
- The runner queries the application database (`security_events`) using `SecurityEventRepository.get_by_request_id(request_id)`.
- It records actual persisted values: `actual_risk`, `actual_action`, `actual_rule_ids`, `actual_ml_label`, `actual_ml_confidence`, and `actual_ml_model_version`.
- Pass/fail decisions strictly evaluate `status_passed`, `action_passed`, `risk_passed`, `rule_passed`, `headers_verified`, `reflection_safe`, and `correlation_id_verified`.

```
                    Security Test Runner
                             |
         +-------------------+-------------------+
         |                                       |
         v                                       v
[ Direct Test Mode ]                   [ Burp Proxy Mode ]
HTTP Request -> 127.0.0.1:5000         HTTP Request -> 127.0.0.1:8080 (Proxy)
         |                                       |
         +-------------------+-------------------+
                             |
                             v
                   Flask Defense Pipeline
                             |
                +------------+------------+
                |                         |
                v                         v
        Input Validation            Normalization
                |                         |
                +------------+------------+
                             |
                             v
                 Deterministic Rule Engine
                             |
                +------------+------------+
                |                         |
                v                         v
          Policy Engine          ML Classifier (Shadow)
                |                         |
                v                         v
         Response Action         Security Telemetry
       (ALLOW/REJECT/BLOCK)      (Zero Raw Payload)
                             |
                             v
              SQLite `security_events` Table
                             |
                             +-- Runner retrieves actual telemetry by X-Request-ID
```

---

## 2. Test Payload Corpus
The controlled corpus (`security_testing/payloads.py`) consists of 15 targeted test cases categorized into benign negative controls and suspicious exploit patterns.

### Benign Negative Controls (False-Positive Verification)
1. **`SEC-BENIGN-01` (Technical Discussion):** Technical prose discussing `alert()` functions. Evaluated as `MEDIUM` risk, handled via `SAFE_RENDER` with status `200 OK` in HTML text context.
2. **`SEC-BENIGN-02` (Mathematical Comparison):** `x < 10 and y > 20`. Correctly recognized as non-HTML; status `200 OK` (`ALLOW`).
3. **`SEC-BENIGN-03` (Profile Biography):** Normal career description discussing security topics; status `200 OK` (`ALLOW`).
4. **`SEC-BENIGN-04` (Safe Web URL):** Valid HTTPS URL (`https://example.com/docs/...`); status `200 OK` (`ALLOW`).
5. **`SEC-BENIGN-05` (Normal Comment):** Standard benign user text; status `200 OK` (`ALLOW`).

### Suspicious Exploit Patterns (Detection & Prevention Verification)
1. **`SEC-ATTACK-01` (Basic Script Tag):** `<script>alert(1)</script>` -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
2. **`SEC-ATTACK-02` (Image Event Handler):** `<img src=x onerror=alert(document.cookie)>` -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
3. **`SEC-ATTACK-03` (SVG Event Handler):** `<svg/onload=confirm(1)>` -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
4. **`SEC-ATTACK-04` (JavaScript Pseudo-Protocol):** `javascript:alert(window.origin)` on profile website -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
5. **`SEC-ATTACK-05` (Attribute Breakout):** `"><script>alert(1)</script>` on profile display_name -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
6. **`SEC-ATTACK-06` (Dangerous Tag - Iframe):** `<iframe src="javascript:alert(1)"></iframe>` -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
7. **`SEC-ATTACK-07` (Mixed-Case Obfuscation):** `<sCrIpT>prompt(1)</sCrIpT>` -> Normalized -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
8. **`SEC-ATTACK-08` (Whitespace Variation):** `<img   src=x\tonerror=alert(1)>` -> Normalized -> `CRITICAL` risk -> Blocked (`403 Forbidden`).
9. **`SEC-ATTACK-09` (Dangerous Scheme - VBScript):** `vbscript:msgbox(1)` on profile website -> Scheme validation rejection (`400 Bad Request`).
10. **`SEC-ATTACK-10` (Dangerous Scheme - Data URI):** `data:text/html,<script>alert(1)</script>` on profile website -> `CRITICAL` risk -> Blocked (`403 Forbidden`).

---

## 3. Defense-in-Depth Verification

### Security Headers Validation
Every response is verified for the presence and correctness of defensive headers:
- `Content-Security-Policy`: Restricts script execution and disallows framing.
- `X-Content-Type-Options`: `nosniff`.
- `X-Frame-Options`: `DENY`.
- `Referrer-Policy`: `strict-origin-when-cross-origin`.

### Output Encoding & Reflection Safety
- The runner inspects the HTTP response body to ensure raw executable attack strings are never reflected unescaped.
- Blocked pages (`blocked.html`) display only sanitized user guidance and correlation IDs.

### Telemetry Safety & Privacy
- Security event records stored in SQLite and queried by the dashboard contain only SHA-256 fingerprints, matched rule IDs, risk levels, and response actions.
- Raw payload text is strictly excluded from persistent telemetry and log files.

---

## 4. Execution Instructions
Run the automated security tests directly against the local application:
```powershell
.\.venv\Scripts\python.exe scripts/run_security_tests.py
```
