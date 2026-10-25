# Threat Model Document
## P_211 Defensive Web Application — Cross-Site Scripting (XSS) Detection & Prevention

### 1. Overview & Scope
This document outlines the threat landscape, security boundaries, attacker assumptions, and defensive controls implemented within the **P_211 Defensive Web Application**.

The application is engineered strictly as an academic/enterprise demonstration system designed to detect, mitigate, and monitor Cross-Site Scripting (XSS) attacks locally (`127.0.0.1`) across user input surfaces.

---

### 2. Assets & Trust Boundaries

#### Protected Assets
1. **Application Presentation Layer:** HTML rendered to users in browsers.
2. **Persistent Data Store (SQLite):** User profiles and discussion comments.
3. **Security Telemetry Store:** Audit records, detection logs, and risk metrics.
4. **Session / Browser Context:** Client-side document cookies and DOM execution environments.

#### Trust Boundaries
- **Untrusted Input Boundary:** Any incoming HTTP parameter (URL queries, form inputs, headers).
- **Application Logic Boundary:** Python Flask routing, normalization, and validation handlers.
- **Security Engine Boundary:** Deterministic rule engine (`XSS-001` through `XSS-006`) and policy decision layer.
- **Persistence Boundary:** Parameterized SQLite database access.

---

### 3. Identified Threat Vectors & Attack Scenarios

| Threat ID | Threat Category | Attack Vector / Description | Impact |
| :--- | :--- | :--- | :--- |
| **T-01** | Reflected XSS | Malicious payload submitted via `/search` (GET/POST) reflected back in HTML response. | Client execution of unauthorized JavaScript. |
| **T-02** | Stored XSS | Persistent attack payload stored via `/comments` and rendered to subsequent visitors. | Long-term account compromise and DOM manipulation. |
| **T-03** | Attribute Breakout | Payload breaking out of input attributes on `/profile` via quote injection (`"><script>`). | Hijacking HTML document context. |
| **T-04** | Executable URI Schemes | Links containing `javascript:`, `vbscript:`, or `data:text/html` in profile website URL. | Arbitrary script execution upon user interaction. |
| **T-05** | Obfuscated Exploit Payloads | Obfuscated mixed-case (`<sCrIpT>`), whitespace manipulation, or HTML entities. | Evasion of naive keyword filters. |
| **T-06** | Telemetry / Privacy Leakage | Raw exploit payloads stored in logs, API responses, or exposed to analysts. | Secondary injection vulnerabilities in monitoring tooling. |
| **T-07** | ML Model Deserialization | Arbitrary code execution via untrusted Python pickle model files. | Remote code execution on the application server. |

---

### 4. Defensive Controls & Mitigations

```
Untrusted Input
      |
      v
[ Strict Length & Boundary Validation ] -> Disallowed URI schemes / oversized queries rejected
      |
      v
[ Input Normalization ] -> Strip null bytes, unescape entities, standardize whitespace & case
      |
      v
[ Deterministic Rule Engine ] -> XSS-001..006 signature & sink heuristics (AUTHORITATIVE)
      |
      +-----------------------------+
      |                             |
      v                             v
[ Policy Engine ]             [ ML Classifier ]
(ALLOW/REJECT/BLOCK)          (Shadow / Advisory Mode)
      |                             |
      v                             v
[ Sanitized Output & Headers ] [ Safe Telemetry Store ]
- Jinja2 Auto-Escaping         - SHA-256 Fingerprints
- Content-Security-Policy      - Request Correlation IDs
- X-Frame-Options: DENY        - Zero Raw Payloads Stored
- X-Content-Type-Options
```

#### Detailed Safeguards
1. **Authoritative Deterministic Engine:** High or Critical severity findings cannot be downgraded or overturned by the ML advisory layer.
2. **Context-Aware Mitigation:** HTML text contexts safely auto-escape technical prose (`SAFE_RENDER`), while dangerous contexts (URL links, attributes) strictly reject (`REJECT` 400 or `BLOCK` 403).
3. **Safe Serialization:** Machine learning artifacts use standard JSON format rather than Python `pickle`, eliminating unsafe deserialization risks.
4. **Defense-in-Depth HTTP Headers:** Restricts script execution to `'self'`, forbids iframe framing (`DENY`), and blocks MIME-type sniffing (`nosniff`).
5. **Zero Raw Payload Logging:** Security telemetry stores SHA-256 hashes and matched rule IDs rather than raw attack payloads.

---

### 5. Out of Scope (What This System Does NOT Attempt to Solve)
- External network scanning, web application firewalls (WAF), or distributed DDoS mitigation.
- Complex third-party browser extensions or DOM-based vulnerabilities originating in external CDN libraries.
- Server-side template injection (SSTI) or operating system command execution vulnerabilities.
