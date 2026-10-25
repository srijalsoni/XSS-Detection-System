# P_211 Core XSS Detection Engine Documentation

## 1. What XSS Detection Means
Cross-Site Scripting (XSS) is a client-side code injection vulnerability occurring when malicious executable code (typically JavaScript or HTML event handlers) is accepted by a web application and rendered in a user's browser without appropriate neutralization.

In **Phase 4**, the P_211 project implements the **Core XSS Detection Engine**. The primary objective of detection is **telemetry, observation, and analysis**:
* To systematically parse untrusted user inputs received by application routes.
* To identify known malicious attack signatures, dangerous tags, inline event handlers, and execution schemes.
* To quantify threat severity into an explainable risk level.
* To log high-fidelity security events into persistent storage for real-time monitoring and future analytics.

> **CRITICAL BOUNDARY:** Detection is **NOT** Prevention. In Phase 4, detected attacks are classified and logged without blocking or sanitizing the request. This preserves the controlled testing baseline and allows independent evaluation before prevention is enabled in Phase 5.

---

## 2. Detector Architecture
The detection subsystem is fully encapsulated in the `security/` package, adhering to single-responsibility design:

```
security/
├── __init__.py          # Public security API exports
├── models.py            # DetectionInput, DetectionResult, MatchedRule dataclasses
├── normalization.py     # Safe text canonicalization & bounded decoding
├── patterns.py          # Pre-compiled linear regex rules & XSSRule registry
├── scoring.py           # Context-aware risk scoring & heuristic amplifier
└── detector.py          # Orchestration pipeline (XSSDetector, default_detector)
```

### End-to-End Request Pipeline
```
User / Browser Input
        │
        ▼
Flask Route Handler (/search, /comments, /profile)
        │
        ├── Basic Server-Side Validation (Presence & Length Limits)
        │
        ▼
XSSDetector.analyze(DetectionInput)
        │
        ├── Normalizer.normalize() (Max 4096 chars, multi-pass URL/HTML entity decode, null-strip)
        │
        ├── Pattern Registry Matching (Linear pre-compiled regex evaluation)
        │
        ├── Heuristic Risk Scoring (LOW / MEDIUM / HIGH / CRITICAL)
        │
        ▼
DetectionResult (Confidence, matched rule IDs, indicators, input SHA-256 hash)
        │
        ▼
SecurityEventRepository.create(...) (Logged to SQLite security_events table)
        │
        ▼
Safe Jinja2 Application Response (Execution continues without interruption)
```

---

## 3. Normalization Engine
Input canonicalization is essential to defeat evasion attempts such as URL encoding (`%3Cscript%3E`), double URL encoding (`%253Cscript%253E`), and HTML entity encoding (`&lt;script&gt;`).

* **Bounded Processing:** Inputs are clamped to 4,096 characters to prevent denial-of-service via oversized payloads.
* **Multi-Pass URL Decoding:** Evaluates up to two iterative passes of `urllib.parse.unquote`.
* **HTML Entity Decoding:** Uses standard library `html.unescape`.
* **Null Byte Stripping:** Eliminates embedded NULL bytes (`\x00`).
* **Non-Destructive:** Normalization is used **strictly for security analysis** and does not alter the original application data stored in the database or presented back to the user.

---

## 4. Detection Rules & Signature Registry
Each rule features a stable identifier, category, severity, and description:

| Rule ID | Rule Name | Category | Severity | Detection Purpose | Example Pattern |
|---|---|---|---|---|---|
| **XSS-001** | Explicit Script Tag | `SCRIPT_TAG` | HIGH | Identifies opening and closing `<script>` tags across case and whitespace variations | `<script>`, `</script>`, `<script /x>` |
| **XSS-002** | Inline Event Handler Attribute | `EVENT_HANDLER` | HIGH | Identifies inline DOM event handlers commonly attached to tags | `onload=`, `onerror=`, `onclick=` |
| **XSS-003** | Executable URI Scheme | `PSEUDO_PROTOCOL` | HIGH | Identifies JavaScript, VBScript, and HTML data URIs | `javascript:`, `vbscript:`, `data:text/html` |
| **XSS-004** | Dangerous HTML/SVG Elements | `DANGEROUS_TAG` | MEDIUM | Detects elements frequently abused for code injection | `<svg>`, `<iframe>`, `<object>`, `<embed>` |
| **XSS-005** | Attribute Delimiter Breakout | `ATTRIBUTE_INJECTION` | MEDIUM | Identifies quote-bracket transitions that escape attributes into HTML tags | `"><tag`, `'><tag` |
| **XSS-006** | JavaScript Execution Sink Call | `JS_SINK` | MEDIUM | Identifies invocations of dangerous browser sinks | `alert(`, `eval(`, `prompt(`, `document.cookie` |

---

## 5. Heuristics & Risk Scoring
The `Scorer` class evaluates matched rules along with input context to compute risk levels:

* **NONE (0.0):** No indicators matched.
* **LOW (0.35):** Weak or isolated indicator (e.g. single generic pattern).
* **MEDIUM (0.55):** Single moderate indicator (e.g. `<svg>` tag or standalone sink call).
* **HIGH (0.80 - 0.90):** Strong indicator such as an explicit `<script>` element or inline event handler attribute.
* **CRITICAL (0.95 - 0.99):** Compound attack patterns demonstrating structural exploitability:
  * Tag Breakout + Event Handler (e.g. `"><img src=x onerror=...`)
  * Dangerous Tag + Inline Handler (e.g. `<svg onload=...`)
  * Event Handler + Execution Sink (e.g. `onerror=alert(document.cookie)`)
  * Script Tag + Execution Sink (e.g. `<script>eval(...)`)

---

## 6. Security Event Integration
When `result.detected` is True, `inspect_and_log_security_event` records telemetry into the SQLite `security_events` table via `SecurityEventRepository.create`:
* `event_type`: "XSS"
* `endpoint`: Target endpoint (e.g. `/search`, `/comments`, `/profile`)
* `method`: HTTP method (POST, GET)
* `risk_level`: Computed risk level (LOW, MEDIUM, HIGH, CRITICAL)
* `action`: "LOGGED" (Observation mode)
* `rule_id`: Comma-separated rule IDs (e.g. `XSS-001,XSS-006`)
* `input_hash`: Cryptographic SHA-256 digest of untrusted input
* `request_id`: Correlated request UUID (`X-Request-ID`)
* `details_json`: Structured context, confidence score, explanation, and matched indicator summaries

> **Privacy & Security Guarantee:** The raw malicious payload is **never** logged in plaintext in security event records or log files. A standard SHA-256 hash is computed for forensic deduplication without credential leakage.

---

## 7. False-Positive Awareness & Safe Inputs
The engine was specifically tested against benign strings containing punctuation and technical terms:
* Comparison operators (e.g. `Price: $100 < $200 & rating > 4`) are accepted.
* Academic/discussion references (e.g. `HTML syntax and JavaScript event handler`) are accepted.
* Normal web URLs (e.g. `https://example.com/docs?id=1`) are accepted.

---

## 8. Current Limitations
* **Pure Detection:** Malicious requests are detected and logged, but not blocked or sanitized.
* **Static Heuristics:** Analysis is rule-based and signature-driven; machine learning models are scheduled for future phases.
* **Scope Boundary:** Limited strictly to XSS detection; SQL injection, CSRF, and SSRF detection are outside the engine's scope.
