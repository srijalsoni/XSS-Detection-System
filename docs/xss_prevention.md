# P_211 XSS Prevention and Response Engine Documentation

## 1. Detection vs Prevention
In a resilient cybersecurity architecture, **Detection** and **Prevention** serve distinct, complementary purposes:
* **Detection (Phase 4):** Answers the question: *"Is this input suspicious or non-compliant?"* It parses, normalizes, inspects signatures, evaluates heuristics, assigns risk, and produces structured diagnostic telemetry without modifying user input or altering application execution.
* **Prevention (Phase 5):** Answers the question: *"What should the application do with this request?"* It evaluates the detection findings against configurable security policies, enforces context-aware output encoding, inspects URL schemes, sets defense-in-depth HTTP headers, and renders safe blocking responses for dangerous requests.

---

## 2. Prevention Architecture
The prevention subsystem is encapsulated in the `security/` module:
```
security/
├── __init__.py          # Security package public exports
├── models.py            # DetectionInput, DetectionResult, MatchedRule
├── normalization.py     # Safe canonicalization for detection
├── patterns.py          # Pre-compiled linear regex rule definitions
├── scoring.py           # Context-aware risk scoring & heuristic amplifier
├── detector.py          # Orchestrates normalization, patterns, scoring
├── policy.py            # Decides action (PolicyEngine, ResponseDecision, ResponseAction)
├── prevention.py        # URL validation, HTML attribute encoding helpers
├── headers.py           # Content-Security-Policy and HTTP security headers
└── response.py          # Pipeline orchestration (process_security_pipeline, render_blocked_response)
```

### End-to-End Prevention Pipeline
```
User / Browser Input
        │
        ▼
Flask Route Handler (/search, /comments, /profile)
        │
        ▼
process_security_pipeline()
        ├── DetectionInput(value, field, endpoint, context, request_id)
        ├── XSSDetector.analyze() -> DetectionResult
        ├── PolicyEngine.evaluate(DetectionResult) -> ResponseDecision
        └── SecurityEventRepository.create(..., action=decision.security_event_action)
        │
        ▼
Decision: should_continue?
        ├── NO  -> render_blocked_response(decision) [HTTP 400 or 403, templates/blocked.html]
        └── YES -> Continue normal validated route execution & auto-escaped Jinja2 rendering
```

---

## 3. Response Actions
The `PolicyEngine` assigns explicit actions depending on risk level and input context:
* **ALLOW:** Granted to clean, benign input (`risk_level == NONE`). Status `200 OK`. No security event recorded.
* **LOG_ONLY:** Applied to low-severity indicators (`risk_level == LOW`). Status `200 OK`. Event recorded as `LOGGED` while request proceeds.
* **SAFE_RENDER:** Applied to medium-risk indicators in standard content contexts (`html_text`). The text is accepted and safely rendered via Jinja2 auto-escaping. Event recorded as `SAFE_RENDERED`.
* **REJECT:** Applied to high-risk indicators (`risk_level == HIGH`) or medium-risk indicators situated in high-sensitivity contexts (e.g., `url` or `html_attribute`). Status `400 Bad Request`. Request execution halted.
* **BLOCK:** Applied to compound exploit patterns and critical findings (`risk_level == CRITICAL`). Status `403 Forbidden`. Request execution halted.

---

## 4. HTML Output Handling
* All user-controlled fields (`query`, `author`, `content`, `display_name`, `bio`, `website`) are rendered strictly using Jinja2 automatic context-sensitive HTML escaping.
* The dangerous filter `|safe` is strictly prohibited on all untrusted user data.
* Stored comments and profile biographies remain raw textual data in SQLite and are safely encoded at render time, preventing stored XSS execution.

---

## 5. URL Security
The Profile `website` field is validated using `validate_url()`:
* **Allowed Schemes:** `http`, `https`, or relative paths without pseudo-protocols.
* **Prohibited Schemes:** `javascript:`, `vbscript:`, `data:`, `file:`, `ftp:`.
* URLs containing embedded nulls, control characters, or unquoted dangerous schemes are immediately rejected before storage or reflection.

---

## 6. Security Headers
Attached to every HTTP response via application middleware:
* **Content-Security-Policy (CSP):** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';`
  * Strictly avoids `'unsafe-inline'` and `'unsafe-eval'`.
* **X-Content-Type-Options:** `nosniff` prevents MIME confusion attacks.
* **X-Frame-Options:** `DENY` prohibits clickjacking and frame embedding.
* **Referrer-Policy:** `strict-origin-when-cross-origin` protects sensitive URL paths.
* **X-XSS-Protection:** `1; mode=block` enables legacy browser filtering.

---

## 7. Event Lifecycle
```
REQUEST (with X-Request-ID)
      │
      ▼
DETECTION (Normalized analysis via XSSDetector)
      │
      ▼
DETECTION RESULT (Matched rules, risk level, confidence, input SHA-256 hash)
      │
      ▼
POLICY DECISION (Action: ALLOW, LOG_ONLY, SAFE_RENDER, REJECT, BLOCK)
      │
      ▼
SECURITY EVENT LOGGING (Stored in SQLite security_events with action and diagnostic metadata)
      │
      ▼
RESPONSE TO USER (HTTP 200, 400, or 403 without payload reflection or internal leakage)
```

---

## 8. Block / Reject Behavior
When a request is blocked (HTTP 403) or rejected (HTTP 400):
* The response renders `templates/blocked.html`.
* The page displays a professional advisory message explaining that the input contained prohibited executable constructs.
* **Information Leakage Prevention:** The page never reflects raw payload strings, internal regexes, rule IDs (`XSS-001`), database errors, or stack traces.

---

## 9. False-Positive Considerations
Legitimate educational and technical discussions (such as questions mentioning `"JavaScript"`, math inequalities like `5 < 10`, or programming comments) are analyzed safely. Because benign inputs trigger no rules, they receive `ALLOW` actions without false blocks.

---

## 10. Limitations
* Client-side JavaScript execution contexts with rich dynamic formatting (WYSIWYG HTML) are not supported or required in this architecture.
* Real-time automated blackholing or IP banning is out of scope for Phase 5 and deferred to infrastructure/network layers.
