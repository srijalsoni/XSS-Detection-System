# P_211 Security Monitoring Dashboard & Telemetry Analytics

## 1. Dashboard Purpose
The **Security Monitoring Dashboard** (Phase 6) provides local, real-time observability and defensive visual analytics for the P_211 web application. It transforms raw security events persisted in the SQLite `security_events` table into actionable telemetry, allowing administrators and developers to inspect:
* Total threat event volume and temporal velocity.
* Risk level distributions (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* Defensive mitigation actions executed (`LOGGED`, `SAFE_RENDERED`, `REJECTED`, `BLOCKED`).
* Trigger frequencies for detection rules (`XSS-001` through `XSS-006`).
* Targeted application attack surfaces (`/search`, `/comments`, `/profile`).
* Recent security incidents with detailed diagnostic reasoning.

---

## 2. Dashboard Architecture
```
Browser Client (Local Admin / Security Analyst)
        │
        ├── GET /dashboard (templates/dashboard.html)
        │         ├── static/css/dashboard.css
        │         ├── static/js/vendor/chart.umd.js (Local Chart.js v4.4.1)
        │         └── static/js/dashboard.js
        │
        └── RESTful Telemetry API (routes/dashboard_routes.py)
                  │
                  ├── GET /api/security/summary
                  ├── GET /api/security/risk-distribution
                  ├── GET /api/security/actions
                  ├── GET /api/security/rules
                  ├── GET /api/security/endpoints
                  ├── GET /api/security/timeline
                  └── GET /api/security/recent
                  │
                  ▼
          DashboardRepository (database/dashboard_repository.py)
                  │ (Parameterized SQL: COUNT, GROUP BY, WHERE, ORDER BY)
                  ▼
          SQLite Database (database/app.db: security_events)
```

---

## 3. Telemetry API Endpoints
All API endpoints accept an optional `time_range` query parameter (`24h`, `7d`, `30d`, `all`).

| Endpoint | Method | Output Schema / Purpose |
|---|---|---|
| `/api/security/summary` | GET | Returns `total_events`, `high_risk_events`, `critical_events`, `blocked_events`, `rejected_events`, `safe_rendered_events`, `logged_events`. |
| `/api/security/risk-distribution` | GET | Returns `labels` (`["LOW", "MEDIUM", "HIGH", "CRITICAL"]`) and corresponding `counts`. |
| `/api/security/actions` | GET | Returns `labels` (`["LOGGED", "SAFE_RENDERED", "REJECTED", "BLOCKED"]`) and corresponding `counts`. |
| `/api/security/rules` | GET | Returns `rule_ids`, formatted descriptive `labels`, and trigger `counts` across compound detections. |
| `/api/security/endpoints` | GET | Returns targeted endpoints (`/search`, `/comments`, `/profile`) and event counts. |
| `/api/security/timeline` | GET | Returns ISO time buckets and event counts over time for line chart rendering. |
| `/api/security/recent` | GET | Returns list of recent safe telemetry dictionaries (limits up to 100). |

---

## 4. Database Aggregation & Query Design
* **Server-Side SQL Grouping:** All aggregations utilize native SQLite `COUNT(*)`, `SUM(CASE ...)`, and `GROUP BY` operations. The application never loads large raw datasets into Python memory for processing.
* **SQL Injection Safety:** Time cutoff boundaries are computed server-side in Python as ISO-8601 strings and passed via parameterized SQL placeholders (`?`).
* **Indexes Utilized:** Queries leverage existing schema indexes:
  * `idx_sec_events_created_at`
  * `idx_sec_events_risk`
  * `idx_sec_events_type`

---

## 5. Chart.js Integration & Strict CSP Compliance
* **Local Vendor Hosting:** The Chart.js bundle (`chart.umd.js` v4.4.1) is hosted locally under `static/js/vendor/`.
* **Zero Remote CDN Calls:** No external CDNs are referenced at runtime, maintaining full compliance with the application's strict Content Security Policy (`script-src 'self'`).
* **Visualizations Rendered:**
  * **Line Chart:** Threat Activity Over Time (`chart-timeline`).
  * **Doughnut Chart:** Risk Level Distribution (`chart-risk`).
  * **Bar Chart:** Response Actions Executed (`chart-actions`).
  * **Horizontal Bar Chart:** Rule Trigger Frequencies (`chart-rules`).
  * **Doughnut Chart:** Targeted Endpoints (`chart-endpoints`).

---

## 6. Security Controls & Data Privacy
1. **Zero Raw Payload Exposure:** In accordance with defensive security best practices, the dashboard and APIs never return, store, or display original malicious input strings. Only rule IDs, event types, risk levels, timestamps, request IDs, and safe diagnostic explanations are exposed.
2. **Safe DOM Manipulation:** `static/js/dashboard.js` strictly utilizes safe DOM APIs (`document.createElement`, `textContent`, `appendChild`). The dangerous property `innerHTML` is completely avoided.
3. **No Dynamic Execution:** No `eval()`, `Function()`, or inline event listeners exist in the dashboard templates or scripts.
4. **Sanitized Error Handling:** Database exceptions or API failures return standardized JSON error messages (`{"error": "..."}`) without exposing stack traces, paths, or connection internals.

---

## 7. Time Filtering Workflow
* Users can toggle between **Last 24h**, **Last 7d**, **Last 30d**, and **All Time** via filter buttons.
* The frontend asynchronously requests fresh telemetry across all endpoints simultaneously using `Promise.all()`.
* Chart instances are dynamically updated or redrawn via Chart.js `.destroy()` and re-instantiation, preventing memory leaks or visual artifacts.

---

## 8. Testing & Verification
The dashboard is validated by 14 dedicated automated tests in `tests/test_dashboard.py`:
* Verification of `GET /dashboard` returning HTTP 200.
* Schema and data validation across all 7 JSON API endpoints.
* Empty database handling (gracefully returns 0 counts and empty tables).
* Time filtering parameter validation.
* SQL injection resistance on query parameters.
* Proof of zero raw payload reflection in telemetry responses.
* Mathematical consistency verification between database records and aggregated metrics.

---

## 9. Known Boundaries & Limitations
* The dashboard is designed for local application inspection and does not implement distributed authentication or external multi-tenant access.
* Machine learning anomaly detection and external Burp Suite scanning interfaces are reserved for future phases.
