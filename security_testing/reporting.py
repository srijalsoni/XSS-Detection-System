from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class TestExecutionRecord:
    payload_id: str
    category: str
    target_endpoint: str
    http_method: str
    
    # Expected vs Actual Status
    expected_status: int
    actual_status: int
    
    # Expected vs Actual Action
    expected_action: str
    actual_action: str
    
    # Expected vs Actual Risk
    expected_risk: str
    actual_risk: str
    
    # Expected vs Actual Rule IDs
    expected_rule_ids: Optional[str]
    actual_rule_ids: Optional[str]
    
    # Actual ML Telemetry (retrieved directly from security event)
    actual_ml_label: Optional[str]
    actual_ml_confidence: Optional[float]
    actual_ml_model_version: Optional[str]
    actual_ml_enabled: Optional[bool]
    
    # Verification checks
    status_passed: bool
    action_passed: bool
    risk_passed: bool
    rule_passed: bool
    headers_verified: bool
    reflection_safe: bool
    correlation_id_verified: bool
    passed: bool
    
    # Metadata
    request_id: Optional[str] = None
    notes: str = ""

@dataclass
class SecurityTestReport:
    timestamp: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate: float
    mode: str                     # "DIRECT" or "BURP_PROXY"
    proxy_url: Optional[str]
    records: List[TestExecutionRecord]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save_json(self, output_path: str):
        import os
        import json
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def generate_markdown_summary(self) -> str:
        lines = [
            f"# Automated Security Test Execution Report",
            f"**Execution Timestamp:** {self.timestamp} UTC",
            f"**Execution Mode:** `{self.mode}` (Proxy: {self.proxy_url or 'None'})",
            f"**Total Payloads Evaluated:** {self.total_tests}",
            f"**Passed:** {self.passed_tests} | **Failed:** {self.failed_tests} | **Pass Rate:** {self.pass_rate:.1f}%",
            "",
            "## Summary of Test Results (Expected vs Observed)",
            "",
            "| Payload ID | Category | Endpoint | Exp Status | Act Status | Exp Action | Act Action | Exp Risk | Act Risk | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        for r in self.records:
            status_badge = "PASS" if r.passed else "FAIL"
            lines.append(
                f"| `{r.payload_id}` | {r.category} | `{r.target_endpoint}` | "
                f"{r.expected_status} | {r.actual_status} | "
                f"{r.expected_action} | {r.actual_action} | "
                f"{r.expected_risk} | {r.actual_risk} | **{status_badge}** |"
            )

        lines.extend([
            "",
            "## Observed Defensive Telemetry & Real ML Advisory Evidence",
            "",
            "| Payload ID | Exp Rule(s) | Observed Rule(s) | ML Label | ML Confidence | ML Version | Correlation ID |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ])

        for r in self.records:
            exp_r = r.expected_rule_ids or "None"
            act_r = r.actual_rule_ids or "None"
            ml_lbl = r.actual_ml_label or "N/A"
            ml_conf = f"{r.actual_ml_confidence:.4f}" if r.actual_ml_confidence is not None else "N/A"
            ml_ver = r.actual_ml_model_version or "N/A"
            req = (r.request_id[:8] + "...") if r.request_id else "None"
            lines.append(f"| `{r.payload_id}` | `{exp_r}` | `{act_r}` | {ml_lbl} | {ml_conf} | {ml_ver} | `{req}` |")

        return "\n".join(lines)
