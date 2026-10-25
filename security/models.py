import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


@dataclass
class DetectionInput:
    """Structured representation of untrusted input to be analyzed."""
    value: str
    source: str = "form"             # form, query, header, etc.
    field: str = "unknown"           # field name e.g. 'query', 'content', 'display_name'
    method: str = "POST"
    endpoint: str = "/"
    context: str = "html_text"       # html_text, html_attribute, url, javascript
    request_id: Optional[str] = None

    def compute_sha256(self) -> str:
        """Compute standard SHA-256 fingerprint of the original raw input."""
        return hashlib.sha256(self.value.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class MatchedRule:
    """Representation of an individual rule that triggered."""
    rule_id: str
    name: str
    category: str
    severity: str                    # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    matched_indicator: str


@dataclass
class DetectionResult:
    """Structured result returned by the XSS detection engine."""
    detected: bool
    risk_level: str                  # LOW, MEDIUM, HIGH, CRITICAL, NONE
    event_type: str = "XSS"
    matched_rules: List[MatchedRule] = field(default_factory=list)
    confidence: float = 0.0          # 0.0 to 1.0
    reasoning: str = ""
    indicator_summary: List[str] = field(default_factory=list)
    context: str = "html_text"
    source: str = "form"
    field_name: str = "unknown"
    input_hash: str = ""
    request_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Phase 7: Secondary Machine Learning Advisory Telemetry (Non-breaking defaults)
    ml_label: str = "UNAVAILABLE"    # BENIGN, SUSPICIOUS, or UNAVAILABLE
    ml_confidence: float = 0.0       # 0.0 to 1.0
    ml_model_version: str = "1.0.0"
    ml_enabled: bool = False

    def to_details_dict(self) -> Dict[str, Any]:
        """Convert detection diagnostics to safe metadata dictionary (no raw payload)."""
        data = {
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "context": self.context,
            "source": self.source,
            "field": self.field_name,
            "matched_rules_count": len(self.matched_rules),
            "matched_rule_ids": [r.rule_id for r in self.matched_rules],
            "indicators": self.indicator_summary[:5]  # Limit to top 5 safe summaries
        }
        if self.ml_enabled:
            data["ml"] = {
                "label": self.ml_label,
                "confidence": self.ml_confidence,
                "model_version": self.ml_model_version,
                "enabled": True
            }
        return data
