from typing import Optional, Tuple
from flask import current_app, render_template, make_response
from database import SecurityEventRepository
from security.detector import default_detector
from security.models import DetectionInput, DetectionResult
from security.policy import PolicyEngine, ResponseDecision, ResponseAction


def process_security_pipeline(
    field_name: str,
    raw_value: str,
    endpoint: str,
    method: str,
    context: str = "html_text",
    request_id: Optional[str] = None
) -> Tuple[DetectionResult, ResponseDecision]:
    """
    Executes the full Phase 5 defense pipeline:
    DetectionInput -> XSSDetector.analyze() -> PolicyEngine.evaluate() -> SecurityEventRepository.create()
    """
    det_input = DetectionInput(
        value=raw_value,
        source="form" if method == "POST" else "query",
        field=field_name,
        method=method,
        endpoint=endpoint,
        context=context,
        request_id=request_id
    )
    result = default_detector.analyze(det_input)
    decision = PolicyEngine.evaluate(result)

    if result.detected:
        rule_ids = ",".join(r.rule_id for r in result.matched_rules)
        current_app.logger.warning(
            "Security Event: [Action: %s] [Risk: %s] [Rules: %s] [Field: %s] [req_id=%s]",
            decision.security_event_action, result.risk_level, rule_ids, field_name, request_id
        )
        SecurityEventRepository.create(
            event_type=result.event_type,
            endpoint=endpoint,
            method=method,
            risk_level=result.risk_level,
            action=decision.security_event_action,
            rule_id=rule_ids,
            input_hash=result.input_hash,
            request_id=request_id,
            details=result.to_details_dict()
        )

    return result, decision


def render_blocked_response(decision: ResponseDecision):
    """
    Renders a sanitized, professional rejection/block response
    without reflecting raw payloads or internal rules.
    """
    html_content = render_template(
        "blocked.html",
        message=decision.user_message,
        status_code=decision.status_code,
        action=decision.action
    )
    return make_response(html_content, decision.status_code)
