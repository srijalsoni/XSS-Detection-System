from dataclasses import dataclass
from typing import Optional
from security.models import DetectionResult


class ResponseAction:
    ALLOW = "ALLOW"
    LOG_ONLY = "LOG_ONLY"
    SAFE_RENDER = "SAFE_RENDER"
    REJECT = "REJECT"
    BLOCK = "BLOCK"


@dataclass
class ResponseDecision:
    """Represents the deliberate action decided by the policy engine."""
    action: str                        # ALLOW, LOG_ONLY, SAFE_RENDER, REJECT, BLOCK
    status_code: int = 200             # 200, 400, 403
    user_message: str = ""             # Safe user-facing feedback (no raw payload)
    security_event_action: str = "LOGGED"  # DETECTED, LOGGED, REJECTED, BLOCKED, SAFE_RENDERED
    should_continue: bool = True       # Whether the route handler should proceed
    reason: str = ""                   # Internal diagnostic reason for event log


class PolicyEngine:
    """
    Evaluates detection results and application context to produce an explainable
    response decision. Separates detection from mitigation.
    """

    @staticmethod
    def evaluate(detection_result: DetectionResult) -> ResponseDecision:
        # Case 1: Benign input
        if not detection_result.detected:
            return ResponseDecision(
                action=ResponseAction.ALLOW,
                status_code=200,
                user_message="",
                security_event_action="NONE",
                should_continue=True,
                reason="Input evaluated clean with no indicators."
            )

        risk = detection_result.risk_level.upper()
        field = detection_result.field_name
        endpoint = detection_result.context

        # Case 2: CRITICAL risk -> BLOCK
        if risk == "CRITICAL":
            return ResponseDecision(
                action=ResponseAction.BLOCK,
                status_code=403,
                user_message="Your request was blocked because it contains high-risk content prohibited by security policy.",
                security_event_action="BLOCKED",
                should_continue=False,
                reason=f"Blocked compound high-risk XSS attack vector on field '{field}'."
            )

        # Case 3: HIGH risk -> REJECT
        if risk == "HIGH":
            return ResponseDecision(
                action=ResponseAction.REJECT,
                status_code=400,
                user_message="Your request could not be processed because it contains prohibited script or executable patterns.",
                security_event_action="REJECTED",
                should_continue=False,
                reason=f"Rejected request due to explicit XSS indicator on field '{field}'."
            )

        # Case 4: MEDIUM risk -> Contextual Handling (REJECT if URL/attribute context, else SAFE_RENDER)
        if risk == "MEDIUM":
            if detection_result.context in ["url", "html_attribute"]:
                return ResponseDecision(
                    action=ResponseAction.REJECT,
                    status_code=400,
                    user_message="The provided value is not accepted in this field.",
                    security_event_action="REJECTED",
                    should_continue=False,
                    reason=f"Rejected medium-risk pattern in sensitive context '{detection_result.context}' on field '{field}'."
                )
            else:
                return ResponseDecision(
                    action=ResponseAction.SAFE_RENDER,
                    status_code=200,
                    user_message="",
                    security_event_action="SAFE_RENDERED",
                    should_continue=True,
                    reason=f"Allowed with safe template auto-escaping for medium-risk indicator in context '{detection_result.context}'."
                )

        # Case 5: LOW risk -> LOG_ONLY + ALLOW
        return ResponseDecision(
            action=ResponseAction.LOG_ONLY,
            status_code=200,
            user_message="",
            security_event_action="LOGGED",
            should_continue=True,
            reason=f"Logged low-risk anomaly on field '{field}'; allowed normal processing."
        )
