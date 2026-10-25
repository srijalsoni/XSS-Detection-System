from typing import List, Tuple
from security.patterns import XSSRule


class Scorer:
    """
    Evaluates rule matches and context heuristics to assign an explainable risk level:
    LOW, MEDIUM, HIGH, CRITICAL.
    """

    @staticmethod
    def calculate_risk(matched_rules: List[XSSRule], context: str) -> Tuple[str, float, str]:
        if not matched_rules:
            return "NONE", 0.0, "No XSS indicators detected."

        categories = {r.category for r in matched_rules}
        severities = [r.severity for r in matched_rules]
        rule_count = len(matched_rules)

        # Baseline confidence based on rule count and highest severity
        if "CRITICAL" in severities:
            base_score = 0.95
        elif "HIGH" in severities:
            base_score = 0.80
        elif "MEDIUM" in severities:
            base_score = 0.55
        else:
            base_score = 0.35

        # Heuristic 1: Multiple correlated indicators amplify risk
        # e.g., Tag/Attribute breakout + Event handler OR Event handler + JS sink
        has_tag_or_elem = bool(categories.intersection({"SCRIPT_TAG", "DANGEROUS_TAG", "ATTRIBUTE_INJECTION"}))
        has_handler_or_protocol = bool(categories.intersection({"EVENT_HANDLER", "PSEUDO_PROTOCOL"}))
        has_sink = "JS_SINK" in categories

        is_critical_combination = (
            (has_tag_or_elem and has_handler_or_protocol) or
            (has_handler_or_protocol and has_sink) or
            ("SCRIPT_TAG" in categories and has_sink)
        )

        if is_critical_combination:
            risk_level = "CRITICAL"
            confidence = min(0.99, base_score + 0.15)
            reason = (
                f"Critical compound XSS pattern: {len(matched_rules)} indicators matched across "
                f"'{', '.join(sorted(categories))}' categories in context '{context}'."
            )
        elif "HIGH" in severities or rule_count >= 2:
            risk_level = "HIGH"
            confidence = min(0.90, base_score + (0.05 * (rule_count - 1)))
            reason = (
                f"High confidence XSS indicator: {len(matched_rules)} rule(s) triggered "
                f"([{', '.join(r.rule_id for r in matched_rules)}])."
            )
        elif "MEDIUM" in severities:
            risk_level = "MEDIUM"
            confidence = base_score
            reason = f"Moderate XSS indicator detected: [{matched_rules[0].rule_id} - {matched_rules[0].name}]."
        else:
            risk_level = "LOW"
            confidence = base_score
            reason = f"Low severity suspicious indicator: [{matched_rules[0].rule_id}]."

        return risk_level, confidence, reason
