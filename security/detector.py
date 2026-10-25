from typing import List, Optional
import logging
from security.models import DetectionInput, DetectionResult, MatchedRule
from security.normalization import Normalizer
from security.patterns import BUILTIN_RULES, XSSRule
from security.scoring import Scorer

logger = logging.getLogger("p211_app")


class XSSDetector:
    """
    Core defensive XSS detection engine with secondary ML advisory layer.
    Orchestrates input normalization, signature scanning, heuristics, scoring,
    and optional machine-learning shadow telemetry.
    """

    def __init__(self, rules: Optional[List[XSSRule]] = None, enable_ml: bool = True):
        self.rules = rules if rules is not None else BUILTIN_RULES
        self.enable_ml = enable_ml

    def analyze(self, detection_input: DetectionInput) -> DetectionResult:
        raw_value = detection_input.value or ""
        input_hash = detection_input.compute_sha256()

        # Step 1: Normalize input safely without modifying original application data
        normalized_value = Normalizer.normalize(raw_value)

        # Step 2: Primary Deterministic Rule & Heuristic Detection (Authoritative)
        matched_rules: List[XSSRule] = []
        matched_indicators: List[str] = []

        if normalized_value:
            for rule in self.rules:
                match = rule.pattern.search(normalized_value)
                if match:
                    matched_rules.append(rule)
                    # Extract snippet of matching indicator safely
                    snippet = match.group(0)[:30]
                    matched_indicators.append(snippet)

        detected = len(matched_rules) > 0

        if detected:
            risk_level, confidence, reasoning = Scorer.calculate_risk(
                matched_rules, detection_input.context
            )
            rule_objects = [
                MatchedRule(
                    rule_id=r.rule_id,
                    name=r.name,
                    category=r.category,
                    severity=r.severity,
                    description=r.description,
                    matched_indicator=ind
                )
                for r, ind in zip(matched_rules, matched_indicators)
            ]
        else:
            risk_level = "NONE"
            confidence = 0.0
            reasoning = "Input passed all XSS detection checks without matches."
            rule_objects = []

        # Step 3: Phase 7 Secondary Machine Learning Advisory (Shadow Mode)
        ml_label = "UNAVAILABLE"
        ml_conf = 0.0
        ml_version = "1.0.0"
        ml_active = False

        if self.enable_ml:
            try:
                from ml.predictor import MLPredictor
                ml_res = MLPredictor.predict(normalized_value)
                ml_label = ml_res.predicted_label
                ml_conf = ml_res.confidence
                ml_version = ml_res.model_version
                ml_active = ml_res.is_available

                # CRITICAL PRESERVATION: Deterministic engine remains authoritative.
                # ML never downgrades a deterministic HIGH/CRITICAL detection.
                if detected and ml_label == "BENIGN":
                    logger.debug("ML-Rule Disagreement: Deterministic detection (%s) preserved over ML BENIGN.", risk_level)
            except Exception as e:
                logger.warning("ML prediction failed safely: %s", str(e))
                ml_label = "UNAVAILABLE"
                ml_active = False

        return DetectionResult(
            detected=detected,
            risk_level=risk_level,
            event_type="XSS",
            matched_rules=rule_objects,
            confidence=confidence,
            reasoning=reasoning,
            indicator_summary=matched_indicators,
            context=detection_input.context,
            source=detection_input.source,
            field_name=detection_input.field,
            input_hash=input_hash,
            request_id=detection_input.request_id,
            ml_label=ml_label,
            ml_confidence=ml_conf,
            ml_model_version=ml_version,
            ml_enabled=ml_active
        )


# Global detector singleton for application-wide use
default_detector = XSSDetector()
