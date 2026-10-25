from dataclasses import dataclass
from typing import Optional
from ml.model_manager import ModelManager
from ml.config import MLConfig

@dataclass
class MLPredictionResult:
    predicted_label: str       # "BENIGN", "SUSPICIOUS", or "UNAVAILABLE"
    confidence: float          # 0.0 to 1.0
    model_version: str         # e.g. "1.0.0"
    is_available: bool         # True if ML model evaluated input
    error_message: Optional[str] = None
    explanation: str = ""

class MLPredictor:
    """
    Performs inference on normalized text inputs using the trained ML model.
    Operates in advisory/shadow mode by default.
    """
    @staticmethod
    def predict(normalized_text: str) -> MLPredictionResult:
        mgr = ModelManager.get_instance()

        if not mgr.is_available:
            return MLPredictionResult(
                predicted_label="UNAVAILABLE",
                confidence=0.0,
                model_version=MLConfig.VERSION,
                is_available=False,
                error_message=mgr.load_error or "ML model not ready",
                explanation="ML classifier is currently offline or disabled."
            )

        if not normalized_text:
            return MLPredictionResult(
                predicted_label="BENIGN",
                confidence=0.99,
                model_version=mgr.metadata.get("model_version", MLConfig.VERSION),
                is_available=True,
                explanation="Empty input evaluated as benign."
            )

        try:
            # Transform and predict
            vec = mgr.vectorizer.transform([normalized_text])
            prob_suspicious = mgr.classifier.predict_proba(vec)[0]

            if prob_suspicious >= 0.5:
                label = "SUSPICIOUS"
                confidence = round(prob_suspicious, 4)
                expl = f"ML classifier identified statistical n-gram anomaly with {confidence*100:.1f}% confidence."
            else:
                label = "BENIGN"
                confidence = round(1.0 - prob_suspicious, 4)
                expl = f"ML classifier identified input pattern as normal text with {confidence*100:.1f}% confidence."

            return MLPredictionResult(
                predicted_label=label,
                confidence=confidence,
                model_version=mgr.metadata.get("model_version", MLConfig.VERSION),
                is_available=True,
                explanation=expl
            )
        except Exception as e:
            return MLPredictionResult(
                predicted_label="UNAVAILABLE",
                confidence=0.0,
                model_version=mgr.metadata.get("model_version", MLConfig.VERSION),
                is_available=False,
                error_message=str(e),
                explanation="Inference error encountered during ML processing."
            )
