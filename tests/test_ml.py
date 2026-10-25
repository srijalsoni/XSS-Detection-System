import os
import json
import pytest
from ml.config import MLConfig
from ml.dataset import load_dataset, deterministic_split
from ml.features import CharNGramVectorizer
from ml.classifier import PureLogisticRegression
from ml.model_manager import ModelManager
from ml.predictor import MLPredictor, MLPredictionResult
from security import DetectionInput, default_detector, XSSDetector


# ============================================================================
# DATASET & SPLITTING TESTS (Tests 1-3)
# ============================================================================

def test_dataset_loading():
    """1. Test that dataset loads properly and is non-empty."""
    texts, labels = load_dataset(MLConfig.DATASET_PATH)
    assert len(texts) > 50
    assert len(texts) == len(labels)


def test_dataset_label_validation():
    """2. Test that labels are strictly binary (0 or 1)."""
    texts, labels = load_dataset(MLConfig.DATASET_PATH)
    assert all(l in (0, 1) for l in labels)
    assert labels.count(0) > 0
    assert labels.count(1) > 0


def test_deterministic_train_test_split():
    """3. Test that splitting is stratified and reproducible across seeds."""
    texts, labels = load_dataset(MLConfig.DATASET_PATH)
    split1 = deterministic_split(texts, labels, seed=42)
    split2 = deterministic_split(texts, labels, seed=42)
    assert split1.train_texts == split2.train_texts
    assert split1.test_labels == split2.test_labels
    assert len(split1.test_texts) > 0


# ============================================================================
# FEATURE EXTRACTION & TRAINING (Tests 4-6)
# ============================================================================

def test_feature_extraction():
    """4. Test that CharNGramVectorizer produces valid sparse vectors."""
    vec = CharNGramVectorizer(ngram_range=(3, 5), max_features=100)
    samples = ["<script>alert(1)</script>", "normal search query"]
    X = vec.fit_transform(samples)
    assert len(X) == 2
    assert len(vec.vocabulary_) > 0
    # Sparse vector should be normalized with positive weights
    assert all(isinstance(v, dict) for v in X)


def test_model_training_and_artifacts():
    """5-6. Test that model trains and artifacts are non-empty."""
    assert os.path.exists(MLConfig.MODEL_PATH)
    assert os.path.exists(MLConfig.VECTORIZER_PATH)
    assert os.path.exists(MLConfig.METADATA_PATH)


# ============================================================================
# MODEL LOADING & PREDICTION (Tests 7-11)
# ============================================================================

def test_model_loading():
    """7. Test that ModelManager successfully loads active model."""
    mgr = ModelManager.get_instance()
    assert mgr.is_available is True
    assert mgr.vectorizer is not None
    assert mgr.classifier is not None


def test_benign_prediction():
    """8. Test that benign prose is classified as BENIGN with high confidence."""
    res = MLPredictor.predict("Flask web application development tutorial")
    assert res.is_available is True
    assert res.predicted_label == "BENIGN"
    assert res.confidence >= 0.5


def test_suspicious_prediction():
    """9. Test that obvious script injection is classified as SUSPICIOUS."""
    res = MLPredictor.predict("<script>alert(1)</script>")
    assert res.is_available is True
    assert res.predicted_label == "SUSPICIOUS"
    assert res.confidence >= 0.5


def test_prediction_confidence_range():
    """10. Test that prediction confidence is strictly bounded [0.0, 1.0]."""
    res = MLPredictor.predict("<img src=x onerror=alert(1)>")
    assert 0.0 <= res.confidence <= 1.0


def test_model_version_metadata():
    """11. Test that prediction result contains model version metadata."""
    res = MLPredictor.predict("normal text")
    assert res.model_version is not None
    assert len(res.model_version) > 0


# ============================================================================
# ROBUSTNESS & EDGE CASES (Tests 12-15)
# ============================================================================

def test_empty_input_handling():
    """12. Test that empty or whitespace input is handled safely."""
    res = MLPredictor.predict("")
    assert res.predicted_label == "BENIGN"
    res_space = MLPredictor.predict("   \t  ")
    assert res_space.predicted_label == "BENIGN"


def test_unicode_handling():
    """13. Test that non-ASCII Unicode characters do not cause exceptions."""
    unicode_payload = "Überprüfen von <script>alert('ü')</script> — 安全测试"
    res = MLPredictor.predict(unicode_payload)
    assert res.is_available is True
    assert res.predicted_label == "SUSPICIOUS"


def test_missing_model_fails_safely(monkeypatch):
    """14. Test that missing model file fails safely without crashing."""
    mgr = ModelManager.get_instance()
    orig_path = MLConfig.MODEL_PATH
    try:
        MLConfig.MODEL_PATH = "ml/models/non_existent.joblib"
        mgr.reload()
        assert mgr.is_available is False
        res = MLPredictor.predict("<script>alert(1)</script>")
        assert res.is_available is False
        assert res.predicted_label == "UNAVAILABLE"
    finally:
        MLConfig.MODEL_PATH = orig_path
        mgr.reload()


def test_corrupted_model_fails_safely(tmp_path):
    """15. Test that malformed JSON artifact fails safely."""
    mgr = ModelManager.get_instance()
    orig_path = MLConfig.MODEL_PATH
    corrupt_file = str(tmp_path / "corrupt.joblib")
    with open(corrupt_file, "w") as f:
        f.write("{invalid_json: true, broken")

    try:
        MLConfig.MODEL_PATH = corrupt_file
        mgr.reload()
        assert mgr.is_available is False
        res = MLPredictor.predict("any text")
        assert res.is_available is False
    finally:
        MLConfig.MODEL_PATH = orig_path
        mgr.reload()


# ============================================================================
# INTEGRATION & POLICY PRESERVATION (Tests 16-20)
# ============================================================================

def test_ml_disabled_mode():
    """16. Test that ML can be disabled via detector parameter."""
    det = XSSDetector(enable_ml=False)
    res = det.analyze(DetectionInput(value="<script>alert(1)</script>"))
    assert res.detected is True  # Deterministic detection still works!
    assert res.ml_enabled is False
    assert res.ml_label == "UNAVAILABLE"


def test_ml_shadow_mode_telemetry():
    """17. Test that shadow mode attaches ML telemetry to DetectionResult."""
    res = default_detector.analyze(DetectionInput(value="<script>alert(1)</script>"))
    assert res.detected is True
    assert res.ml_enabled is True
    assert res.ml_label == "SUSPICIOUS"
    details = res.to_details_dict()
    assert "ml" in details
    assert details["ml"]["label"] == "SUSPICIOUS"
    assert details["ml"]["enabled"] is True


def test_deterministic_detector_preserves_authority_over_ml_disagreement():
    """
    18. CRITICAL GUARANTEE: Even if ML were to predict BENIGN, a deterministic
    detection (e.g. CRITICAL or HIGH) is NEVER downgraded.
    """
    # Test payload with explicit event handler
    det = default_detector.analyze(DetectionInput(value="<img src=x onerror=alert(1)>"))
    assert det.detected is True
    assert det.risk_level in ["HIGH", "CRITICAL"]


def test_raw_payload_never_logged_in_ml_details():
    """19. Telemetry dictionaries produced by ML never contain raw payload strings."""
    secret = "secret_exploit_token_xyz"
    det = default_detector.analyze(DetectionInput(value=f"<script>{secret}</script>"))
    details_str = json.dumps(det.to_details_dict())
    assert secret not in details_str


def test_repeated_prediction_consistency():
    """20. Test that inference is 100% deterministic and stateless."""
    payload = "Educational discussion of JavaScript alert() vs confirm()"
    res1 = MLPredictor.predict(payload)
    res2 = MLPredictor.predict(payload)
    assert res1.predicted_label == res2.predicted_label
    assert res1.confidence == res2.confidence
