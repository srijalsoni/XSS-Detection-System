import os
import json
import logging
from typing import Optional, Dict, Any
from ml.config import MLConfig
from ml.features import CharNGramVectorizer
from ml.classifier import PureLogisticRegression

logger = logging.getLogger("p211_app")

class ModelManager:
    """
    Safely loads, caches, and validates locally generated ML artifacts.
    Guarantees fail-safe behavior: if artifacts are missing, corrupt, or disabled,
    it gracefully signals unavailability without crashing.
    """
    _instance: Optional["ModelManager"] = None

    def __init__(self):
        self.vectorizer: Optional[CharNGramVectorizer] = None
        self.classifier: Optional[PureLogisticRegression] = None
        self.metadata: Dict[str, Any] = {}
        self.is_available: bool = False
        self.load_error: Optional[str] = None
        self.reload()

    @classmethod
    def get_instance(cls) -> "ModelManager":
        if cls._instance is None:
            cls._instance = ModelManager()
        return cls._instance

    def reload(self):
        """Loads artifacts safely using standard JSON deserialization."""
        self.is_available = False
        self.load_error = None

        if not MLConfig.ENABLED:
            self.load_error = "ML subsystem is disabled in configuration."
            return

        if not os.path.exists(MLConfig.MODEL_PATH) or not os.path.exists(MLConfig.VECTORIZER_PATH):
            self.load_error = "Model or vectorizer artifact not found on disk."
            return

        try:
            # 1. Load vectorizer
            with open(MLConfig.VECTORIZER_PATH, "r", encoding="utf-8") as f:
                vec_data = json.load(f)
            self.vectorizer = CharNGramVectorizer(
                ngram_range=tuple(vec_data["ngram_range"]),
                max_features=len(vec_data["vocabulary_"])
            )
            self.vectorizer.vocabulary_ = vec_data["vocabulary_"]
            self.vectorizer.idf_ = vec_data["idf_"]

            # 2. Load classifier
            with open(MLConfig.MODEL_PATH, "r", encoding="utf-8") as f:
                clf_data = json.load(f)
            self.classifier = PureLogisticRegression()
            self.classifier.num_features_ = clf_data["num_features_"]
            self.classifier.bias_ = clf_data["bias_"]
            # JSON keys are strings, convert back to int indices
            self.classifier.weights_ = {int(k): v for k, v in clf_data["weights_"].items()}

            # 3. Load metadata
            if os.path.exists(MLConfig.METADATA_PATH):
                with open(MLConfig.METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            else:
                self.metadata = {"model_version": MLConfig.VERSION}

            self.is_available = True
            logger.info("ML XSS Classifier loaded successfully (version %s).", self.metadata.get("model_version"))
        except Exception as e:
            self.is_available = False
            self.load_error = f"Failed to load ML artifacts: {str(e)}"
            logger.warning("ML subsystem unavailable: %s", self.load_error)
