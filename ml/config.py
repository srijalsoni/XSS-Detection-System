import os

class MLConfig:
    """Central configuration for Machine Learning subsystem."""
    DATASET_PATH = os.path.join("ml", "data", "xss_training.jsonl")
    MODEL_DIR = os.path.join("ml", "models")
    MODEL_PATH = os.path.join(MODEL_DIR, "xss_classifier.json")
    VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.json")
    METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

    # Hyperparameters
    NGRAM_RANGE = (3, 5)
    ANALYZER = "char"
    MAX_FEATURES = 5000
    RANDOM_SEED = 42

    # Operational Mode: 'shadow', 'advisory', or 'disabled'
    ENABLED = True
    MODE = "shadow"
    VERSION = "1.0.0"
