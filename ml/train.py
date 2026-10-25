import os
import json
import gzip
from datetime import datetime, timezone
from ml.config import MLConfig
from ml.dataset import load_dataset, deterministic_split
from ml.features import CharNGramVectorizer
from ml.classifier import PureLogisticRegression
from ml.evaluation import evaluate_predictions

def train_and_export():
    print("Loading dataset from:", MLConfig.DATASET_PATH)
    texts, labels = load_dataset(MLConfig.DATASET_PATH)
    print(f"Total dataset: {len(texts)} samples (Benign: {labels.count(0)}, Suspicious: {labels.count(1)})")

    # Split dataset
    split = deterministic_split(texts, labels, seed=MLConfig.RANDOM_SEED)
    print(f"Split sizes - Train: {len(split.train_texts)}, Val: {len(split.val_texts)}, Test: {len(split.test_texts)}")

    # Vectorize
    vectorizer = CharNGramVectorizer(
        ngram_range=MLConfig.NGRAM_RANGE,
        max_features=MLConfig.MAX_FEATURES
    )
    X_train = vectorizer.fit_transform(split.train_texts)
    X_val = vectorizer.transform(split.val_texts)
    X_test = vectorizer.transform(split.test_texts)
    print(f"Extracted {len(vectorizer.vocabulary_)} character n-gram features.")

    # Train Classifier
    clf = PureLogisticRegression(learning_rate=0.4, l2_reg=0.0005, epochs=60)
    clf.fit(X_train, split.train_labels, len(vectorizer.vocabulary_))

    # Evaluate on held-out test set
    test_probs = clf.predict_proba(X_test)
    test_preds = clf.predict(X_test, threshold=0.5)
    test_metrics = evaluate_predictions(split.test_labels, test_preds, test_probs)

    print("\n--- Held-Out Test Evaluation ---")
    print(f"Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"Precision: {test_metrics['precision']:.4f}")
    print(f"Recall:    {test_metrics['recall']:.4f}")
    print(f"F1 Score:  {test_metrics['f1_score']:.4f}")
    print(f"Confusion Matrix: {test_metrics['confusion_matrix']}")

    # Export artifacts to ml/models/
    os.makedirs(MLConfig.MODEL_DIR, exist_ok=True)

    # 1. Export vectorizer
    vec_data = {
        "ngram_range": vectorizer.ngram_range,
        "vocabulary_": vectorizer.vocabulary_,
        "idf_": vectorizer.idf_
    }
    with open(MLConfig.VECTORIZER_PATH, "w", encoding="utf-8") as f:
        json.dump(vec_data, f)

    # 2. Export model weights
    clf_data = {
        "num_features_": clf.num_features_,
        "bias_": clf.bias_,
        "weights_": clf.weights_
    }
    with open(MLConfig.MODEL_PATH, "w", encoding="utf-8") as f:
        json.dump(clf_data, f)

    # 3. Export metadata
    metadata = {
        "model_version": MLConfig.VERSION,
        "algorithm": "PureLogisticRegression",
        "vectorizer": "CharNGramVectorizer",
        "ngram_range": list(MLConfig.NGRAM_RANGE),
        "feature_count": len(vectorizer.vocabulary_),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "metrics": test_metrics,
        "dataset_samples": len(texts)
    }
    with open(MLConfig.METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\nModel artifacts saved successfully in:", MLConfig.MODEL_DIR)
    return metadata

if __name__ == "__main__":
    train_and_export()
