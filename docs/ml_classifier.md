# Machine Learning Classifier Layer (Phase 7)
## Secondary ML-Assisted XSS Classification & Comparative Evaluation

### 1. Why ML Was Added
The core detection engine (Phases 4–6) relies on an authoritative deterministic rule and signature scanner. While deterministic pattern matching is fast, predictable, and essential for blocking known high-risk exploit payloads, it can be rigid when encountering obfuscated syntax, compound delimiters, or subtle variations.

The machine learning classifier was introduced in Phase 7 as a **secondary, advisory layer** designed to:
- Evaluate contextual text patterns and character n-gram combinations.
- Provide a complementary confidence signal (ml_label and ml_confidence).
- Highlight potential edge cases or novel variants for security telemetry without risking false-negative bypasses of deterministic rules.
- Enable comparative evaluation between deterministic signature engines and statistical models.

---

### 2. Architectural Design & Precedence

#### Pipeline Flow
`
              User Input
                  |
                  v
             Normalization (safe text representation)
                  |
          +-------+-------+
          |               |
          v               v
   Rule Detector       ML Classifier (Secondary)
   (Authoritative)        |
          |       prediction/confidence
          |               |
          +-------+-------+
                  |
                  v
         Combined Security Result
                  |
                  v
           Policy Engine
                  |
        +---------+---------+
        |         |         |
      ALLOW     REJECT    BLOCK
`

#### Precedence Principles
1. **Rule Engine Remains Authoritative:** The deterministic rule engine retains absolute veto power. If deterministic rules evaluate an input as HIGH or CRITICAL, the ML prediction cannot downgrade the risk or convert the action to ALLOW.
2. **Conservative Combination:** When the rule engine flags an attack, the event is blocked/rejected according to policy regardless of ML confidence.
3. **Shadow / Advisory Mode by Default:** ML predictions operate in shadow mode (ML_ENFORCEMENT_MODE = "shadow"). ML predictions are recorded in security event details telemetry (ml_label, ml_confidence, ml_model_version, ml_enabled) without modifying core response decisions.

---

### 3. Dataset Design & Reproducibility
- **Dataset File:** ml/data/xss_training.jsonl
- **Specification:** Version 1.0 (documented in ml/data/README.md)
- **Total Samples:** 112 curated samples (57 Benign, 55 Suspicious)
- **Labels:**
  - 0 = BENIGN: Everyday comments, search terms, biographies, technical prose discussing cybersecurity concepts (alert(), document.cookie), mathematical comparisons (x < 10 and y > 20), API documentation, and code explanations.
  - 1 = SUSPICIOUS: Script tags, inline event handlers (onerror, onload, onmouseover), JavaScript pseudo-protocols (javascript:), dangerous HTML5/SVG/iframe constructs, and attribute breakouts.
- **Data Splitting:** Stratified, deterministic split using random.seed(42):
  - **Training Set:** 77 samples (68.75%)
  - **Validation Set:** 16 samples (14.29%)
  - **Test Set:** 19 samples (16.96%)

---

### 4. Feature Engineering
- **Technique:** Character n-gram TF-IDF vectorization (ml/features.py).
- **N-gram Range:** 3 to 5 characters (ngram_range=(3, 5)).
- **Lowercasing:** True (case-insensitive character n-grams).
- **Sublinear TF Scaling:** Enabled (1 + log(tf)) to prevent high-frequency characters from dominating.
- **L2 Normalization:** Applied to all feature vectors to ensure scale invariance across input lengths.
- **Input Bounding:** Inputs are truncated to the first 4,096 characters to prevent denial-of-service via resource exhaustion.

---

### 5. Model Architecture & Training
- **Model Choice:** L2-regularized Logistic Regression (PureLogisticRegression in ml/classifier.py).
- **Optimization:** Mini-batch stochastic gradient descent with binary cross-entropy loss and L2 weight regularization (lambda = 0.001).
- **Explainability:** Produces standard sigmoid probability scores (P(y=1|x) in [0.0, 1.0]) with a decision threshold of 0.5.
- **Model Artifacts:**
  - ml/models/xss_classifier.json (Model weights and biases in safe JSON format)
  - ml/models/tfidf_vectorizer.json (Feature vocabulary and IDF weights in safe JSON format)
  - ml/models/model_metadata.json (Hyperparameters, vocabulary size, split counts, and performance metrics)

---

### 6. Evaluation Metrics & Performance
Evaluated on the held-out test set (19 samples: 10 Benign, 9 Suspicious):
- **Accuracy:** 100.00% (1.0000)
- **Precision (Suspicious):** 1.0000
- **Recall (Suspicious):** 1.0000
- **F1-Score (Suspicious):** 1.0000
- **Confusion Matrix:**
  - True Negatives (Benign as Benign): 10
  - False Positives (Benign as Suspicious): 0
  - False Negatives (Suspicious as Benign): 0
  - True Positives (Suspicious as Suspicious): 9

#### Inference Latency Benchmarks
- **Model Load Time:** ~10.3 ms
- **Single Prediction Latency:** ~0.08 ms
- **1,000 Repeated Predictions Throughput:** ~29.5 ms total (~0.030 ms per prediction)

---

### 7. Failure Modes & Resilience
- **Missing Artifacts:** If ml/models/ artifacts are missing or unreadable, ModelManager gracefully sets is_available = False and logs a warning.
- **Corrupted Artifacts:** Malformed JSON in model files triggers safe exception handling and disables ML inference.
- **Fail-Safe Operation:** In all failure states, deterministic XSS detection proceeds with deterministic detection functionality; security decisions are never degraded or blocked by ML issues.
- **Safe Serialization:** Standard JSON format is used for persistence, eliminating Python pickle deserialization risks and arbitrary code execution vulnerabilities.