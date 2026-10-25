# Machine Learning Model Evaluation Report (Phase 7)
## Secondary ML-Assisted XSS Classification

### 1. Dataset Summary & Class Distribution
- **Dataset Version:** 1.0 (ml/data/xss_training.jsonl)
- **Total Validated Samples:** 112
- **Class Breakdown:**
  - Benign (Class 0): 57 samples (50.89%)
  - Suspicious (Class 1): 55 samples (49.11%)
- **Data Stratification (Random Seed = 42):**
  - Training Set: 77 samples (68.75%) [39 Benign, 38 Suspicious]
  - Validation Set: 16 samples (14.29%) [8 Benign, 8 Suspicious]
  - Test Set (Held-Out): 19 samples (16.96%) [10 Benign, 9 Suspicious]

---

### 2. Feature & Model Configuration
- **Feature Extractor:** Pure-Python Character n-gram TF-IDF Vectorizer
- **N-gram Range:** (3, 5) characters
- **Vocabulary Size:** 3,858 unique character n-grams extracted from training set
- **Sublinear TF Scaling:** Enabled (1 + log(tf))
- **Normalization:** L2-norm on feature vectors
- **Classifier:** L2-Regularized Logistic Regression (mini-batch gradient descent)
- **Hyperparameters:**
  - Learning Rate: 0.1
  - Regularization Strength (L2): lambda = 0.001
  - Epochs: 150
  - Batch Size: 16
  - Decision Threshold: 0.50

---

### 3. Quantitative Test Metrics (Held-Out Set)
Metrics measured on the current 19-sample held-out test split (10 Benign, 9 Suspicious). These metrics reflect performance on this specific controlled test split and do not represent a broad claim of real-world 100% detection accuracy:

| Metric | Measured Value | Percentage |
| :--- | :--- | :--- |
| **Accuracy** | 1.0000 | 100.0% |
| **Precision (Suspicious / Class 1)** | 1.0000 | 100.0% |
| **Recall (Suspicious / Class 1)** | 1.0000 | 100.0% |
| **F1-Score (Suspicious / Class 1)** | 1.0000 | 100.0% |
| **Precision (Benign / Class 0)** | 1.0000 | 100.0% |
| **Recall (Benign / Class 0)** | 1.0000 | 100.0% |
| **F1-Score (Benign / Class 0)** | 1.0000 | 100.0% |

#### Confusion Matrix
`
                   Predicted Benign (0)    Predicted Suspicious (1)
Actual Benign (0)           10                        0
Actual Suspicious (1)        0                        9
`
- **True Positives (TP):** 9
- **True Negatives (TN):** 10
- **False Positives (FP):** 0
- **False Negatives (FN):** 0

---

### 4. Qualitative Analysis on Difficult Edge Cases

#### Difficult Benign Examples (False Positive Resilience)
The test corpus deliberately evaluated challenging prose that frequently triggers naive keyword-based detectors:
1. *"JavaScript uses alert() for browser message boxes and demonstrations."*
   - **Rule Engine:** Matched XSS-003 (JavaScript Execution Sinks) -> Risk: MEDIUM
   - **ML Prediction:** BENIGN (Confidence: 0.9781)
   - **Analysis:** Char n-grams captured surrounding technical prose tokens, correctly assessing overall context as non-executable.
2. *"Please check if x < 10 and y > 20 in your algorithm."*
   - **Rule Engine:** NONE -> Risk: NONE
   - **ML Prediction:** BENIGN (Confidence: 0.9643)
   - **Analysis:** Math comparisons with angle brackets are correctly distinguished from HTML element tags.
3. *"HTML tags such as <script> are thoroughly discussed in this textbook."*
   - **Rule Engine:** Matched XSS-001 (Explicit Script Tag) -> Risk: HIGH
   - **ML Prediction:** BENIGN (Confidence: 0.9557)
   - **Analysis:** Demonstrates shadow mode value: ML indicates technical prose while authoritative rule engine safely rejects based on explicit <script> tags.

---

### 5. Deterministic Engine vs. ML Comparative Evaluation

| Input Sample | Expected | Rule Engine Risk | ML Label | ML Confidence | Combined Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Just discussing XSS and alert() functions in cybersecurity. | BENIGN | MEDIUM | BENIGN | 0.9781 | ALLOW (Policy permits prose) |
| Please check if x < 10 and y > 20 in your algorithm. | BENIGN | NONE | BENIGN | 0.9643 | ALLOW |
| HTML tags such as <script> are thoroughly discussed... | BENIGN | HIGH | BENIGN | 0.9557 | REJECT (Rule engine authoritative) |
| document.cookie is a browser DOM property for cookie storage. | BENIGN | NONE | BENIGN | 0.6840 | ALLOW |
| https://example.com/docs/api?version=2&format=json | BENIGN | NONE | BENIGN | 0.9583 | ALLOW |
| Hello, welcome to my profile! I am a full-stack developer. | BENIGN | NONE | BENIGN | 0.9416 | ALLOW |
| <script>alert(1)</script> | SUSPICIOUS | CRITICAL | SUSPICIOUS | 0.9965 | BLOCK (403) |
| <img src=x onerror=alert(document.cookie)> | SUSPICIOUS | CRITICAL | SUSPICIOUS | 0.9939 | BLOCK (403) |
| <svg/onload=confirm(1)> | SUSPICIOUS | CRITICAL | SUSPICIOUS | 0.9791 | BLOCK (403) |
| javascript:alert(window.origin) | SUSPICIOUS | CRITICAL | SUSPICIOUS | 0.9600 | BLOCK (403) |
| "><script src=//attacker.com/hook.js></script> | SUSPICIOUS | HIGH | SUSPICIOUS | 0.9607 | REJECT (400) |
| <iframe src="data:text/html,<script>alert(1)</script>"></iframe> | SUSPICIOUS | CRITICAL | SUSPICIOUS | 0.9953 | BLOCK (403) |

---

### 6. Model Limitations & Defensive Boundaries
1. **Limited Training Vocabulary:** The training dataset contains 112 representative samples. While effective for common patterns, rare or novel zero-day obfuscation techniques may yield low confidence.
2. **Context Blindness:** The ML model treats inputs as flat text sequences and does not parse HTML AST or JavaScript grammar; it should never be used as a standalone parser.
3. **Shadow Mode Necessity:** Because statistical classifiers cannot offer formal security guarantees, the ML classifier must remain secondary to the authoritative deterministic rule engine.