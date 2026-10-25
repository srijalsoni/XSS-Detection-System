# P_211 Machine Learning Dataset Documentation

## 1. Dataset Purpose
The `xss_training.jsonl` dataset provides a balanced, defensive, and reproducible corpus for training and evaluating a secondary local machine learning classifier to detect Cross-Site Scripting (XSS) input anomalies.

## 2. Dataset Versioning
* **Dataset Version:** 1.0
* **Format:** JSON Lines (`.jsonl`), each line formatted as `{"text": "<string>", "label": <0 or 1>}`
* **Label Mapping:**
  * `0` = `BENIGN` (Harmless user input, technical documentation, math expressions, standard URLs, punctuation, and educational prose)
  * `1` = `SUSPICIOUS` (Executable script tags, DOM event handlers, pseudo-protocols, dangerous SVG/HTML constructs, attribute breakouts, execution sinks, and encoded variants)

## 3. Class Balance & Difficulty
The dataset intentionally includes challenging benign examples that frequently cause false positives in naive keyword filters:
* Educational prose discussing JavaScript sinks: `"In JavaScript, functions like alert() and eval() require defensive review."`
* HTML documentation referencing script tags: `"HTML tags such as <script> are discussed in this security document."`
* Mathematical inequalities: `"Equation: 5 < 10 and 20 > 15"`
* Valid web URLs: `"https://developer.mozilla.org/en-US/docs/Web/JavaScript"`
* Programming queries: `"How to write document.cookie parser in Python?"`

## 4. Source & Privacy
All samples are synthetically generated local defensive benchmarks. Zero production user data or private credentials are included.
