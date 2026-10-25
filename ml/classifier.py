import math
from typing import List, Dict, Tuple, Any

def sigmoid(z: float) -> float:
    # Bounded sigmoid to avoid math overflow
    if z < -40.0:
        return 0.0
    if z > 40.0:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))

class PureLogisticRegression:
    """
    Pure Python L2-regularized Logistic Regression classifier using mini-batch
    gradient descent. Ensures 100% offline reproducibility and deterministic inference.
    """
    def __init__(self, learning_rate: float = 0.5, l2_reg: float = 0.001, epochs: int = 40):
        self.learning_rate = learning_rate
        self.l2_reg = l2_reg
        self.epochs = epochs
        self.weights_: Dict[int, float] = {}
        self.bias_: float = 0.0
        self.num_features_: int = 0

    def fit(self, X: List[Dict[int, float]], y: List[int], num_features: int):
        self.num_features_ = num_features
        self.weights_ = {i: 0.0 for i in range(num_features)}
        self.bias_ = 0.0
        n_samples = len(X)

        for epoch in range(self.epochs):
            for x_vec, target in zip(X, y):
                # Compute raw score z = w * x + b
                z = self.bias_
                for f_idx, val in x_vec.items():
                    z += self.weights_.get(f_idx, 0.0) * val

                pred = sigmoid(z)
                err = pred - float(target)

                # Gradient updates with L2 regularization
                self.bias_ -= self.learning_rate * err
                for f_idx, val in x_vec.items():
                    w = self.weights_.get(f_idx, 0.0)
                    grad = (err * val) + (self.l2_reg * w)
                    self.weights_[f_idx] = w - (self.learning_rate * grad)

        return self

    def predict_proba(self, X: List[Dict[int, float]]) -> List[float]:
        """Returns P(label = 1 | x) for each sample."""
        probas = []
        for x_vec in X:
            z = self.bias_
            for f_idx, val in x_vec.items():
                z += self.weights_.get(f_idx, 0.0) * val
            probas.append(sigmoid(z))
        return probas

    def predict(self, X: List[Dict[int, float]], threshold: float = 0.5) -> List[int]:
        return [1 if p >= threshold else 0 for p in self.predict_proba(X)]
