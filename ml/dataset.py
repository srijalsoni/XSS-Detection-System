import os
import json
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional

@dataclass
class DatasetSplit:
    train_texts: List[str]
    train_labels: List[int]
    val_texts: List[str]
    val_labels: List[int]
    test_texts: List[str]
    test_labels: List[int]

def load_dataset(filepath: str = "ml/data/xss_training.jsonl") -> Tuple[List[str], List[int]]:
    """Loads and validates the training dataset from JSONL."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found: {filepath}")

    texts = []
    labels = []
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if "text" not in item or "label" not in item:
                raise ValueError(f"Line {idx} missing 'text' or 'label'")
            lbl = int(item["label"])
            if lbl not in (0, 1):
                raise ValueError(f"Invalid label {lbl} at line {idx}; must be 0 or 1")
            texts.append(item["text"])
            labels.append(lbl)

    return texts, labels

def deterministic_split(
    texts: List[str],
    labels: List[int],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42
) -> DatasetSplit:
    """
    Splits dataset into stratified, reproducible train/val/test splits
    using pure Python (no scikit-learn dependency required for splitting).
    """
    import random
    rng = random.Random(seed)

    benign_pairs = [(t, l) for t, l in zip(texts, labels) if l == 0]
    suspicious_pairs = [(t, l) for t, l in zip(texts, labels) if l == 1]

    rng.shuffle(benign_pairs)
    rng.shuffle(suspicious_pairs)

    def split_group(pairs):
        n = len(pairs)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        train = pairs[:n_train]
        val = pairs[n_train:n_train + n_val]
        test = pairs[n_train + n_val:]
        return train, val, test

    b_train, b_val, b_test = split_group(benign_pairs)
    s_train, s_val, s_test = split_group(suspicious_pairs)

    train = b_train + s_train
    val = b_val + s_val
    test = b_test + s_test

    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)

    return DatasetSplit(
        train_texts=[t for t, l in train],
        train_labels=[l for t, l in train],
        val_texts=[t for t, l in val],
        val_labels=[l for t, l in val],
        test_texts=[t for t, l in test],
        test_labels=[l for t, l in test]
    )
