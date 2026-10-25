import re
import math
from typing import List, Dict, Tuple, Set

class CharNGramVectorizer:
    """
    Lightweight, deterministic character n-gram TF-IDF vectorizer
    implemented in pure Python without external dependencies.
    """
    def __init__(self, ngram_range: Tuple[int, int] = (3, 5), min_df: int = 1, max_features: int = 2500):
        self.ngram_range = ngram_range
        self.min_df = min_df
        self.max_features = max_features
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: List[float] = []

    def _extract_ngrams(self, text: str) -> List[str]:
        cleaned = text.lower()
        ngrams = []
        n_len = len(cleaned)
        min_n, max_n = self.ngram_range
        for n in range(min_n, max_n + 1):
            if n_len < n:
                continue
            for i in range(n_len - n + 1):
                ngrams.append(cleaned[i:i + n])
        return ngrams

    def fit(self, raw_documents: List[str]):
        doc_counts: Dict[str, int] = {}
        n_docs = len(raw_documents)

        for doc in raw_documents:
            seen_in_doc: Set[str] = set(self._extract_ngrams(doc))
            for ng in seen_in_doc:
                doc_counts[ng] = doc_counts.get(ng, 0) + 1

        # Filter by min_df and sort by document frequency descending
        filtered = [(ng, count) for ng, count in doc_counts.items() if count >= self.min_df]
        filtered.sort(key=lambda x: x[1], reverse=True)

        if self.max_features:
            filtered = filtered[:self.max_features]

        # Alphabetical sorting for deterministic index assignment
        filtered_terms = sorted([term for term, _ in filtered])
        self.vocabulary_ = {term: idx for idx, term in enumerate(filtered_terms)}

        # Standard smooth IDF: log((1 + n_docs) / (1 + df)) + 1
        self.idf_ = [0.0] * len(self.vocabulary_)
        for term, idx in self.vocabulary_.items():
            df = doc_counts.get(term, 0)
            self.idf_[idx] = math.log((1.0 + n_docs) / (1.0 + df)) + 1.0

        return self

    def transform(self, raw_documents: List[str]) -> List[Dict[int, float]]:
        """Transforms documents into sparse TF-IDF vectors (dict of {feature_idx: tfidf_weight})."""
        sparse_vectors = []
        for doc in raw_documents:
            ngrams = self._extract_ngrams(doc)
            term_counts: Dict[int, int] = {}
            for ng in ngrams:
                if ng in self.vocabulary_:
                    f_idx = self.vocabulary_[ng]
                    term_counts[f_idx] = term_counts.get(f_idx, 0) + 1

            # Compute TF-IDF
            total_terms = len(ngrams) or 1
            tfidf_vec: Dict[int, float] = {}
            norm_sq = 0.0

            for f_idx, count in term_counts.items():
                tf = count / total_terms
                val = tf * self.idf_[f_idx]
                tfidf_vec[f_idx] = val
                norm_sq += val * val

            # L2 normalization
            if norm_sq > 0.0:
                l2_norm = math.sqrt(norm_sq)
                for f_idx in tfidf_vec:
                    tfidf_vec[f_idx] /= l2_norm

            sparse_vectors.append(tfidf_vec)
        return sparse_vectors

    def fit_transform(self, raw_documents: List[str]) -> List[Dict[int, float]]:
        return self.fit(raw_documents).transform(raw_documents)
