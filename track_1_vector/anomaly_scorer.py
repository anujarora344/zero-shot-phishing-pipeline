"""
Track 1: k-NN Cosine Anomaly Scorer
Author: Track 1 Lead
Purpose:
    Computes Out-of-Distribution (OOD) anomaly scores by finding the k-nearest
    neighbors in the trusted reference vector space using cosine distance.
"""

from dataclasses import dataclass, field
import logging
from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.neighbors import NearestNeighbors

logger = logging.getLogger("Track1-Scorer")

DEFAULT_K = 5
DEFAULT_ANOMALY_THRESHOLD = 0.50


@dataclass
class ScoringResult:
    """Standardized output of the anomaly scoring engine."""
    knn_distance: float
    anomaly_score: float
    is_anomaly: bool
    nearest_domains: List[Dict[str, Any]] = field(default_factory=list)


class AnomalyScorer:
    """
    Computes unsupervised anomaly scores using k-Nearest Neighbors and Cosine Distance.
    
    Mathematical Foundation:
    1. Cosine Distance:
       d(u, v) = 1 - (u . v) / (||u|| * ||v||)
       For L2-normalized embeddings, d(u, v) = 1 - (u . v).
       Range: [0.0 (identical direction) to 2.0 (opposite direction)].
       In practice, embeddings on the unit hypersphere typically range from 0.0 to 1.0.

    2. k-NN Mean Distance:
       D_k = (1 / k) * sum_{i=1}^k d(u, r_i)
       where r_i are the k nearest reference vectors.

    3. Score Normalization:
       anomaly_score = clip(D_k / distance_scale, 0.0, 1.0)
       Higher score = more anomalous / further from trusted reference infrastructure.

    4. Interpretation:
       - Low score (<0.30): URL topology closely aligns with trusted reference domains.
       - Medium score (0.30 - 0.50): Mild structural divergence, possibly legitimate new pattern.
       - High score (>=0.50): Significant out-of-distribution anomaly. Triggers Track 2 agentic inspection.
    """

    def __init__(
        self,
        reference_vectors: np.ndarray,
        reference_domains: List[str],
        k: int = DEFAULT_K,
        threshold: float = DEFAULT_ANOMALY_THRESHOLD,
        distance_scale: float = 1.0
    ):
        if len(reference_domains) == 0 or reference_vectors.shape[0] == 0:
            raise ValueError("Reference store must contain at least 1 domain and vector.")

        self.k = min(k, len(reference_domains))
        self.threshold = threshold
        self.distance_scale = distance_scale
        self.reference_domains = reference_domains
        self.reference_vectors = reference_vectors

        # Initialize brute-force k-NN with cosine distance
        self.nn_model = NearestNeighbors(
            n_neighbors=self.k,
            metric="cosine",
            algorithm="brute"
        )
        self.nn_model.fit(self.reference_vectors)
        logger.info(f"AnomalyScorer initialized with {len(reference_domains)} references, k={self.k}")

    def score(self, query_vector: np.ndarray) -> ScoringResult:
        """
        Computes anomaly score for a single query vector of shape (384,).
        """
        # Ensure 2D shape (1, 384)
        if query_vector.ndim == 1:
            q = query_vector.reshape(1, -1)
        else:
            q = query_vector

        # Find k nearest neighbors
        distances, indices = self.nn_model.kneighbors(q)
        
        k_distances = distances[0]
        k_indices = indices[0]

        # Compute mean distance across the k nearest reference vectors
        mean_knn_distance = float(np.mean(k_distances))

        # Normalize score into [0.0, 1.0]
        normalized_score = float(np.clip(mean_knn_distance / self.distance_scale, 0.0, 1.0))
        is_anomaly = normalized_score >= self.threshold

        nearest_info = []
        for dist, idx in zip(k_distances, k_indices):
            nearest_info.append({
                "domain": self.reference_domains[idx],
                "distance": round(float(dist), 4)
            })

        return ScoringResult(
            knn_distance=round(mean_knn_distance, 4),
            anomaly_score=round(normalized_score, 4),
            is_anomaly=bool(is_anomaly),
            nearest_domains=nearest_info
        )

    def score_batch(self, query_vectors: np.ndarray) -> List[ScoringResult]:
        """Computes anomaly scores for a batch of query vectors of shape (N, 384)."""
        if query_vectors.shape[0] == 0:
            return []

        distances, indices = self.nn_model.kneighbors(query_vectors)
        results = []

        for row_dist, row_idx in zip(distances, indices):
            mean_dist = float(np.mean(row_dist))
            normalized = float(np.clip(mean_dist / self.distance_scale, 0.0, 1.0))
            is_anom = normalized >= self.threshold

            nearest_info = [
                {"domain": self.reference_domains[idx], "distance": round(float(d), 4)}
                for d, idx in zip(row_dist, row_idx)
            ]

            results.append(ScoringResult(
                knn_distance=round(mean_dist, 4),
                anomaly_score=round(normalized, 4),
                is_anomaly=bool(is_anom),
                nearest_domains=nearest_info
            ))

        return results
