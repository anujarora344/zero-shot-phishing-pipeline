"""
Track 1: Vector Space Anomaly Detection Pipeline
Author: Track 1 Lead
Purpose:
    Master orchestration module for Track 1. Accepts raw URLs, parses topologies,
    extracts lexical features, generates dense vector representations, compares
    against trusted reference manifolds, and emits standardized Track1Input payloads.
"""

import argparse
import json
import logging
import sys
from typing import List, Dict, Any, Union

from track_1_vector.url_parser import parse_url, ParsedURL
from track_1_vector.feature_extractor import extract_features, URLFeatures
from track_1_vector.embedding_model import URLEmbedder
from track_1_vector.reference_store import ReferenceStore
from track_1_vector.anomaly_scorer import AnomalyScorer, ScoringResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Track1-Engine")


class VectorAnomalyEngine:
    """
    End-to-End Track 1 Engine.
    Orchestrates URL parsing, feature extraction, embedding, and k-NN scoring.
    """

    def __init__(
        self,
        reference_data_path: str = None,
        k: int = 5,
        threshold: float = 0.50,
        embedder: URLEmbedder = None
    ):
        self.k = k
        self.threshold = threshold
        self.embedder = embedder or URLEmbedder()
        self.reference_store = ReferenceStore(data_path=reference_data_path, embedder=self.embedder)
        self.scorer = AnomalyScorer(
            reference_vectors=self.reference_store.vectors,
            reference_domains=self.reference_store.domains,
            k=self.k,
            threshold=self.threshold
        )
        logger.info(
            f"VectorAnomalyEngine initialized successfully. "
            f"[Backend: {self.embedder.backend}, Reference Count: {self.reference_store.size()}]"
        )

    def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Processes a single raw URL and returns a structured dictionary
        strictly compatible with the team's Track1Input schema.
        """
        # Step 1: Parse URL topology
        parsed: ParsedURL = parse_url(raw_url)

        # Step 2: Extract structural & lexical features
        features: URLFeatures = extract_features(parsed)

        # Step 3: Format tokens and encode to dense vector
        formatted_prompt = self.embedder.format_url_for_embedding(
            raw_url=parsed.raw_url,
            domain=parsed.domain,
            subdomains=parsed.subdomains,
            path=parsed.path
        )
        query_vector = self.embedder.encode(formatted_prompt)

        # Step 4: Compute unsupervised k-NN anomaly score
        scoring: ScoringResult = self.scorer.score(query_vector)

        # Step 5: Format according to the team's agreed schema
        payload = {
            "raw_url": parsed.raw_url,
            "domain": parsed.domain,
            "subdomains": parsed.subdomains,
            "features": features.to_dict(),
            "knn_distance": scoring.knn_distance,
            "anomaly_score": scoring.anomaly_score,
            "is_anomaly": scoring.is_anomaly
        }
        return payload

    def analyze_batch(self, raw_urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyzes a batch of URLs with optimized vectorized embedding and scoring.
        """
        if not raw_urls:
            return []

        # Parse all
        parsed_list = [parse_url(u) for u in raw_urls]
        features_list = [extract_features(p) for p in parsed_list]

        # Format inputs
        prompts = [
            self.embedder.format_url_for_embedding(
                raw_url=p.raw_url,
                domain=p.domain,
                subdomains=p.subdomains,
                path=p.path
            )
            for p in parsed_list
        ]

        # Batch encode
        query_vectors = self.embedder.encode(prompts)

        # Batch score
        scoring_results = self.scorer.score_batch(query_vectors)

        outputs = []
        for p, feat, sc in zip(parsed_list, features_list, scoring_results):
            outputs.append({
                "raw_url": p.raw_url,
                "domain": p.domain,
                "subdomains": p.subdomains,
                "features": feat.to_dict(),
                "knn_distance": sc.knn_distance,
                "anomaly_score": sc.anomaly_score,
                "is_anomaly": sc.is_anomaly
            })
        return outputs


# Singleton engine instance for fast reuse
_default_engine = None


def get_default_engine() -> VectorAnomalyEngine:
    global _default_engine
    if _default_engine is None:
        _default_engine = VectorAnomalyEngine()
    return _default_engine


def analyze_url(url: str) -> Dict[str, Any]:
    """Convenience function matching Track 1 standalone entrypoint."""
    return get_default_engine().analyze_url(url)


def analyze_batch(urls: List[str]) -> List[Dict[str, Any]]:
    """Convenience function matching Track 1 batch entrypoint."""
    return get_default_engine().analyze_batch(urls)


def main():
    parser = argparse.ArgumentParser(
        description="Track 1: Vector Space Anomaly Detection for Phishing URL Intelligence"
    )
    parser.add_argument("--url", type=str, help="Single URL to analyze")
    parser.add_argument("--batch", nargs="+", help="Multiple URLs to analyze")
    parser.add_argument("--file", type=str, help="Path to text or CSV file containing URLs (one per line)")
    parser.add_argument("--threshold", type=float, default=0.50, help="Anomaly decision threshold [0.0 - 1.0]")
    parser.add_argument("--k", type=int, default=5, help="Number of nearest neighbors to query")

    args = parser.parse_args()
    engine = VectorAnomalyEngine(k=args.k, threshold=args.threshold)

    if args.url:
        result = engine.analyze_url(args.url)
        print(json.dumps(result, indent=2))
    elif args.batch:
        results = engine.analyze_batch(args.batch)
        print(json.dumps(results, indent=2))
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = engine.analyze_batch(lines)
        print(json.dumps(results, indent=2))
    else:
        # Default self-test demonstration
        demo_urls = [
            "https://accounts.google.com/signin",
            "http://paypal-login.security-verify.com/auth",
            "http://192.168.1.50/admin-login.php",
            "https://github.com/login"
        ]
        print("\n=== Track 1 Demonstration Run ===")
        results = engine.analyze_batch(demo_urls)
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
