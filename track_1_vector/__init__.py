"""
Track 1: Vector Space Anomaly Detection Package
"""

from track_1_vector.url_parser import parse_url, ParsedURL
from track_1_vector.feature_extractor import extract_features, URLFeatures
from track_1_vector.embedding_model import URLEmbedder
from track_1_vector.reference_store import ReferenceStore
from track_1_vector.anomaly_scorer import AnomalyScorer, ScoringResult

def get_engine():
    """Lazy importer for the master anomaly engine."""
    from track_1_vector.anomaly_engine import VectorAnomalyEngine
    return VectorAnomalyEngine()

__all__ = [
    "parse_url",
    "ParsedURL",
    "extract_features",
    "URLFeatures",
    "URLEmbedder",
    "ReferenceStore",
    "AnomalyScorer",
    "ScoringResult",
    "get_engine",
]
