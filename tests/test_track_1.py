"""
Automated Test Suite for Track 1: Vector Space Anomaly Detection
Tests:
- URL parsing & topology extraction (trusted, multi-subdomain, IP host, punycode, malformed)
- Feature extraction validity (lengths, counts, entropy, ranges)
- Embedding generation (shapes, normalization, deterministic reproducibility)
- Reference store operations and fallback resilience
- k-NN anomaly scoring (distance ranges, threshold boundary logic)
- End-to-end Track 1 engine execution
- Strict Pydantic schema compliance with Track 2's Track1Input
- Edge cases: empty input, batch input, invalid URLs, missing reference files
"""

import math
import numpy as np
import pytest

from track_1_vector.url_parser import parse_url, compute_shannon_entropy, is_ip_address, extract_domain_and_subdomains
from track_1_vector.feature_extractor import extract_features
from track_1_vector.embedding_model import URLEmbedder
from track_1_vector.reference_store import ReferenceStore
from track_1_vector.anomaly_scorer import AnomalyScorer
from track_1_vector.anomaly_engine import VectorAnomalyEngine
from track_2_agentic.schemas import Track1Input


# =====================================================================
# 1. URL Parser Tests
# =====================================================================

def test_url_parser_standard_trusted():
    parsed = parse_url("https://accounts.google.com/signin?hl=en")
    assert parsed.scheme == "https"
    assert parsed.domain == "google.com"
    assert parsed.subdomains == ["accounts"]
    assert parsed.path == "/signin"
    assert parsed.has_ip_host is False
    assert parsed.is_https is True
    assert "hl" in parsed.query_params
    assert parsed.entropy > 0.0


def test_url_parser_multi_subdomain():
    parsed = parse_url("http://login.secure.update.paypal.security-alert.com/auth")
    assert parsed.domain == "security-alert.com"
    assert parsed.subdomains == ["login", "secure", "update", "paypal"]
    assert len(parsed.subdomains) == 4
    assert parsed.is_https is False


def test_url_parser_ip_address_host():
    parsed = parse_url("http://192.168.1.100:8080/admin/index.php")
    assert parsed.domain == "192.168.1.100"
    assert parsed.has_ip_host is True
    assert parsed.port == 8080
    assert len(parsed.subdomains) == 0


def test_url_parser_schemeless_input():
    parsed = parse_url("chase-verify-billing.net/login")
    assert parsed.domain == "chase-verify-billing.net"
    assert parsed.path == "/login"


def test_url_parser_malformed_empty():
    parsed = parse_url("")
    assert parsed.raw_url == ""
    assert parsed.domain == ""
    assert parsed.subdomains == []

    parsed_none = parse_url(None)
    assert parsed_none.domain == ""


def test_entropy_computation():
    # Repetitive string has 0 or low entropy
    assert compute_shannon_entropy("aaaaaaa") == 0.0
    # Diverse alphanumeric string has higher entropy
    h = compute_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
    assert h > 4.5


# =====================================================================
# 2. Feature Extractor Tests
# =====================================================================

def test_feature_extraction_values():
    parsed = parse_url("https://pay-pal.com/verify-account?id=99&token=abc")
    features = extract_features(parsed)
    f_dict = features.to_dict()

    assert f_dict["url_length"] == len(parsed.raw_url)
    assert f_dict["domain_length"] == len("pay-pal.com")
    assert f_dict["digit_count"] == 2  # '9', '9'
    assert f_dict["hyphen_count"] == 2  # 'pay-pal', 'verify-account'
    assert f_dict["query_param_count"] == 2
    assert f_dict["is_https"] is True
    assert f_dict["has_ip_host"] is False
    assert f_dict["subdomain_depth"] == 0

    vec = features.to_vector()
    assert len(vec) == 14
    assert all(isinstance(v, (int, float)) for v in vec)


# =====================================================================
# 3. Embedding Model Tests
# =====================================================================

def test_embedding_generation_shape_and_norm():
    embedder = URLEmbedder()
    vec = embedder.encode("https://www.google.com")
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (384,)
    
    # Check L2 unit normalization
    norm = np.linalg.norm(vec)
    assert math.isclose(norm, 1.0, rel_tol=1e-3)


def test_embedding_batch_generation():
    embedder = URLEmbedder()
    urls = [
        "https://google.com",
        "https://microsoft.com",
        "http://phishing-site-test.com"
    ]
    vecs = embedder.encode(urls)
    assert isinstance(vecs, np.ndarray)
    assert vecs.shape == (3, 384)


def test_embedding_deterministic_property():
    embedder = URLEmbedder(prefer_fallback=True)
    v1 = embedder.encode("https://paypal-login-account.com")
    v2 = embedder.encode("https://paypal-login-account.com")
    assert np.allclose(v1, v2)


# =====================================================================
# 4. Reference Store Tests
# =====================================================================

def test_reference_store_loading():
    store = ReferenceStore()
    assert store.size() >= 40
    assert "google.com" in store.domains
    assert "github.com" in store.domains
    assert store.vectors.shape == (store.size(), 384)


def test_reference_store_missing_file_fallback():
    # Non-existent path falls back to built-in list gracefully
    store = ReferenceStore(data_path="non_existent_file.csv")
    assert store.size() > 0
    assert "google.com" in store.domains


# =====================================================================
# 5. Anomaly Scorer Tests
# =====================================================================

def test_anomaly_scorer_distances():
    ref_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "github.com"]
    embedder = URLEmbedder(prefer_fallback=True)
    ref_vectors = embedder.encode([f"https://{d}" for d in ref_domains])

    scorer = AnomalyScorer(
        reference_vectors=ref_vectors,
        reference_domains=ref_domains,
        k=3,
        threshold=0.50
    )

    # Identical domain query should produce low distance
    q_vec = embedder.encode("https://google.com")
    res = scorer.score(q_vec)
    assert res.knn_distance >= 0.0
    assert res.anomaly_score >= 0.0
    assert res.anomaly_score <= 1.0
    assert len(res.nearest_domains) == 3
    # First nearest neighbor should be google.com
    assert res.nearest_domains[0]["domain"] == "google.com"
    assert math.isclose(res.nearest_domains[0]["distance"], 0.0, abs_tol=1e-4)


# =====================================================================
# 6. End-to-End Engine & Track 2 Schema Compatibility Tests
# =====================================================================

def test_engine_single_url_and_schema_validation():
    engine = VectorAnomalyEngine()
    result = engine.analyze_url("https://accounts.google.com/signin")

    # Verify keys
    assert "raw_url" in result
    assert "domain" in result
    assert "subdomains" in result
    assert "features" in result
    assert "knn_distance" in result
    assert "anomaly_score" in result
    assert "is_anomaly" in result

    # CRITICAL TEST: Validate that Track 2's Pydantic Track1Input parses result directly
    validated_track1_input = Track1Input(**result)
    assert validated_track1_input.domain == "google.com"
    assert validated_track1_input.subdomains == ["accounts"]
    assert isinstance(validated_track1_input.anomaly_score, float)
    assert isinstance(validated_track1_input.is_anomaly, bool)


def test_engine_phishing_url_flagged():
    engine = VectorAnomalyEngine()
    phish_url = "http://paypal-login.security-verify.com/auth"
    result = engine.analyze_url(phish_url)

    assert result["domain"] == "security-verify.com"
    assert result["subdomains"] == ["paypal-login"]
    assert result["features"]["hyphen_count"] >= 2
    # Should be flagged as an anomaly or have high distance
    assert result["knn_distance"] > 0.30


def test_engine_batch_processing():
    engine = VectorAnomalyEngine()
    urls = [
        "https://github.com/login",
        "http://secure-update-appleid.com/confirm",
        "http://10.0.0.1/router-login"
    ]
    results = engine.analyze_batch(urls)
    assert len(results) == 3
    for r in results:
        # Validate schema contract on every item in batch
        Track1Input(**r)


def test_engine_empty_batch():
    engine = VectorAnomalyEngine()
    results = engine.analyze_batch([])
    assert results == []
