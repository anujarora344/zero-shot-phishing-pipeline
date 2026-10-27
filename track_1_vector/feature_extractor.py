"""
Track 1: Structural & Lexical Feature Extractor
Author: Track 1 Lead
Purpose:
    Extracts numerical and categorical features from a ParsedURL object.
    These features feed both the statistical anomaly scoring and the
    cross-track JSON interface for Track 2 (Agentic Threat Engine).
"""

from dataclasses import asdict, dataclass
import re
from typing import Dict, Any, List
from track_1_vector.url_parser import ParsedURL


# Characters often manipulated in deceptive or payload-bearing URLs
SUSPICIOUS_CHARS = set("@-_=/?&%#.~+;:")


@dataclass
class URLFeatures:
    """Structured container for lexical and structural features."""
    entropy: float
    subdomain_depth: int
    has_ip_host: bool
    path_length: int
    url_length: int
    domain_length: int
    special_char_count: int
    digit_count: int
    hyphen_count: int
    subdomain_length: int
    path_depth: int
    query_param_count: int
    is_https: bool
    is_punycode: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert features to JSON-serializable dictionary."""
        return asdict(self)

    def to_vector(self) -> List[float]:
        """Convert key numerical features to an ordered numerical vector."""
        return [
            float(self.entropy),
            float(self.subdomain_depth),
            1.0 if self.has_ip_host else 0.0,
            float(self.path_length),
            float(self.url_length),
            float(self.domain_length),
            float(self.special_char_count),
            float(self.digit_count),
            float(self.hyphen_count),
            float(self.subdomain_length),
            float(self.path_depth),
            float(self.query_param_count),
            1.0 if self.is_https else 0.0,
            1.0 if self.is_punycode else 0.0
        ]


def extract_features(parsed: ParsedURL) -> URLFeatures:
    """
    Computes structural, topological, and lexical metrics from a ParsedURL.
    
    Decision rationale:
    - entropy: Captures obfuscated or algorithmically generated strings.
    - subdomain_depth: Phishing URLs frequently hide brand names in subdomains
      (e.g., login.chase.com.evil-domain.com).
    - has_ip_host: Legitimate major services almost never use raw IPs in public links.
    - hyphen_count: Phishing domains heavily rely on hyphens (e.g., paypal-account-verify).
    - path_length & special_char_count: Indicators of obfuscated redirects or encoded payloads.
    """
    raw_url = parsed.raw_url
    host = parsed.host
    path = parsed.path
    subdomains = parsed.subdomains

    url_length = len(raw_url)
    domain_length = len(parsed.domain)
    path_length = len(path)
    subdomain_depth = len(subdomains)
    subdomain_length = sum(len(s) for s in subdomains)

    # Count path segments (depth)
    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)

    # Count digits in entire URL
    digit_count = sum(1 for c in raw_url if c.isdigit())

    # Count hyphens in URL (classic brand typosquatting signal)
    hyphen_count = raw_url.count("-")

    # Count suspicious special characters
    special_char_count = sum(1 for c in raw_url if c in SUSPICIOUS_CHARS)

    # Query param count
    query_param_count = len(parsed.query_params)

    return URLFeatures(
        entropy=parsed.entropy,
        subdomain_depth=subdomain_depth,
        has_ip_host=parsed.has_ip_host,
        path_length=path_length,
        url_length=url_length,
        domain_length=domain_length,
        special_char_count=special_char_count,
        digit_count=digit_count,
        hyphen_count=hyphen_count,
        subdomain_length=subdomain_length,
        path_depth=path_depth,
        query_param_count=query_param_count,
        is_https=parsed.is_https,
        is_punycode=parsed.is_punycode
    )
