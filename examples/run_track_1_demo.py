"""
Track 1: End-to-End Demonstration & Integration Verification
Author: Track 1 Lead
Usage:
    python examples/run_track_1_demo.py
"""

import json
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from track_1_vector.anomaly_engine import VectorAnomalyEngine
from track_2_agentic.schemas import Track1Input


def main():
    print("=" * 70)
    print(" ZERO-SHOT & UNSUPERVISED PHISHING URL INTELLIGENCE PIPELINE ")
    print(" TRACK 1: Vector Space Anomaly Detection Demonstration ")
    print("=" * 70)

    # Initialize Track 1 engine
    engine = VectorAnomalyEngine(threshold=0.50, k=5)

    test_urls = [
        # Benign reference alignment
        ("Benign Trusted (Google)", "https://accounts.google.com/signin"),
        ("Benign Trusted (GitHub)", "https://github.com/login"),
        # Brand impersonation & subdomain misdirection
        ("Phishing (PayPal Spoof)", "http://paypal-login.security-verify.com/auth"),
        ("Phishing (AppleID Spoof)", "http://appleid-verify-account.com/login"),
        # Raw IP address hostname
        ("Suspicious (Raw IP Host)", "http://192.168.1.100:8080/admin/login.php"),
        # Complex multi-subdomain with long path
        ("Obfuscated (Multi-Subdomain)", "http://secure.banking.update.account-service.net/portal/verify?client_id=88412")
    ]

    print("\n[+] Running Track 1 Vector Space Anomaly Scoring:\n")

    for category, url in test_urls:
        print(f"--- Testing: {category} ---")
        print(f"Target URL: {url}")
        
        # Track 1 Analysis
        result = engine.analyze_url(url)
        
        # Verify cross-track contract compliance with Track 2 Pydantic schema
        validated_contract = Track1Input(**result)
        
        print(f"Apex Domain:    {result['domain']}")
        print(f"Subdomains:     {result['subdomains']}")
        print(f"k-NN Distance:  {result['knn_distance']:.4f}")
        print(f"Anomaly Score:  {result['anomaly_score']:.4f}")
        print(f"Is Anomaly:     {result['is_anomaly']}")
        print(f"Features:       Entropy={result['features']['entropy']}, Digits={result['features']['digit_count']}, Hyphens={result['features']['hyphen_count']}, IP_Host={result['features']['has_ip_host']}")
        print(f"[Schema Check]: Successfully validated by Track 2 Pydantic model 'Track1Input'.\n")

    print("=" * 70)
    print("Demonstration completed successfully with 100% schema validation.")
    print("=" * 70)


if __name__ == "__main__":
    main()
