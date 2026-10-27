"""
Track 1: Trusted Reference Store
Author: Track 1 Lead
Purpose:
    Manages the baseline index of verified, high-reputation root domains.
    Computes and caches dense reference vectors to serve as the benchmark
    manifold against which unknown URLs are compared.
"""

import csv
import logging
import os
from pathlib import Path
from typing import List, Optional
import numpy as np

from track_1_vector.embedding_model import URLEmbedder

logger = logging.getLogger("Track1-ReferenceStore")

# Core development fallback domains in case the dataset file is unreachable
FALLBACK_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "wikipedia.org", "netflix.com", "linkedin.com", "twitter.com",
    "instagram.com", "github.com", "cloudflare.com", "yahoo.com", "dropbox.com",
    "zoom.us", "salesforce.com", "adobe.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citi.com", "nytimes.com", "bbc.com",
    "cnn.com", "reddit.com", "spotify.com", "whatsapp.com", "office.com",
    "bing.com", "ebay.com", "walmart.com", "twitch.tv", "pinterest.com",
    "duckduckgo.com", "gitlab.com", "stackoverflow.com", "medium.com", "slack.com",
    "stripe.com", "shopify.com"
]


class ReferenceStore:
    """
    Stores and manages reference embeddings for trusted domains.
    
    Why index trusted domains rather than phishing URLs?
    - Benign Internet infrastructure has stable topological characteristics.
    - Attackers constantly craft new phishing variations, making a static 'bad list'
      obsolete within hours.
    - In unsupervised anomaly detection, the reference set defines the 'normal' manifold.
      Any URL falling outside this manifold exhibits Out-of-Distribution (OOD) properties.
    """

    def __init__(self, data_path: Optional[str] = None, embedder: Optional[URLEmbedder] = None):
        self.data_path = data_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "trusted_reference_domains.csv"
        )
        self.embedder = embedder or URLEmbedder()
        self.domains: List[str] = []
        self.vectors: np.ndarray = np.empty((0, self.embedder.embedding_dim), dtype=np.float32)
        
        self.load_reference_data()

    def load_reference_data(self):
        """Loads domain strings from CSV or falls back to built-in development list."""
        domains_loaded = []
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        domain = row.get("domain", "").strip().lower()
                        if domain and domain not in domains_loaded:
                            domains_loaded.append(domain)
                logger.info(f"Loaded {len(domains_loaded)} trusted domains from {self.data_path}")
            except Exception as e:
                logger.warning(f"Failed to read CSV at {self.data_path}: {e}. Using fallback list.")
        
        if not domains_loaded:
            domains_loaded = list(FALLBACK_DOMAINS)
            logger.info(f"Using {len(domains_loaded)} built-in trusted development domains.")

        self.domains = domains_loaded
        self._build_index()

    def _build_index(self):
        """Encodes all trusted domains into vector representations."""
        logger.info(f"Indexing {len(self.domains)} reference domains using backend: {self.embedder.backend}")
        formatted_inputs = [
            self.embedder.format_url_for_embedding(raw_url=f"https://{d}", domain=d)
            for d in self.domains
        ]
        self.vectors = self.embedder.encode(formatted_inputs)
        logger.info(f"Reference index built: shape {self.vectors.shape}")

    def size(self) -> int:
        """Returns the number of indexed reference domains."""
        return len(self.domains)
