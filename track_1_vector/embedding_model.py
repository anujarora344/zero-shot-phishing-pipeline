"""
Track 1: Dense Vector Embedding Engine
Author: Track 1 Lead
Purpose:
    Transforms URL strings and topological tokens into dense vector representations.
    Supports SentenceTransformer ('all-MiniLM-L6-v2') as primary transformer backend
    with an automatic, deterministic subword n-gram dense projection fallback.
"""

import hashlib
import logging
import math
from typing import List, Union
import numpy as np

logger = logging.getLogger("Track1-Embedder")

DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384  # Standard MiniLM embedding dimensionality


class URLEmbedder:
    """
    Modular URL embedding generator.
    
    Why all-MiniLM-L6-v2?
    - Produces compact 384-dimensional dense vector embeddings.
    - Highly fast CPU inference (<15ms per sample), ideal for real-time URL inspection.
    - Captures semantic token proximity (e.g. associating words like 'login', 'account',
      'verify', 'secure' with distinct spatial clusters).
      
    What the embedding captures vs what it does NOT:
    - Captures: Lexical token similarities, brand keywords, token arrangements, and path semantics.
    - Does NOT capture: Real-time DNS registration status, whether the server is active,
      or direct malicious intent. Embeddings reflect topological/semantic distribution,
      NOT ground-truth maliciousness.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME, prefer_fallback: bool = False):
        self.model_name = model_name
        self.embedding_dim = EMBEDDING_DIM
        self._backend = "uninitialized"
        self._model = None

        if not prefer_fallback:
            self._try_load_sentence_transformer()
        
        if self._model is None:
            self._init_deterministic_fallback()

    def _try_load_sentence_transformer(self):
        """Attempts to load sentence-transformers without crashing if missing."""
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading SentenceTransformer: {self.model_name}...")
            self._model = SentenceTransformer(self.model_name)
            self._backend = f"sentence_transformers:{self.model_name}"
            logger.info("SentenceTransformer loaded successfully.")
        except Exception as e:
            logger.warning(
                f"SentenceTransformer ({self.model_name}) could not be initialized ({e}). "
                "Engaging deterministic dense subword fallback engine."
            )
            self._model = None

    def _init_deterministic_fallback(self):
        """
        Initializes an offline, zero-dependency deterministic dense projection.
        Maps character and subword n-grams into a unit-normalized 384-dimensional
        vector using stable cryptographic hashing (Murmur/MD5 projection).
        Ensures zero-crash reproducibility in all test, CI, and offline environments.
        """
        self._backend = "deterministic_dense_ngram_projection (384-dim)"
        logger.info("Using deterministic dense n-gram embedding fallback.")

    @property
    def backend(self) -> str:
        """Returns the active backend descriptor."""
        return self._backend

    def format_url_for_embedding(self, raw_url: str, domain: str = "", subdomains: List[str] = None, path: str = "") -> str:
        """
        Synthesizes structured URL tokens for language model consumption.
        URLs are not natural sentences; explicit token prefixes help transformer
        tokenizers attend to brand, subdomain misdirection, and endpoint keywords.
        """
        subdomain_str = " ".join(subdomains) if subdomains else "none"
        clean_path = path.replace("/", " ").replace("-", " ").replace("_", " ").strip()
        
        return (
            f"url: {raw_url} | "
            f"domain: {domain} | "
            f"subdomains: {subdomain_str} | "
            f"path: {clean_path}"
        )

    def _deterministic_encode_single(self, text: str) -> np.ndarray:
        """
        Maps a text string to a 384-dim unit vector via n-gram hash projections.
        Tokens that share substrings (e.g. 'paypal-login' vs 'paypal-auth')
        activate correlated vector components, preserving geometric similarity.
        """
        vec = np.zeros(self.embedding_dim, dtype=np.float32)
        if not text:
            return vec

        # Extract character n-grams of sizes 3, 4, and 5 + whitespace tokens
        tokens = [text] + text.lower().split()
        ngrams = list(tokens)
        for n in (3, 4, 5):
            for i in range(len(text) - n + 1):
                ngrams.append(text[i:i+n])

        for gram in ngrams:
            # Produce 2 deterministic hashes for pseudo-random projection indices
            h1 = int(hashlib.md5(gram.encode("utf-8")).hexdigest(), 16)
            idx1 = h1 % self.embedding_dim
            sign1 = 1.0 if ((h1 >> 16) & 1) else -1.0
            vec[idx1] += sign1

            h2 = int(hashlib.sha256(gram.encode("utf-8")).hexdigest()[:16], 16)
            idx2 = h2 % self.embedding_dim
            sign2 = 1.0 if ((h2 >> 16) & 1) else -1.0
            vec[idx2] += sign2 * 0.5

        # L2-normalize to unit hypersphere
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec = vec / norm
        return vec

    def encode(self, texts: Union[str, List[str]]) -> np.ndarray:
        """
        Generates dense vector embeddings for input text(s).
        Returns:
            np.ndarray of shape (N, 384) with float32 dtype.
        """
        is_single = isinstance(texts, str)
        text_list = [texts] if is_single else list(texts)

        if not text_list:
            return np.empty((0, self.embedding_dim), dtype=np.float32)

        if self._model is not None and "sentence_transformers" in self._backend:
            try:
                embeddings = self._model.encode(
                    text_list,
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False
                )
                return embeddings[0] if is_single else embeddings
            except Exception as e:
                logger.warning(f"Inference error with transformer: {e}. Falling back to deterministic.")

        # Fallback path
        encoded = np.array([self._deterministic_encode_single(t) for t in text_list], dtype=np.float32)
        return encoded[0] if is_single else encoded
