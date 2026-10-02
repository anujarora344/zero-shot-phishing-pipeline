# track_2_agentic/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional

class Track1Input(BaseModel):
    raw_url: str
    domain: str
    subdomains: List[str]
    features: dict
    knn_distance: float
    anomaly_score: float
    is_anomaly: bool

class AgenticThreatAnalysis(BaseModel):
    verdict: str = Field(description="Must be 'PHISHING', 'BENIGN', or 'SUSPICIOUS'")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    impersonated_brand: Optional[str] = Field(default=None, description="Target brand if spoofing is detected")
    reasoning_chain: List[str] = Field(description="Step-by-step Chain-of-Thought observations")
    threat_indicators: List[str] = Field(description="List of detected anomalies like Typosquatting or Brand Impersonation")