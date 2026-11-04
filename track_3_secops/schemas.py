from pydantic import BaseModel
from typing import List, Optional


class Track2Response(BaseModel):
    raw_url: str
    track1_ref: dict
    verdict: str
    confidence: float
    impersonated_brand: Optional[str] = None
    reasoning_chain: List[str]
    threat_indicators: List[str]


class SecurityAudit(BaseModel):
    indirect_prompt_injection_detected: bool
    sanitized_payload: str
    payload_decoded: bool


class Track3FinalResponse(BaseModel):
    pipeline_timestamp: str
    raw_url: str
    security_audit: SecurityAudit
    analysis: dict  