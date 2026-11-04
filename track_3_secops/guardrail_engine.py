import base64
import re
from urllib.parse import urlparse, parse_qs, unquote


MALICIOUS_KEYWORDS = [
    "ignore", 
    "override", 
    "system", 
    "instruction", 
    "respond", 
    "only", 
    "threat_level"
]

def scan_for_base64_injection(url: str) -> dict:
    """
    Scans a URL for both URL-encoded and Base64-encoded prompt injections.
    Returns the audit results matching the Track 3 schema.
    """
    audit_result = {
        "indirect_prompt_injection_detected": False,
        "sanitized_payload": url,
        "payload_decoded": False
    }

    
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    
    for param, values in query_params.items():
        for value in values:
            
            
            decoded_url_text = unquote(value).lower()
            if any(keyword in decoded_url_text for keyword in MALICIOUS_KEYWORDS):
                audit_result["indirect_prompt_injection_detected"] = True
                
                safe_url = url.replace(f"{param}={value}", f"{param}=REDACTED")
                audit_result["sanitized_payload"] = safe_url
                return audit_result

            
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value) and len(value) > 10:
                try:
                    decoded_bytes = base64.b64decode(value)
                    decoded_text = decoded_bytes.decode('utf-8').lower()
                    audit_result["payload_decoded"] = True

                    if any(keyword in decoded_text for keyword in MALICIOUS_KEYWORDS):
                        audit_result["indirect_prompt_injection_detected"] = True
                        safe_url = url.replace(f"{param}={value}", f"{param}=REDACTED")
                        audit_result["sanitized_payload"] = safe_url
                        return audit_result
                        
                except Exception:
                    pass

    return audit_result