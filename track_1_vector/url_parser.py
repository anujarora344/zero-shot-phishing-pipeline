"""
Track 1: URL Topology & Lexical Parser
Author: Track 1 Lead
Purpose:
    Deconstructs raw URL strings into standardized structural components
    (scheme, host, apex domain, subdomains, path, query parameters)
    and computes initial lexical statistics.
"""

from dataclasses import dataclass, field
import ipaddress
import math
import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, unquote


# Common multi-part public suffixes to enable accurate apex domain extraction
# without hard dependencies on network requests.
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "co.in", "net.in", "org.in", "gov.in", "gen.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.br", "org.br", "net.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.sg", "edu.sg", "gov.sg",
    "com.mx", "org.mx", "edu.mx",
    "co.kr", "ne.kr", "re.kr",
    "com.tr", "edu.tr", "gov.tr"
}


@dataclass
class ParsedURL:
    """Standardized structured representation of a parsed URL."""
    raw_url: str
    normalized_url: str
    scheme: str
    host: str
    domain: str
    subdomains: List[str] = field(default_factory=list)
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    query_params: dict = field(default_factory=dict)
    fragment: str = ""
    has_ip_host: bool = False
    is_https: bool = False
    is_punycode: bool = False
    entropy: float = 0.0


def compute_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
    Higher entropy indicates random/obfuscated character distributions,
    frequently seen in algorithmic domain generation (DGA) or phishing paths.
    """
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def is_ip_address(host: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def extract_domain_and_subdomains(host: str) -> tuple[str, List[str]]:
    """
    Splits hostname into (apex_domain, subdomains_list).
    Example:
        'paypal-login.security-verify.com' -> ('security-verify.com', ['paypal-login'])
        'accounts.google.com'              -> ('google.com', ['accounts'])
        'www.github.com'                   -> ('github.com', [])
    """
    if not host:
        return "", []

    # Strip port if present in host string
    clean_host = host.split(":")[0].lower().strip(".")

    # If the host is an IP address, domain is the IP itself
    if is_ip_address(clean_host):
        return clean_host, []

    parts = clean_host.split(".")
    if len(parts) <= 1:
        return clean_host, []

    # Check for multi-part TLD match (e.g. co.uk)
    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in MULTI_PART_TLDS:
        apex_domain = ".".join(parts[-3:])
        subdomain_parts = parts[:-3]
    else:
        apex_domain = ".".join(parts[-2:])
        subdomain_parts = parts[:-2]

    # Filter out common benign prefixes like 'www' from subdomains
    subdomains = [s for s in subdomain_parts if s and s != "www"]
    return apex_domain, subdomains


def parse_url(url: str) -> ParsedURL:
    """
    Main URL topology parser. Handles missing schemes, edge cases,
    and returns a structured ParsedURL dataclass.
    """
    if not url or not isinstance(url, str):
        return ParsedURL(
            raw_url=str(url),
            normalized_url="",
            scheme="",
            host="",
            domain="",
            subdomains=[]
        )

    clean_input = url.strip()
    
    # Prepend scheme if missing so urllib parses correctly
    if "://" not in clean_input:
        working_url = "http://" + clean_input
        inferred_scheme = False
    else:
        working_url = clean_input
        inferred_scheme = True

    try:
        parsed = urlparse(working_url)
    except Exception:
        # Fallback for malformed URLs
        return ParsedURL(
            raw_url=clean_input,
            normalized_url=clean_input.lower(),
            scheme="",
            host="",
            domain=clean_input.split("/")[0],
            subdomains=[]
        )

    scheme = parsed.scheme.lower() if inferred_scheme else ""
    is_https = scheme == "https"
    
    raw_host = parsed.netloc or parsed.path.split("/")[0]
    # Remove authentication credentials if present (e.g. user:pass@host)
    if "@" in raw_host:
        raw_host = raw_host.split("@")[-1]

    host = raw_host.lower().strip()
    port = parsed.port
    clean_hostname = host.split(":")[0] if ":" in host else host

    domain, subdomains = extract_domain_and_subdomains(clean_hostname)
    path = parsed.path
    query = parsed.query
    query_params = parse_qs(query) if query else {}
    fragment = parsed.fragment

    has_ip = is_ip_address(clean_hostname)
    is_puny = "xn--" in host.lower()
    entropy = compute_shannon_entropy(clean_input)

    normalized_url = f"{scheme + '://' if scheme else ''}{host}{path}"
    if query:
        normalized_url += f"?{query}"

    return ParsedURL(
        raw_url=clean_input,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host,
        domain=domain,
        subdomains=subdomains,
        port=port,
        path=path,
        query=query,
        query_params=query_params,
        fragment=fragment,
        has_ip_host=has_ip,
        is_https=is_https,
        is_punycode=is_puny,
        entropy=entropy
    )
