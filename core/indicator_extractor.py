import re
from datetime import datetime

IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,10}\b')
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&\'\(\)\*\+,;=%]+')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
HASH_SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
HASH_MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')

# Exclude obvious false positive domain endings or local domains
IGNORED_DOMAINS = {"w3.org", "schema.org", "example.com", "localhost", "local", "internal", "schemas.microsoft.com"}

def extract_indicators_from_text(text: str, source_evidence_id: int = None, case_id: int = None) -> list[dict]:
    """
    Extracts forensic indicators (IOCs) from text content.
    Returns normalized indicator records.
    """
    extracted = []
    seen = set()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # 1. URLs
    urls = URL_REGEX.findall(text)
    for u in set(urls):
        if u not in seen:
            seen.add(u)
            extracted.append({
                "case_id": case_id,
                "evidence_id": source_evidence_id,
                "indicator_value": u,
                "indicator_type": "URL",
                "first_seen": now_str,
                "last_seen": now_str,
                "occurrence_count": text.count(u),
                "tags": "Network, URL",
                "notes": "Extracted from forensic artifact stream"
            })

    # 2. IP Addresses
    ips = IP_REGEX.findall(text)
    for ip in set(ips):
        if ip.startswith("0.") or ip == "255.255.255.255" or ip.startswith("127.0.0."):
            continue
        if ip not in seen:
            seen.add(ip)
            is_internal = ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
            tag = "Private IP" if is_internal else "External IP, Network"
            extracted.append({
                "case_id": case_id,
                "evidence_id": source_evidence_id,
                "indicator_value": ip,
                "indicator_type": "IP Address",
                "first_seen": now_str,
                "last_seen": now_str,
                "occurrence_count": text.count(ip),
                "tags": tag,
                "notes": f"Network address ({'Internal Subnet' if is_internal else 'Routable External'})"
            })

    # 3. Emails
    emails = EMAIL_REGEX.findall(text)
    for em in set(emails):
        if em not in seen:
            seen.add(em)
            extracted.append({
                "case_id": case_id,
                "evidence_id": source_evidence_id,
                "indicator_value": em,
                "indicator_type": "Email Address",
                "first_seen": now_str,
                "last_seen": now_str,
                "occurrence_count": text.count(em),
                "tags": "User Activity, Email",
                "notes": "Email identifier discovered in content"
            })

    # 4. Domains (standalone)
    domains = DOMAIN_REGEX.findall(text)
    for d in set(domains):
        clean_d = d.lower()
        if clean_d in IGNORED_DOMAINS or clean_d.endswith(".png") or clean_d.endswith(".exe") or clean_d.endswith(".dll") or clean_d.endswith(".sys"):
            continue
        if clean_d not in seen and not any(clean_d in u for u in urls):
            seen.add(clean_d)
            extracted.append({
                "case_id": case_id,
                "evidence_id": source_evidence_id,
                "indicator_value": clean_d,
                "indicator_type": "Domain",
                "first_seen": now_str,
                "last_seen": now_str,
                "occurrence_count": text.lower().count(clean_d),
                "tags": "Domain, Hostname",
                "notes": "Host domain referenced in forensic data"
            })

    return extracted
