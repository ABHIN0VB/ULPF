from typing import Optional

IOC_IPS = {
    '192.168.1.1': {'category': 'malware', 'confidence': 'high'},
    '203.0.113.5': {'category': 'c2', 'confidence': 'high'},
}

IOC_DOMAINS = {
    'evil.com': {'category': 'phishing', 'confidence': 'high'},
}

def check_ip(ip: str) -> Optional[dict]:
    if ip in IOC_IPS:
        return {
            'matched': True,
            'feed': 'demo-threat-feed',
            'category': IOC_IPS[ip]['category'],
            'confidence': IOC_IPS[ip]['confidence']
        }
    return None

def check_domain(domain: str) -> Optional[dict]:
    if domain in IOC_DOMAINS:
        return {
            'matched': True,
            'feed': 'demo-threat-feed',
            'category': IOC_DOMAINS[domain]['category'],
            'confidence': IOC_DOMAINS[domain]['confidence']
        }
    return None
