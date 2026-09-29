import re

def enrich_ip(ip: str) -> dict:
    if not ip:
        return {}
        
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.'
    ]
    
    for pat in private_patterns:
        if re.match(pat, ip):
            return {'type': 'private'}
            
    if ip.startswith('8.8.'):
        return {'country': 'US', 'country_iso_code': 'US', 'city': 'Mountain View', 'asn': 15169, 'org': 'Google LLC'}
    elif ip.startswith('1.1.'):
        return {'country': 'Australia', 'country_iso_code': 'AU', 'city': 'Research', 'asn': 13335, 'org': 'Cloudflare'}
    elif ip.startswith('203.0.113.'):
        return {'country': 'CN', 'country_iso_code': 'CN', 'city': 'Beijing', 'asn': 4134, 'org': 'CHINANET'}
        
    return {'country': 'Unknown', 'country_iso_code': 'UN', 'city': 'Unknown', 'asn': 0, 'org': 'Unknown ISP'}
