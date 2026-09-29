import re
import ipaddress
from typing import Dict, Any, List, Tuple

class UESValidator:
    """
    Validates normalized events against the Universal Event Schema (UES) v1.0
    and calculates data quality metrics.
    """
    CORE_FIELDS = [
        'event.action',
        'event.outcome',
        'event.severity',
        'source.ip',
        'destination.ip',
        'network.protocol'
    ]

    @classmethod
    def validate_and_score(cls, ues: Dict[str, Any], parse_confidence: float = 1.0) -> Tuple[bool, List[str], float]:
        """
        Validates event and returns:
        (is_valid: bool, errors: List[str], field_completeness: float)
        """
        errors: List[str] = []

        # 1. Mandatory ULPF metadata
        ulpf = ues.get('ulpf', {})
        if not ulpf.get('id'):
            errors.append("Missing ulpf.id")
        if not ulpf.get('raw'):
            errors.append("Missing ulpf.raw (lossless raw log required)")
        if not ulpf.get('raw_hash'):
            errors.append("Missing ulpf.raw_hash")

        # 2. Event section validation
        event = ues.get('event', {})
        outcome = event.get('outcome')
        if outcome not in ['success', 'failure', 'unknown']:
            errors.append(f"Invalid event.outcome: '{outcome}'. Must be success, failure, or unknown.")
        
        severity = event.get('severity')
        if severity is not None:
            if not isinstance(severity, int) or severity < 0 or severity > 10:
                errors.append(f"Invalid event.severity: '{severity}'. Must be integer 0-10.")

        # 3. Source & Destination IP/Port validation
        src = ues.get('source', {})
        src_ip = src.get('ip')
        if src_ip:
            if not cls._is_valid_ip(src_ip):
                errors.append(f"Invalid source.ip format: '{src_ip}'")
        
        src_port = src.get('port')
        if src_port is not None:
            if not (isinstance(src_port, int) and 1 <= src_port <= 65535):
                errors.append(f"Invalid source.port: '{src_port}'. Must be 1-65535.")

        dst = ues.get('destination', {})
        dst_ip = dst.get('ip')
        if dst_ip:
            if not cls._is_valid_ip(dst_ip):
                errors.append(f"Invalid destination.ip format: '{dst_ip}'")

        dst_port = dst.get('port')
        if dst_port is not None:
            if not (isinstance(dst_port, int) and 1 <= dst_port <= 65535):
                errors.append(f"Invalid destination.port: '{dst_port}'. Must be 1-65535.")

        # 4. Field completeness score
        present_count = 0
        for f in cls.CORE_FIELDS:
            parts = f.split('.')
            val = ues
            found = True
            for p in parts:
                if isinstance(val, dict) and p in val and val[p] is not None and val[p] != "":
                    val = val[p]
                else:
                    found = False
                    break
            if found:
                present_count += 1
                
        field_completeness = round(present_count / len(cls.CORE_FIELDS), 2)
        is_valid = len(errors) == 0

        return is_valid, errors, field_completeness

    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False
