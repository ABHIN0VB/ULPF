import re
from parser_engine.base_parser import BaseParser

class FWXParser(BaseParser):
    """Parser for proprietary FWX Perimeter Firewalls."""
    SOURCE_ID = "fwx"
    VERSION = "1.0.0"
    PRIORITY = 20

    def can_parse(self, raw: str, metadata: dict) -> float:
        if raw.startswith("FWX|"):
            return 0.95
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        parts = raw.strip().split('|')
        parsed = {"vendor": "FWX"}
        if len(parts) >= 2:
            parsed["timestamp"] = parts[1]
        for p in parts[2:]:
            if '=' in p:
                k, v = p.split('=', 1)
                parsed[k.lower()] = v
        return parsed
