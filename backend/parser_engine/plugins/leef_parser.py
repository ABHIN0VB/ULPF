import re
from parser_engine.base_parser import BaseParser

class LEEFParser(BaseParser):
    SOURCE_ID = "leef"
    PRIORITY = 10

    def __init__(self):
        # LEEF:Version|Vendor|Product|Version|EventID|key=value\tkey=value
        self.header_pattern = re.compile(r'^LEEF:(?P<version>[^|]+)\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<dev_version>[^|]+)\|(?P<event_id>[^|]+)(?:\|(?P<attributes>.*))?$')

    def can_parse(self, raw: str, metadata: dict) -> float:
        if raw.startswith('LEEF:'):
            return 0.95
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        match = self.header_pattern.match(raw)
        if not match:
            return {}
            
        parsed = match.groupdict()
        attributes = parsed.pop('attributes', None)
        
        if attributes:
            parts = attributes.split('\t')
            for part in parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    parsed[k] = v
                    
        return parsed
