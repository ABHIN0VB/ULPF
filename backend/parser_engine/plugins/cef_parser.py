import re
from parser_engine.base_parser import BaseParser

class CEFParser(BaseParser):
    SOURCE_ID = "cef"
    PRIORITY = 10

    def __init__(self):
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        self.header_pattern = re.compile(r'^CEF:(?P<version>[^|]+)\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<dev_version>[^|]+)\|(?P<event_class_id>[^|]+)\|(?P<name>[^|]+)\|(?P<severity>[^|]+)(?:\|(?P<extension>.*))?$')

    def can_parse(self, raw: str, metadata: dict) -> float:
        if raw.startswith('CEF:'):
            return 0.95
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        match = self.header_pattern.match(raw)
        if not match:
            return {}
            
        parsed = match.groupdict()
        extension = parsed.pop('extension', None)
        
        if extension:
            # simple key=value extraction
            ext_matches = re.finditer(r'([a-zA-Z0-9]+)=([^=]+)(?=\s+[a-zA-Z0-9]+=|$)', extension)
            for m in ext_matches:
                parsed[m.group(1)] = m.group(2).strip()
                
        return parsed
