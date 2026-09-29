import re
from parser_engine.base_parser import BaseParser

class FortinetParser(BaseParser):
    SOURCE_ID = "fortinet"
    PRIORITY = 20

    def can_parse(self, raw: str, metadata: dict) -> float:
        if 'devname=' in raw and 'logid=' in raw:
            return 0.9
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        parsed = {}
        # match key=value or key="value"
        matches = re.finditer(r'([a-zA-Z0-9_]+)=(?:"([^"]+)"|([^ \n]+))', raw)
        for m in matches:
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3)
            parsed[key] = val
        return parsed
