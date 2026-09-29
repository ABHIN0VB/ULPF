import re
from parser_engine.base_parser import BaseParser

class CheckpointParser(BaseParser):
    SOURCE_ID = "checkpoint"
    PRIORITY = 20

    def can_parse(self, raw: str, metadata: dict) -> float:
        if 'orig=' in raw and 'product=' in raw:
            return 0.85
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        parsed = {}
        parts = re.split(r'[;\s]+', raw.strip())
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                parsed[k] = v
        return parsed
