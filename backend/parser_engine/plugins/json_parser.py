import json
from parser_engine.base_parser import BaseParser

class JsonParser(BaseParser):
    SOURCE_ID = "json"
    PRIORITY = 10

    def can_parse(self, raw: str, metadata: dict) -> float:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return 0.95
        except (ValueError, TypeError):
            pass
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        try:
            data = json.loads(raw)
            return self._flatten(data)
        except Exception:
            return {}
            
    def _flatten(self, d, parent_key='', sep='.', depth=0):
        if depth >= 2:
            return {parent_key: d} if parent_key else d
            
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten(v, new_key, sep=sep, depth=depth+1).items())
            else:
                items.append((new_key, v))
        return dict(items)
