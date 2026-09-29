import csv
import io
from parser_engine.base_parser import BaseParser

class CSVParser(BaseParser):
    SOURCE_ID = "csv"
    PRIORITY = 30

    def can_parse(self, raw: str, metadata: dict) -> float:
        if ',' in raw and len(raw.split(',')) >= 3:
            return 0.6
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        try:
            reader = csv.reader(io.StringIO(raw))
            row = next(reader)
            
            parsed = {}
            headers = metadata.get('csv_header', [])
            
            for i, val in enumerate(row):
                key = headers[i] if i < len(headers) else f"col_{i}"
                parsed[key] = val
                
            return parsed
        except Exception:
            return {}
