from parser_engine.base_parser import BaseParser
class DynamicDemoParser(BaseParser):
    SOURCE_ID = "dynamic_demo"
    VERSION = "1.0.0"
    PRIORITY = 20
    def can_parse(self, raw, meta): return 0.99 if raw.startswith("DYNAMIC_DEMO:") else 0.0
    def parse(self, raw, meta): return {"action": "allow", "protocol": "tcp"}
