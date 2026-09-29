import re
from parser_engine.base_parser import BaseParser

class SyslogRFC5424Parser(BaseParser):
    SOURCE_ID = "syslog_rfc5424"
    PRIORITY = 15

    def __init__(self):
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        self.pattern = re.compile(
            r'^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured_data>-|\[.*?\])\s*(?P<message>.*)$'
        )
        self.can_parse_pattern = re.compile(r'^<\d+>\d\s')

    def can_parse(self, raw: str, metadata: dict) -> float:
        if self.can_parse_pattern.match(raw):
            return 0.9
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        match = self.pattern.match(raw)
        if not match:
            return {}
        
        parsed = match.groupdict()
        pri = int(parsed['pri'])
        parsed['facility'] = pri >> 3
        parsed['severity'] = pri & 7
        
        # Simple structured data parsing
        sd = parsed.get('structured_data', '')
        if sd and sd != '-':
            sd_parts = re.findall(r'\[(.*?)\]', sd)
            parsed_sd = {}
            for part in sd_parts:
                kv_matches = re.findall(r'([^=\s]+)="([^"]+)"', part)
                for k, v in kv_matches:
                    parsed_sd[k] = v
            parsed['structured_data_parsed'] = parsed_sd
            
        return parsed
