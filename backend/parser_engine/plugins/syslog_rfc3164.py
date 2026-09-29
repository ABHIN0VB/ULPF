import re
from parser_engine.base_parser import BaseParser

class SyslogRFC3164Parser(BaseParser):
    SOURCE_ID = "syslog_rfc3164"
    PRIORITY = 20

    def __init__(self):
        # <PRI>Mon DD HH:MM:SS hostname tag: message
        self.pattern = re.compile(
            r'^<(?P<pri>\d+)>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>[^:]+):\s+(?P<message>.*)$'
        )

    def can_parse(self, raw: str, metadata: dict) -> float:
        if raw.startswith('<') and self.pattern.match(raw):
            return 0.9
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        match = self.pattern.match(raw)
        if not match:
            return {}
        
        parsed = match.groupdict()
        pri = int(parsed['pri'])
        facility = pri >> 3
        severity = pri & 7
        
        parsed['facility'] = facility
        parsed['severity'] = severity
        
        # Parse tag into process and PID if possible
        tag_match = re.match(r'^(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?$', parsed['tag'])
        if tag_match:
            parsed.update(tag_match.groupdict())
            
        return parsed
