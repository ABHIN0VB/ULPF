import re
from parser_engine.base_parser import BaseParser

class CiscoASAParser(BaseParser):
    SOURCE_ID = "cisco_asa"
    PRIORITY = 20

    def __init__(self):
        self.base_pattern = re.compile(r'%ASA-(?P<severity>\d)-(?P<message_id>\d+):\s+(?P<message>.*)')
        
        self.msg_patterns = [
            re.compile(r'(?P<action>Built|Teardown|Deny) (?P<direction>\w+)?\s?(?P<protocol>\w+) connection (?P<connection_id>\d+) for (?P<interface_src>[a-zA-Z0-9_-]+):(?P<src_ip>[0-9\.]+)/(?P<src_port>\d+).*to (?P<interface_dst>[a-zA-Z0-9_-]+):(?P<dst_ip>[0-9\.]+)/(?P<dst_port>\d+)'),
            re.compile(r'(?P<action>Deny) (?P<protocol>\w+) src (?P<interface_src>[a-zA-Z0-9_-]+):(?P<src_ip>[0-9\.]+)/(?P<src_port>\d+) dst (?P<interface_dst>[a-zA-Z0-9_-]+):(?P<dst_ip>[0-9\.]+)/(?P<dst_port>\d+)')
        ]

    def can_parse(self, raw: str, metadata: dict) -> float:
        if '%ASA-' in raw:
            return 0.9
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        match = self.base_pattern.search(raw)
        if not match:
            return {}
            
        parsed = match.groupdict()
        msg = parsed.get('message', '')
        
        for p in self.msg_patterns:
            m = p.search(msg)
            if m:
                parsed.update(m.groupdict())
                break
                
        return parsed
