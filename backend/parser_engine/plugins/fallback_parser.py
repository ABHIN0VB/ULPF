import re
from parser_engine.base_parser import BaseParser

class FallbackParser(BaseParser):
    SOURCE_ID = "fallback"
    PRIORITY = 100

    def can_parse(self, raw: str, metadata: dict) -> float:
        return 0.1

    def parse(self, raw: str, metadata: dict) -> dict:
        parsed = {}
        
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw)
        if len(ips) >= 1:
            parsed['src_ip'] = ips[0]
        if len(ips) >= 2:
            parsed['dst_ip'] = ips[1]
            
        # Extract ports
        ports = re.findall(r':(\d{1,5})\b', raw)
        if len(ports) >= 1:
            parsed['src_port'] = ports[0]
        if len(ports) >= 2:
            parsed['dst_port'] = ports[1]
            
        # Extract kv pairs
        kvs = re.findall(r'([a-zA-Z0-9_]+)=([^\s]+)', raw)
        for k, v in kvs:
            if k not in parsed:
                parsed[k] = v
                
        return parsed
