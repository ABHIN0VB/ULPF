from parser_engine.base_parser import BaseParser

class PaloAltoParser(BaseParser):
    SOURCE_ID = "palo_alto"
    VERSION = "1.0.0"
    PRIORITY = 20

    KNOWN_ACTIONS = {'allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both', 'block', 'alert'}
    KNOWN_PROTOCOLS = {'tcp', 'udp', 'icmp'}

    def can_parse(self, raw: str, metadata: dict) -> float:
        parts = raw.split(',')
        if len(parts) > 20 and ('TRAFFIC' in raw or 'THREAT' in raw):
            return 0.85
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        parts = [p.strip() for p in raw.split(',')]
        parsed = {}
        if len(parts) > 3:
            parsed['receive_time'] = parts[0]
            parsed['serial'] = parts[1]
            parsed['type'] = parts[2]
            parsed['subtype'] = parts[3]
            
            if len(parts) > 20:
                parsed['src_ip'] = parts[6] if len(parts) > 6 else ""
                parsed['dst_ip'] = parts[7] if len(parts) > 7 else ""
                parsed['rule'] = parts[11] if len(parts) > 11 else ""
                parsed['srcuser'] = parts[12] if len(parts) > 12 else ""
                parsed['app'] = parts[14] if len(parts) > 14 else ""
                parsed['from_zone'] = parts[16] if len(parts) > 16 else ""
                parsed['to_zone'] = parts[17] if len(parts) > 17 else ""

                # Robust action & protocol extraction across PAN-OS versions (handles column shifts)
                action_found = None
                proto_found = None

                # Check indices 25 to 35 for action and protocol
                scan_range = parts[25:min(len(parts), 36)]
                for val in scan_range:
                    v_low = val.lower()
                    if not action_found and v_low in self.KNOWN_ACTIONS:
                        action_found = val
                    if not proto_found and v_low in self.KNOWN_PROTOCOLS:
                        proto_found = v_low

                parsed['action'] = action_found or (parts[29] if len(parts) > 29 else "traffic")
                if proto_found:
                    parsed['protocol'] = proto_found

                if len(parts) > 33:
                    parsed['bytes_sent'] = parts[32]
                    parsed['bytes_received'] = parts[33]

        return parsed
