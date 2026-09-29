from typing import Dict, Any

class SIEMAdapter:
    """
    Transforms canonical Universal Event Schema (UES) events
    into standardized SIEM ingestion formats (ArcSight CEF & IBM QRadar LEEF).
    """

    @classmethod
    def to_cef(cls, ues: Dict[str, Any]) -> str:
        """
        Converts UES event to ArcSight Common Event Format (CEF:0).
        """
        ulpf = ues.get('ulpf', {})
        evt = ues.get('event', {})
        src = ues.get('source', {})
        dst = ues.get('destination', {})
        net = ues.get('network', {})
        host = ues.get('host', {})

        vendor = host.get('vendor') or "ULPF"
        product = host.get('type') or ulpf.get('source_id') or "NetworkDevice"
        version = ulpf.get('version') or "1.0"
        event_class_id = evt.get('code') or evt.get('action') or "traffic"
        name = f"{evt.get('action', 'traffic')} connection"
        severity = evt.get('severity', 5)

        # Build extension key-value pairs
        ext_parts = []
        if src.get('ip'):
            ext_parts.append(f"src={src['ip']}")
        if src.get('port'):
            ext_parts.append(f"spt={src['port']}")
        if dst.get('ip'):
            ext_parts.append(f"dst={dst['ip']}")
        if dst.get('port'):
            ext_parts.append(f"dpt={dst['port']}")
        if net.get('protocol'):
            ext_parts.append(f"proto={net['protocol'].upper()}")
        if evt.get('action'):
            ext_parts.append(f"act={evt['action']}")
        if evt.get('outcome'):
            ext_parts.append(f"outcome={evt['outcome']}")
        
        ext_parts.append(f"externalId={ulpf.get('id', '')}")
        ext_parts.append(f"msg=Normalized by ULPF Universal Engine")

        ext_string = " ".join(ext_parts)
        return f"CEF:0|{vendor}|{product}|{version}|{event_class_id}|{name}|{severity}|{ext_string}"

    @classmethod
    def to_leef(cls, ues: Dict[str, Any]) -> str:
        """
        Converts UES event to IBM QRadar Log Event Extended Format (LEEF:1.0).
        """
        ulpf = ues.get('ulpf', {})
        evt = ues.get('event', {})
        src = ues.get('source', {})
        dst = ues.get('destination', {})
        net = ues.get('network', {})
        host = ues.get('host', {})

        vendor = host.get('vendor') or "ULPF"
        product = host.get('type') or ulpf.get('source_id') or "NetworkDevice"
        version = ulpf.get('version') or "1.0"
        event_id = evt.get('code') or evt.get('action') or "traffic"

        attr_parts = []
        if src.get('ip'):
            attr_parts.append(f"src={src['ip']}")
        if src.get('port'):
            attr_parts.append(f"srcPort={src['port']}")
        if dst.get('ip'):
            attr_parts.append(f"dst={dst['ip']}")
        if dst.get('port'):
            attr_parts.append(f"dstPort={dst['port']}")
        if net.get('protocol'):
            attr_parts.append(f"proto={net['protocol'].upper()}")
        if evt.get('action'):
            attr_parts.append(f"action={evt['action']}")
        if evt.get('severity'):
            attr_parts.append(f"sev={evt['severity']}")
            
        attr_parts.append(f"eventId={ulpf.get('id', '')}")
        
        # LEEF standard uses tab delimiters for attributes
        attributes_string = "\t".join(attr_parts)
        return f"LEEF:1.0|{vendor}|{product}|{version}|{event_id}|\t{attributes_string}"
