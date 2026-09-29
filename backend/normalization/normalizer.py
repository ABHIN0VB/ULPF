import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from normalization.field_mapper import FieldMapper
from normalization.enrichment import geoip_mock, threat_intel
from normalization.validator import UESValidator
from normalization.outcome_resolver import OutcomeResolver

field_mapper = FieldMapper()

def normalize(
    parsed_fields: dict,
    source_id: str,
    raw: str,
    parser_plugin: str,
    confidence: float,
    source_metadata: Optional[dict] = None,
    raw_event_id: Optional[str] = None,
    parser_version: str = "1.0.0",
    mapping_version: str = "1.0",
    retry_count: int = 0
) -> dict:
    source_metadata = source_metadata or {}
    
    # 1. Map fields according to YAML mapping definitions
    mapped = field_mapper.map_fields(parsed_fields, source_id, parser_plugin)
    
    now = datetime.now(timezone.utc).isoformat()
    raw_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    event_uuid = str(uuid.uuid4())
    canonical_raw_id = raw_event_id or event_uuid

    # 2. Universal Semantic Action and Outcome Resolution (Precedence & Lossless)
    outcome, action, raw_outcome_val, raw_action_val = OutcomeResolver.resolve(mapped, parsed_fields)

    # 3. Severity mapping
    try:
        raw_sev = (
            mapped.get('event.severity') or mapped.get('severity') or 
            parsed_fields.get('severity') or parsed_fields.get('event_severity') or 0
        )
        severity = int(raw_sev)
        severity = max(0, min(10, severity))
    except (ValueError, TypeError):
        severity = 0

    # 4. Protocol Normalization
    proto_raw = str(
        mapped.get('network.protocol') or mapped.get('protocol') or 
        parsed_fields.get('protocol') or parsed_fields.get('proto') or 'tcp'
    ).lower().strip()

    if proto_raw in ['17', 'udp']:
        proto_clean = 'udp'
    elif proto_raw in ['6', 'tcp']:
        proto_clean = 'tcp'
    elif proto_raw in ['1', 'icmp']:
        proto_clean = 'icmp'
    else:
        proto_clean = proto_raw

    # 5. Construct Universal Event Schema (UES) Structure
    ues: Dict[str, Any] = {
        'ulpf': {
            'id': event_uuid,
            'schema_name': 'ULPF',
            'schema_version': '1.0',
            'version': '1.0',
            'ingest_timestamp': source_metadata.get('received_at', now),
            'processed_timestamp': now,
            'raw': raw,
            'raw_hash': raw_hash,
            'parser_plugin': parser_plugin,
            'source_id': source_id,
            'confidence': round(float(confidence), 2)
        },
        'parser': {
            'name': parser_plugin,
            'version': parser_version
        },
        'lineage': {
            'source_id': source_id,
            'raw_event_id': canonical_raw_id,
            'parser_name': parser_plugin,
            'parser_version': parser_version,
            'mapping_version': mapping_version,
            'normalizer_version': '1.0.0',
            'ingest_timestamp': source_metadata.get('received_at', now),
            'processed_timestamp': now
        },
        'processing': {
            'mapping_version': mapping_version,
            'parser_attempted': parser_plugin,
            'retry_count': retry_count
        },
        'event': {
            'kind': mapped.get('event.kind', 'event'),
            'category': mapped.get('event.category', ['network']),
            'type': mapped.get('event.type', ['connection']),
            'action': action,
            'outcome': outcome,
            'severity': severity,
            'dataset': f'{source_id}.traffic'
        },
        'source': {},
        'destination': {},
        'network': {
            'protocol': proto_clean
        },
        'host': {
            'name': mapped.get('host.name') or mapped.get('host_name') or parsed_fields.get('host') or source_id,
            'ip': source_metadata.get('source_ip', '0.0.0.0'),
            'vendor': mapped.get('host.vendor') or mapped.get('vendor') or 'Generic',
            'type': mapped.get('host.type', 'network_device')
        },
        'tags': [source_id, outcome, 'normalized']
    }

    # Lossless preservation of raw source-specific values (always store, even if they match normalized)
    if raw_action_val is not None:
        ues['event']['original_action'] = raw_action_val
    if raw_outcome_val is not None:
        ues['event']['original_outcome'] = raw_outcome_val

    # Reason / Message preservation
    reason = (
        mapped.get('event.reason') or mapped.get('reason') or 
        parsed_fields.get('reason') or parsed_fields.get('msg')
    )
    if reason:
        ues['event']['reason'] = str(reason).strip()

    # Extract IPs
    src_ip = (
        mapped.get('source.ip') or mapped.get('src_ip') or 
        parsed_fields.get('src_ip') or parsed_fields.get('source_ip') or 
        parsed_fields.get('src') or parsed_fields.get('srcip') or 
        parsed_fields.get('client_ip')
    )
    dst_ip = (
        mapped.get('destination.ip') or mapped.get('dst_ip') or 
        parsed_fields.get('dst_ip') or parsed_fields.get('dest_ip') or 
        parsed_fields.get('destination_ip') or parsed_fields.get('dst') or 
        parsed_fields.get('dstip') or parsed_fields.get('server_ip')
    )
    
    if src_ip:
        ues['source']['ip'] = str(src_ip).strip()
        ues['source']['geo'] = geoip_mock.enrich_ip(str(src_ip).strip())
        ti = threat_intel.check_ip(str(src_ip).strip())
        if ti:
            ues['threat'] = ti
            ues['tags'].append('threat_detected')

    if dst_ip:
        ues['destination']['ip'] = str(dst_ip).strip()
        ues['destination']['geo'] = geoip_mock.enrich_ip(str(dst_ip).strip())
        ti = threat_intel.check_ip(str(dst_ip).strip())
        if ti and 'threat' not in ues:
            ues['threat'] = ti

    # Extract Ports
    src_port = (
        mapped.get('source.port') or mapped.get('src_port') or 
        parsed_fields.get('src_port') or parsed_fields.get('spt') or 
        parsed_fields.get('srcport') or parsed_fields.get('client_port')
    )
    if src_port:
        try:
            ues['source']['port'] = int(src_port)
        except (ValueError, TypeError):
            pass

    dst_port = (
        mapped.get('destination.port') or mapped.get('dst_port') or 
        parsed_fields.get('dst_port') or parsed_fields.get('dpt') or 
        parsed_fields.get('dstport') or parsed_fields.get('server_port') or 
        parsed_fields.get('port')
    )
    if dst_port:
        try:
            ues['destination']['port'] = int(dst_port)
        except (ValueError, TypeError):
            pass

    # Extract User
    user = (
        mapped.get('user.name') or mapped.get('user') or 
        parsed_fields.get('user') or parsed_fields.get('srcuser') or 
        parsed_fields.get('username')
    )
    if user:
        ues['user'] = {'name': str(user).strip()}

    # 6. Schema Validation & Quality Assessment
    is_valid, validation_errors, field_completeness = UESValidator.validate_and_score(ues, confidence)
    ues['quality'] = {
        'parse_success': confidence >= 0.20,
        'schema_valid': is_valid,
        'field_completeness': field_completeness,
        'normalization_confidence': round(confidence, 2),
        'validation_errors': validation_errors
    }

    return ues
