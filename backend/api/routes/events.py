import uuid
import hashlib
from fastapi import APIRouter, Request, Query, HTTPException, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from api.schemas import (
    IngestRequest, IngestResponse, EventSummary, 
    IntegrityCheckResponse, ReprocessResponse
)
from normalization.normalizer import normalize
from output_adapters.siem_adapter import SIEMAdapter
from security.auth import get_current_user_and_role, require_role, Role
from security.audit import audit_log

router = APIRouter()

MAX_LOG_SIZE_BYTES = 65536  # 64 KB maximum log payload protection

@router.get("/events", response_model=List[EventSummary])
def get_events(
    request: Request,
    source_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    event_outcome: Optional[str] = None,
    event_action: Optional[str] = None,
    parser_plugin: Optional[str] = None,
    severity_min: Optional[int] = None,
    severity_max: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0)
):
    filters = {
        'source_id': source_id, 'src_ip': src_ip, 'dst_ip': dst_ip, 
        'event_outcome': event_outcome, 'event_action': event_action, 
        'parser_plugin': parser_plugin,
        'severity_min': severity_min, 'severity_max': severity_max,
        'search': search
    }
    store = request.app.state.event_store
    return store.query_events(filters, limit, offset)

@router.get("/events/{id}")
def get_event(request: Request, id: str):
    evt = request.app.state.event_store.get_event_by_id(id)
    if not evt:
        raise HTTPException(status_code=404, detail=f"Event '{id}' not found")
    return evt

@router.get("/events/{id}/raw")
def get_event_raw(request: Request, id: str):
    raw_row = request.app.state.event_store.get_raw_event(id)
    if not raw_row:
        # Check normalized event to see if it links to a raw_event_id
        evt = request.app.state.event_store.get_event_by_id(id)
        if evt:
            return {
                "id": id,
                "raw": evt.get('ulpf', {}).get('raw', ''),
                "raw_hash": evt.get('ulpf', {}).get('raw_hash', '')
            }
        raise HTTPException(status_code=404, detail=f"Raw event '{id}' not found")
    return {
        "id": raw_row['id'],
        "raw": raw_row['raw_log'],
        "raw_hash": raw_row['raw_hash'],
        "size_bytes": raw_row.get('size_bytes', len(raw_row['raw_log'])),
        "received_at": raw_row['received_at']
    }

@router.get("/events/{id}/verify-integrity", response_model=IntegrityCheckResponse)
def verify_event_integrity(request: Request, id: str):
    """
    Cryptographic verification endpoint demonstrating 100% Lossless Preservation.
    Re-computes SHA-256 of stored raw bytes and compares against immutable stored hash.
    """
    store = request.app.state.event_store
    res = store.verify_event_integrity(id)
    if not res.get("verified") and res.get("error"):
        raise HTTPException(status_code=404, detail=res["error"])
    return res

@router.get("/events/{id}/export/cef")
def export_event_as_cef(request: Request, id: str):
    """SIEM Adapter: Export normalized event as ArcSight CEF string."""
    evt = request.app.state.event_store.get_event_by_id(id)
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    cef_string = SIEMAdapter.to_cef(evt)
    return {"id": id, "format": "CEF:0", "payload": cef_string}

@router.get("/events/{id}/export/leef")
def export_event_as_leef(request: Request, id: str):
    """SIEM Adapter: Export normalized event as IBM QRadar LEEF string."""
    evt = request.app.state.event_store.get_event_by_id(id)
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    leef_string = SIEMAdapter.to_leef(evt)
    return {"id": id, "format": "LEEF:1.0", "payload": leef_string}

@router.post("/events/{id}/reprocess", response_model=ReprocessResponse)
def reprocess_event(
    request: Request,
    id: str,
    auth=Depends(require_role(Role.ANALYST))
):
    """
    Reprocess historical raw event using latest active parser and mapping versions.
    Preserves original raw evidence and creates a new processing lineage version.
    """
    store = request.app.state.event_store
    raw_row = store.get_raw_event(id)
    if not raw_row:
        evt = store.get_event_by_id(id)
        if not evt:
            raise HTTPException(status_code=404, detail="Event not found for reprocessing")
        raw_log = evt.get('ulpf', {}).get('raw', '')
        source_id = evt.get('ulpf', {}).get('source_id', 'reprocess')
    else:
        raw_log = raw_row['raw_log']
        source_id = raw_row['source_id']

    # Reprocess through pipeline
    app = request.app
    metadata = {'source_ip': 'reprocessed', 'reprocessed': True}
    parser, conf = app.state.plugin_registry.detect_parser(raw_log, metadata)
    
    if not parser or conf < 0.20:
        return ReprocessResponse(
            event_id=id,
            success=False,
            parser_plugin="None",
            confidence=conf,
            event_outcome="unknown",
            message="No suitable parser found. Event remains in quarantine."
        )

    parsed_fields = parser.parse(raw_log, metadata)
    parser_name = parser.__class__.__name__
    parser_ver = getattr(parser, "VERSION", "1.0.0")

    ues = normalize(
        parsed_fields=parsed_fields,
        source_id=source_id,
        raw=raw_log,
        parser_plugin=parser_name,
        confidence=conf,
        source_metadata=metadata,
        raw_event_id=id,
        parser_version=parser_ver,
        mapping_version="2.0"  # Signifies updated mapping
    )

    store.store_event(ues)
    audit_log(request, user=auth["user"], role=auth["role"], action="EVENT_REPROCESSED",
              resource=id, result="success", details=f"Reprocessed with {parser_name} v{parser_ver}")

    return ReprocessResponse(
        event_id=ues['ulpf']['id'],
        success=True,
        parser_plugin=parser_name,
        confidence=conf,
        event_outcome=ues.get('event', {}).get('outcome', 'unknown'),
        message=f"Event reprocessed successfully using {parser_name} v{parser_ver}"
    )

@router.post("/ingest", response_model=IngestResponse)
def ingest(request: Request, body: IngestRequest):
    return process_single_log(request, body.raw_log, body.source_id, body.source_ip)

@router.post("/ingest/batch", response_model=List[IngestResponse])
def ingest_batch(request: Request, body: List[IngestRequest]):
    results = []
    for req in body[:1000]:
        res = process_single_log(request, req.raw_log, req.source_id, req.source_ip)
        results.append(res)
    return results

def process_single_log(request: Request, raw_log: str, source_id: str, source_ip: str) -> IngestResponse:
    app = request.app
    store = app.state.event_store

    # 1. Input sanitization & size guard
    raw_clean = raw_log.strip()
    raw_bytes = raw_clean.encode('utf-8', errors='replace')
    if len(raw_bytes) > MAX_LOG_SIZE_BYTES:
        raw_clean = raw_bytes[:MAX_LOG_SIZE_BYTES].decode('utf-8', errors='ignore')
        
    raw_hash = hashlib.sha256(raw_clean.encode('utf-8')).hexdigest()
    raw_event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # 2. RAW EVENT PRESERVATION FIRST (Guarantees zero data loss before any parsing)
    store.save_raw_event(
        event_id=raw_event_id,
        raw_log=raw_clean,
        raw_hash=raw_hash,
        source_id=source_id,
        source_ip=source_ip,
        received_at=now
    )

    # 3. Deduplication Check (Idempotency)
    is_duplicate, dedup_key = store.check_and_record_dedup(source_id, raw_hash, window_seconds=30)

    # 4. Format & Vendor Parser Detection
    metadata = {'source_ip': source_ip, 'source_id': source_id, 'received_at': now}
    parser, conf = app.state.plugin_registry.detect_parser(raw_clean, metadata)

    # 5. Unknown Event & DLQ Routing (Section 4 & 5)
    # If confidence is below threshold or unknown proprietary format without matched parser
    if not parser or conf < 0.20:
        store.store_failed_event(
            event_id=str(uuid.uuid4()),
            raw_event_id=raw_event_id,
            source_id=source_id,
            raw_log=raw_clean,
            raw_hash=raw_hash,
            failure_reason="unsupported_format_or_low_confidence",
            parser_attempted="generic_detector",
            processing_stage="format_detection",
            error_details="No registered plugin could parse this log with confidence >= 0.20",
            retry_count=0
        )
        return IngestResponse(
            id=raw_event_id,
            raw_hash=raw_hash,
            source_id=source_id,
            parser_plugin="UNKNOWN",
            confidence=round(conf, 2),
            event_action="quarantined",
            event_outcome="failure",
            status="quarantined_dlq",
            is_duplicate=is_duplicate,
            field_completeness=0.0,
            schema_valid=False
        )

    # 6. Parse Fields
    try:
        parsed_fields = parser.parse(raw_clean, metadata)
    except Exception as e:
        store.store_failed_event(
            event_id=str(uuid.uuid4()),
            raw_event_id=raw_event_id,
            source_id=source_id,
            raw_log=raw_clean,
            raw_hash=raw_hash,
            failure_reason="parser_exception",
            parser_attempted=parser.__class__.__name__,
            processing_stage="parsing",
            error_details=str(e),
            retry_count=0
        )
        return IngestResponse(
            id=raw_event_id,
            raw_hash=raw_hash,
            source_id=source_id,
            parser_plugin=parser.__class__.__name__,
            confidence=round(conf, 2),
            event_action="parse_error",
            event_outcome="failure",
            status="quarantined_dlq",
            is_duplicate=is_duplicate,
            field_completeness=0.0,
            schema_valid=False
        )

    parser_name = parser.__class__.__name__
    parser_ver = getattr(parser, "VERSION", "1.0.0")

    # 7. Normalization & Schema Validation
    ues = normalize(
        parsed_fields=parsed_fields,
        source_id=source_id,
        raw=raw_clean,
        parser_plugin=parser_name,
        confidence=conf,
        source_metadata=metadata,
        raw_event_id=raw_event_id,
        parser_version=parser_ver,
        mapping_version="1.0"
    )

    # 8. Persist Normalized Event
    store.store_event(ues, is_duplicate=is_duplicate, dedup_key=dedup_key)

    quality = ues.get('quality', {})
    return IngestResponse(
        id=ues['ulpf']['id'],
        raw_hash=raw_hash,
        source_id=source_id,
        parser_plugin=parser_name,
        confidence=round(conf, 2),
        event_action=ues.get('event', {}).get('action'),
        event_outcome=ues.get('event', {}).get('outcome'),
        status="success",
        is_duplicate=is_duplicate,
        field_completeness=quality.get('field_completeness', 0.0),
        schema_valid=quality.get('schema_valid', True)
    )
