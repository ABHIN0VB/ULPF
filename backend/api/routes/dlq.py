from fastapi import APIRouter, Request, HTTPException, Depends, Query
from typing import List, Optional
from api.schemas import DLQItem, ReprocessResponse
from normalization.normalizer import normalize
from security.auth import require_role, Role
from security.audit import audit_log

router = APIRouter()

@router.get("/dlq", response_model=List[DLQItem])
def get_dlq_events(
    request: Request,
    status: Optional[str] = "quarantined",
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0)
):
    """List failed, quarantined, or malformed events stored in the Dead Letter Queue."""
    store = request.app.state.event_store
    return store.query_dlq(limit=limit, offset=offset, status=status)

@router.get("/dlq/{id}", response_model=DLQItem)
def get_dlq_item(request: Request, id: str):
    store = request.app.state.event_store
    item = store.get_failed_event(id)
    if not item:
        raise HTTPException(status_code=404, detail=f"DLQ entry '{id}' not found")
    return item

@router.post("/dlq/{id}/reprocess", response_model=ReprocessResponse)
def reprocess_dlq_item(
    request: Request,
    id: str,
    auth=Depends(require_role(Role.ANALYST))
):
    """
    Attempts to reprocess an event quarantined in the DLQ.
    Useful after an analyst onboards a new parser plugin or mapping definition.
    """
    store = request.app.state.event_store
    dlq_item = store.get_failed_event(id)
    if not dlq_item:
        raise HTTPException(status_code=404, detail="DLQ item not found")

    raw_log = dlq_item['raw_log']
    source_id = dlq_item['source_id']
    raw_event_id = dlq_item['raw_event_id']
    retry_count = dlq_item.get('retry_count', 0) + 1

    app = request.app
    metadata = {'source_ip': 'dlq_retry', 'retry_count': retry_count}
    parser, conf = app.state.plugin_registry.detect_parser(raw_log, metadata)

    if not parser or conf < 0.20:
        store.update_failed_event_status(id, "quarantined", retry_count=retry_count)
        return ReprocessResponse(
            event_id=id,
            success=False,
            parser_plugin="None",
            confidence=conf,
            event_outcome="failure",
            message=f"Still unable to parse. Retry count incremented to {retry_count}."
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
        raw_event_id=raw_event_id,
        parser_version=parser_ver,
        mapping_version="1.1",
        retry_count=retry_count
    )

    store.store_event(ues)
    store.update_failed_event_status(id, "reprocessed", retry_count=retry_count)

    audit_log(
        request,
        user=auth["user"],
        role=auth["role"],
        action="DLQ_REPROCESSED",
        resource=id,
        result="success",
        details=f"Recovered from DLQ using {parser_name} v{parser_ver}"
    )

    return ReprocessResponse(
        event_id=ues['ulpf']['id'],
        success=True,
        parser_plugin=parser_name,
        confidence=conf,
        event_outcome=ues.get('event', {}).get('outcome', 'unknown'),
        message=f"Event recovered from DLQ and normalized using {parser_name} v{parser_ver}"
    )

@router.post("/dlq/reprocess-all")
def reprocess_all_dlq(
    request: Request,
    auth=Depends(require_role(Role.ADMIN))
):
    """Batch reprocesses all quarantined DLQ events."""
    store = request.app.state.event_store
    items = store.query_dlq(limit=500, offset=0, status="quarantined")
    recovered = 0
    failed = 0

    for it in items:
        dlq_id = it['id']
        raw_log = it['raw_log']
        source_id = it['source_id']
        raw_event_id = it['raw_event_id']

        parser, conf = request.app.state.plugin_registry.detect_parser(raw_log, {})
        if parser and conf >= 0.20:
            parsed_fields = parser.parse(raw_log, {})
            parser_name = parser.__class__.__name__
            parser_ver = getattr(parser, "VERSION", "1.0.0")

            ues = normalize(
                parsed_fields=parsed_fields,
                source_id=source_id,
                raw=raw_log,
                parser_plugin=parser_name,
                confidence=conf,
                source_metadata={},
                raw_event_id=raw_event_id,
                parser_version=parser_ver
            )
            store.store_event(ues)
            store.update_failed_event_status(dlq_id, "reprocessed")
            recovered += 1
        else:
            failed += 1

    audit_log(
        request,
        user=auth["user"],
        role=auth["role"],
        action="DLQ_BATCH_REPROCESS",
        resource="all",
        result="success",
        details=f"Recovered {recovered}, remaining {failed}"
    )

    return {
        "total_attempted": len(items),
        "recovered": recovered,
        "remaining_quarantined": failed
    }
