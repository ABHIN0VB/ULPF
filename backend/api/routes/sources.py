from fastapi import APIRouter, Request
from typing import List
from api.schemas import SystemStats, SourceStats, DataQualityMetrics

router = APIRouter()

@router.get("/sources", response_model=List[SourceStats])
def get_sources(request: Request):
    sources = request.app.state.event_store.get_sources()
    return [
        SourceStats(
            source_id=s['source_id'],
            event_count=s['count'],
            last_seen=s['last_seen'],
            success_rate=s.get('success_rate', 1.0),
            duplicates=s.get('duplicates', 0)
        ) for s in sources
    ]

@router.get("/stats", response_model=SystemStats)
def get_stats(request: Request):
    store = request.app.state.event_store
    stats = store.get_stats()
    sources = store.get_sources()
    
    source_stats = [
        SourceStats(
            source_id=s['source_id'],
            event_count=s['count'],
            last_seen=s['last_seen'],
            success_rate=s.get('success_rate', 1.0),
            duplicates=s.get('duplicates', 0)
        ) for s in sources
    ]

    dq = stats.get('data_quality', {})
    data_quality = DataQualityMetrics(
        parse_success_rate=dq.get('parse_success_rate', 1.0),
        schema_validation_rate=dq.get('schema_validation_rate', 1.0),
        avg_field_completeness=dq.get('avg_field_completeness', 0.85),
        duplicate_rate=dq.get('duplicate_rate', 0.0),
        failure_rate=dq.get('failure_rate', 0.0)
    )

    return SystemStats(
        total_events=stats.get('total_events', 0),
        total_raw_events=stats.get('total_raw_events', 0),
        dlq_quarantine_count=stats.get('dlq_quarantine_count', 0),
        duplicate_count=stats.get('duplicate_count', 0),
        sources=source_stats,
        events_by_outcome=stats.get('events_by_outcome', {}),
        events_by_parser=stats.get('events_by_parser', {}),
        data_quality=data_quality
    )
