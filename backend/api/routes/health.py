from fastapi import APIRouter, Request
import time

router = APIRouter()

@router.get("/health")
def get_health(request: Request):
    uptime = time.time() - request.app.state.start_time
    stats = request.app.state.event_store.get_stats()
    dq = stats.get('data_quality', {})
    return {
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "total_events": stats.get('total_events', 0),
        "total_raw_events": stats.get('total_raw_events', 0),
        "dlq_quarantine_count": stats.get('dlq_quarantine_count', 0),
        "duplicate_count": stats.get('duplicate_count', 0),
        "data_quality_score": dq.get('parse_success_rate', 1.0),
        "version": "1.0.0"
    }

@router.get("/health/ready")
def get_ready():
    return {"status": "ready"}
