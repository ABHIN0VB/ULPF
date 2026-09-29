from fastapi import APIRouter, Request, Query, Depends
from typing import List
from api.schemas import AuditLogItem
from security.auth import require_role, Role

router = APIRouter()

@router.get("/audit-logs", response_model=List[AuditLogItem])
def get_audit_logs(
    request: Request,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    auth=Depends(require_role(Role.ANALYST))
):
    """Retrieve security and administrative audit log trail."""
    store = request.app.state.event_store
    return store.query_audit_logs(limit=limit, offset=offset)
