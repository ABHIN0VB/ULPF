from typing import Optional

def audit_log(
    request,
    user: str,
    role: str,
    action: str,
    resource: str,
    result: str = "success",
    details: str = ""
):
    """Convenience helper to write an audit entry into SQLite store."""
    try:
        store = request.app.state.event_store
        client_ip = request.client.host if request.client else "127.0.0.1"
        store.log_audit(
            user=user,
            role=role,
            action=action,
            resource=resource,
            result=result,
            source_ip=client_ip,
            details=details
        )
    except Exception as e:
        print(f"[AUDIT ERROR] Failed to record audit log: {e}")
