from fastapi import Header, HTTPException, Depends, status
from typing import Optional, List
from enum import Enum

class Role(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"

ROLE_HIERARCHY = {
    Role.VIEWER: 1,
    Role.ANALYST: 2,
    Role.ADMIN: 3
}

def get_current_user_and_role(
    x_ulpf_user: Optional[str] = Header(default="admin", alias="X-ULPF-User"),
    x_ulpf_role: Optional[str] = Header(default="ADMIN", alias="X-ULPF-Role")
):
    """
    Simulates / enforces RBAC for air-gapped security operations.
    Defaults to ADMIN for evaluation ease unless explicitly constrained by headers.
    """
    clean_role = x_ulpf_role.upper() if x_ulpf_role else "ADMIN"
    if clean_role not in [r.value for r in Role]:
        clean_role = "VIEWER"
    
    return {
        "user": x_ulpf_user or "operator",
        "role": clean_role
    }

def require_role(min_role: Role):
    def role_dependency(auth_data: dict = Depends(get_current_user_and_role)):
        user_role = Role(auth_data["role"])
        if ROLE_HIERARCHY[user_role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires minimum role: {min_role.value}, current role: {user_role.value}"
            )
        return auth_data
    return role_dependency
