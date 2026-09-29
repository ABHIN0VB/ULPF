from fastapi import APIRouter, Request, UploadFile, File, HTTPException, Depends
from typing import List
import os
import shutil
from api.schemas import PluginInfo, PluginUploadResponse
from pydantic import BaseModel
from parser_engine.plugin_validator import SecurePluginValidator
from security.auth import require_role, Role
from security.audit import audit_log

router = APIRouter()

class TestRequest(BaseModel):
    raw_log: str

@router.get("/plugins", response_model=List[PluginInfo])
def get_plugins(request: Request):
    return request.app.state.plugin_registry.list_plugins()

@router.post("/plugins/test")
def test_plugin(request: Request, body: TestRequest):
    parser, conf = request.app.state.plugin_registry.detect_parser(body.raw_log, {})
    if parser:
        parsed = parser.parse(body.raw_log, {})
        return {
            "parser": parser.__class__.__name__,
            "version": getattr(parser, "VERSION", "1.0.0"),
            "confidence": round(conf, 2),
            "parsed_fields": parsed
        }
    return {"parser": None, "version": None, "confidence": 0.0, "parsed_fields": {}}

@router.post("/plugins/upload", response_model=PluginUploadResponse)
async def upload_plugin(
    request: Request,
    file: UploadFile = File(...),
    auth=Depends(require_role(Role.ADMIN))
):
    """
    Secure Plugin Upload Endpoint.
    Enforces static AST security validation to prevent code injection in air-gapped systems.
    """
    if not file.filename.endswith('.py'):
        return PluginUploadResponse(
            success=False,
            plugin_name=file.filename,
            message="Only Python (.py) parser plugin files are permitted."
        )

    code_bytes = await file.read()

    # 1. Static AST Security Validation
    is_safe, reason, sha256_hash = SecurePluginValidator.validate_code(code_bytes)
    if not is_safe:
        audit_log(request, user=auth["user"], role=auth["role"], action="PLUGIN_UPLOAD_REJECTED",
                  resource=file.filename, result="failed", details=reason)
        raise HTTPException(
            status_code=400,
            detail=f"Plugin security verification failed: {reason}"
        )

    # 2. Save file safely
    plugins_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'parser_engine', 'plugins')
    os.makedirs(plugins_dir, exist_ok=True)
    file_path = os.path.join(plugins_dir, file.filename)

    with open(file_path, "wb") as buffer:
        buffer.write(code_bytes)

    # 3. Hot reload into registry
    registered = request.app.state.plugin_registry.register_plugin(file_path)
    
    audit_log(request, user=auth["user"], role=auth["role"], action="PLUGIN_ACTIVATED",
              resource=file.filename, result="success", details=f"SHA-256: {sha256_hash}")

    plugin_name = registered.__class__.__name__ if registered else file.filename
    return PluginUploadResponse(
        success=True,
        plugin_name=plugin_name,
        sha256_hash=sha256_hash,
        message=f"Plugin '{plugin_name}' passed static security checks and was dynamically registered."
    )
