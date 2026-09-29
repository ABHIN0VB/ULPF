from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class IngestRequest(BaseModel):
    raw_log: str
    source_id: str = 'unknown'
    source_ip: str = '0.0.0.0'

class IngestResponse(BaseModel):
    id: str
    raw_hash: str
    source_id: str
    parser_plugin: str
    confidence: float
    event_action: Optional[str] = None
    event_outcome: Optional[str] = None
    status: str = "success"  # "success" or "quarantined_dlq"
    is_duplicate: bool = False
    field_completeness: Optional[float] = None
    schema_valid: Optional[bool] = None

class EventSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    processed_at: Optional[str] = None
    source_id: Optional[str] = None
    parser_plugin: Optional[str] = None
    parser_version: Optional[str] = None
    event_action: Optional[str] = None
    event_outcome: Optional[str] = None
    event_severity: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    confidence: Optional[float] = None
    is_duplicate: Optional[int] = 0
    field_completeness: Optional[float] = 0.0
    schema_valid: Optional[int] = 1

class DLQItem(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    raw_event_id: str
    timestamp: str
    source_id: str
    raw_log: str
    raw_hash: str
    failure_reason: str
    parser_attempted: str
    processing_stage: str
    error_details: Optional[str] = None
    retry_count: int = 0
    status: str = "quarantined"

class IntegrityCheckResponse(BaseModel):
    event_id: str
    verified: bool
    status: str
    stored_hash: str
    computed_hash: str
    algorithm: str = "SHA-256"
    byte_size: int
    verification_timestamp: str

class ReprocessResponse(BaseModel):
    event_id: str
    success: bool
    parser_plugin: str
    confidence: float
    event_outcome: str
    message: str

class AuditLogItem(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    timestamp: str
    user: str
    role: str
    action: str
    resource: str
    result: str
    source_ip: str
    details: Optional[str] = None

class PluginInfo(BaseModel):
    name: str
    source_id: str
    version: str = "1.0.0"
    priority: int
    description: str

class SourceStats(BaseModel):
    model_config = {"from_attributes": True}

    source_id: str
    event_count: int
    last_seen: Optional[str] = None
    success_rate: float = 1.0
    duplicates: Optional[int] = 0

class DataQualityMetrics(BaseModel):
    parse_success_rate: float
    schema_validation_rate: float
    avg_field_completeness: float
    duplicate_rate: float
    failure_rate: float

class SystemStats(BaseModel):
    total_events: int
    total_raw_events: int
    dlq_quarantine_count: int
    duplicate_count: int
    sources: List[SourceStats]
    events_by_outcome: Dict[str, int]
    events_by_parser: Dict[str, int] = {}
    data_quality: DataQualityMetrics

class PluginUploadResponse(BaseModel):
    success: bool
    plugin_name: str
    sha256_hash: Optional[str] = None
    message: str

class BenchmarkResult(BaseModel):
    total_events: int
    workers: int
    throughput_eps: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    cpu_percent: float
    memory_mb: float
    parse_success_percent: float
    schema_validation_percent: float
    timestamp: str
