import asyncio
import os
import time
import uuid
import hashlib
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routes import events, sources, plugins, health, dlq, benchmark, audit
from event_store.sqlite_store import SQLiteEventStore
from parser_engine.plugin_registry import PluginRegistry
from ingestion.syslog_receiver import start_syslog_server
from normalization.normalizer import normalize

app = FastAPI(
    title="ULPF API — Universal Log Pre-processing Framework",
    version="1.0.0",
    description="SIH 2026 Problem 26156 (NTRO) Production-Grade Universal Pre-processing Engine",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all API routers
app.include_router(events.router, prefix="/api", tags=["Events"])
app.include_router(sources.router, prefix="/api", tags=["Sources"])
app.include_router(plugins.router, prefix="/api", tags=["Plugins"])
app.include_router(dlq.router, prefix="/api", tags=["Dead Letter Queue"])
app.include_router(benchmark.router, prefix="/api", tags=["Benchmarking"])
app.include_router(audit.router, prefix="/api", tags=["Audit"])
app.include_router(health.router, prefix="/api", tags=["Health"])


def process_syslog(raw: str, metadata: dict):
    """
    Robust syslog ingestion pipeline:
    1. Raw event preservation first (lossless guarantee)
    2. Deduplication check
    3. Parser detection & DLQ fallback for malformed/unsupported logs
    4. Normalization and dual-storage
    """
    try:
        raw_clean = raw.strip()
        raw_hash = hashlib.sha256(raw_clean.encode('utf-8')).hexdigest()
        raw_id = str(uuid.uuid4())
        source_id = metadata.get("source_id", "syslog_inbound")
        source_ip = metadata.get("source_ip", "0.0.0.0")
        now = datetime.now(timezone.utc).isoformat()

        store = app.state.event_store

        # 1. RAW PRESERVATION FIRST
        store.save_raw_event(
            event_id=raw_id,
            raw_log=raw_clean,
            raw_hash=raw_hash,
            source_id=source_id,
            source_ip=source_ip,
            received_at=now
        )

        # 2. DEDUPLICATION
        is_dup, dedup_key = store.check_and_record_dedup(source_id, raw_hash, window_seconds=30)

        # 3. DETECTION & PARSING
        parser, conf = app.state.plugin_registry.detect_parser(raw_clean, metadata)
        
        if not parser or conf < 0.20:
            store.store_failed_event(
                event_id=str(uuid.uuid4()),
                raw_event_id=raw_id,
                source_id=source_id,
                raw_log=raw_clean,
                raw_hash=raw_hash,
                failure_reason="syslog_unsupported_format",
                parser_attempted="syslog_receiver",
                processing_stage="format_detection",
                error_details="No registered plugin could parse syslog payload"
            )
            return

        parsed_fields = parser.parse(raw_clean, metadata)
        parser_name = parser.__class__.__name__
        parser_ver = getattr(parser, "VERSION", "1.0.0")

        # 4. NORMALIZATION & UES VALIDATION
        ues = normalize(
            parsed_fields=parsed_fields,
            source_id=source_id,
            raw=raw_clean,
            parser_plugin=parser_name,
            confidence=conf,
            source_metadata=metadata,
            raw_event_id=raw_id,
            parser_version=parser_ver
        )

        store.store_event(ues, is_duplicate=is_dup, dedup_key=dedup_key)

    except Exception as e:
        print(f"[ERROR] Syslog pipeline error: {e}")


@app.on_event("startup")
async def startup_event():
    app.state.start_time = time.time()

    # Resolve DB path from env or default
    db_path = os.environ.get("ULPF_DB_PATH", "ulpf_events.db")
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    app.state.event_store = SQLiteEventStore(db_path)

    app.state.plugin_registry = PluginRegistry()
    print(f"[ULPF] Initialized with {len(app.state.plugin_registry.plugins)} registered parser plugins")

    # Start syslog receiver background task
    asyncio.create_task(start_syslog_server(process_syslog))
    print("[ULPF] Syslog receiver active on UDP/TCP port 5514")


# Serve frontend static assets
_frontend_dir = os.environ.get(
    "ULPF_FRONTEND_DIR",
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)
_frontend_dir = os.path.abspath(_frontend_dir)

if os.path.isdir(_frontend_dir):
    app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")
    print(f"[ULPF] Serving dashboard from {_frontend_dir}")
else:
    @app.get("/")
    def root():
        return {"message": "ULPF API active. Frontend directory not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
