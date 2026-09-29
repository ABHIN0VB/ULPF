from fastapi import APIRouter, Request, Query, Depends
from api.schemas import BenchmarkResult
from tools.benchmark import PerformanceBenchmark
from security.auth import require_role, Role
from security.audit import audit_log

router = APIRouter()

@router.get("/benchmark/latest", response_model=BenchmarkResult)
def get_latest_benchmark(request: Request):
    """Retrieve the latest performance benchmark telemetry."""
    return PerformanceBenchmark.get_latest()

@router.post("/benchmark/run", response_model=BenchmarkResult)
def run_benchmark(
    request: Request,
    count: int = Query(default=1000, ge=100, le=10000),
    auth=Depends(require_role(Role.ADMIN))
):
    """
    Executes a reproducible performance benchmark against synthetic logs.
    Measures Throughput (EPS), P50/P95/P99 latency, CPU/Memory usage, and accuracy.
    """
    registry = request.app.state.plugin_registry
    result = PerformanceBenchmark.run_benchmark(count=count, registry=registry)
    
    audit_log(
        request,
        user=auth["user"],
        role=auth["role"],
        action="BENCHMARK_EXECUTED",
        resource=f"{count}_events",
        result="success",
        details=f"Throughput: {result['throughput_eps']} EPS, P95: {result['p95_latency_ms']} ms"
    )
    
    return result
