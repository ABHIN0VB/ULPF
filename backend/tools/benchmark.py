import time
import os
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, List

from tools.log_generator import SyntheticLogGenerator
from parser_engine.plugin_registry import PluginRegistry
from normalization.normalizer import normalize

LAST_BENCHMARK_RESULT: Dict[str, Any] = {}

class PerformanceBenchmark:
    """
    Executes reproducible performance benchmarks measuring throughput (EPS),
    P50/P95/P99 latencies, CPU/Memory utilization, and parser accuracy.
    """

    @classmethod
    def run_benchmark(cls, count: int = 1000, registry: PluginRegistry = None) -> Dict[str, Any]:
        global LAST_BENCHMARK_RESULT
        if registry is None:
            registry = PluginRegistry()

        process = psutil.Process(os.getpid())
        cpu_start = process.cpu_percent(interval=None)
        mem_start_mb = process.memory_info().rss / (1024 * 1024)

        # Generate test logs
        logs = SyntheticLogGenerator.generate_batch(count)

        latencies_ms: List[float] = []
        parsed_ok = 0
        schema_valid_ok = 0

        start_time = time.perf_counter()

        for item in logs:
            t0 = time.perf_counter()
            raw = item["raw_log"]
            source_id = item["source_id"]

            parser, conf = registry.detect_parser(raw, {})
            if parser and conf >= 0.20:
                parsed_ok += 1
                parsed_fields = parser.parse(raw, {})
                ues = normalize(
                    parsed_fields=parsed_fields,
                    source_id=source_id,
                    raw=raw,
                    parser_plugin=parser.__class__.__name__,
                    confidence=conf,
                    source_metadata={"source_ip": item["source_ip"]}
                )
                if ues.get('quality', {}).get('schema_valid', False):
                    schema_valid_ok += 1

            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        end_time = time.perf_counter()
        total_duration = end_time - start_time
        throughput_eps = round(count / max(total_duration, 0.001), 2)

        latencies_ms.sort()
        p50 = round(latencies_ms[int(len(latencies_ms) * 0.50)], 3) if latencies_ms else 0.0
        p95 = round(latencies_ms[int(len(latencies_ms) * 0.95)], 3) if latencies_ms else 0.0
        p99 = round(latencies_ms[int(len(latencies_ms) * 0.99)], 3) if latencies_ms else 0.0

        mem_end_mb = round(process.memory_info().rss / (1024 * 1024), 2)
        cpu_end = process.cpu_percent(interval=None)

        result = {
            "total_events": count,
            "workers": 1,
            "duration_seconds": round(total_duration, 3),
            "throughput_eps": throughput_eps,
            "p50_latency_ms": p50,
            "p95_latency_ms": p95,
            "p99_latency_ms": p99,
            "cpu_percent": round(cpu_end, 1),
            "memory_mb": mem_end_mb,
            "parse_success_percent": round((parsed_ok / count) * 100.0, 2),
            "schema_validation_percent": round((schema_valid_ok / count) * 100.0, 2),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        LAST_BENCHMARK_RESULT = result
        return result

    @classmethod
    def get_latest(cls) -> Dict[str, Any]:
        global LAST_BENCHMARK_RESULT
        if not LAST_BENCHMARK_RESULT:
            # Generate a lightweight initial baseline
            return cls.run_benchmark(count=500)
        return LAST_BENCHMARK_RESULT
