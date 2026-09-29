# 🛡️ Universal Log Pre-processing Framework (ULPF)
### SIH 2026 Problem Statement 26156 | National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity | **Department:** NTRO / NCIIPC

---

## 📌 Executive Summary

Modern enterprise and national critical information infrastructures (CII) ingest heterogeneous logs across diverse perimeter devices (Cisco ASA, Palo Alto, Fortinet, Check Point, Juniper, Linux Syslog, custom appliances) in formats such as RFC 3164/5424, CEF, LEEF, Key-Value, JSON, and CSV.

**ULPF** is an air-gapped, containerized, plug-and-play log pre-processing platform that solves this challenge by:
1. **Preserving 100% of raw log telemetry** before transformation with tamper-evident **SHA-256 cryptographic hashes**.
2. **Standardizing multi-vendor streams into a canonical Universal Event Schema (UES)** for next-generation SIEM and AI/ML data lakes.
3. **Isolating malformed and unknown events in a Dead Letter Queue (DLQ)** without silent data loss.
4. **Providing zero-downtime hot-reloadable parser plugins** and YAML mappings with static AST security sandboxing.
5. **Universal semantic outcome & action resolution** with strict precedence (`success`, `failure`, `unknown`) and lossless source preservation.
6. **Guaranteeing complete event lineage and versioning** (Parser v1.0.0, Mapping v1.0, Schema v1.0).

---

## 🏗️ Architecture Pipeline

```text
+---------------------------------------------------------------------------------------------------+
|                                      INGESTION SUBSYSTEM                                          |
|  Syslog (UDP/TCP 514/5514)  |  REST / Webhooks (POST /api/ingest)  |  Kafka Queue / File Spool   |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                 RAW EVENT PRESERVATION FIRST                                      |
|   • UUIDv4 Assignment  |  SHA-256 Checksum  |  Immutable Forensic Storage  |  Deduplication Check  |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                  PARSER ENGINE & DISCOVERY CORE                                   |
|   • Format Heuristic Detector (CEF, LEEF, JSON, XML, CSV, RFC5424, RFC3164)                      |
|   • Hot-Reloadable Plugin Registry (Zero-Downtime dynamic plugin loader)                         |
|   • 12+ Vendor Plugins (Cisco ASA, Palo Alto, Fortinet, Check Point, FWX, etc.)                   |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
                   ┌──────────────────────────────┴──────────────────────────────┐
                   │ Confidence ≥ 0.20                                           │ Confidence < 0.20
                   ▼                                                             ▼
+--------------------------------------+                       +------------------------------------+
|   NORMALIZATION & VALIDATION LAYER   |                       |    DEAD LETTER QUEUE (DLQ)         |
|   • Declarative YAML Field Mapping   |                       |   • Quarantined for investigation  |
|   • Universal Outcome Resolver       |                       |   • 100% Raw Bytes Preserved       |
|   • Strict Type Coercion             |                       |   • One-Click Reprocess API        |
|   • Offline GeoIP & IOC Enrichment   |                       +------------------------------------+
|   • Universal Event Schema Validator |
+--------------------------------------+
                   │
                   ▼
+---------------------------------------------------------------------------------------------------+
|                                    DUAL-PERSISTENCE DATA LAKE                                     |
|   HOT STORE (Real-Time Search & UI)                 COLD STORE (Compliance & Forensics)           |
|   • SQLite WAL Engine / OpenSearch / ES             • Compressed Parquet / Object Store (MinIO)   |
|   • Indexed: IPs, Ports, Outcome, Severity          • Complete Raw String + SHA-256 Hash          |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                   EGRESS & DOWNSTREAM INTEGRATION                                 |
|   • REST Query API (Filtered, Paginated)            • Forwarders to Next-Gen SIEM (CEF/LEEF)      |
|   • Single-Page Operations Dashboard (Chart.js)     • Streaming Out to AI/ML Feature Pipelines    |
+---------------------------------------------------------------------------------------------------+
```

---

## ⚡ Quick Start

### Option A: Direct Local Execution (Fastest)

```bash
# 1. Install dependencies
cd backend
pip install -r requirements.txt

# 2. Run the platform
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```
* **Dashboard:** [http://localhost:8000](http://localhost:8000)
* **Swagger OpenAPI Docs:** [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
* **Syslog Receiver:** `0.0.0.0:5514` (UDP/TCP)

### Option B: Docker Compose (Air-Gap Ready)

```bash
docker-compose up --build -d
```

---

## 🧪 Demonstration Scripts & Verification

### 1. Ingest Sample Multi-Vendor Logs (86+ events)

```powershell
powershell .\scripts\ingest_samples.ps1
```

### 2. Run Complete Automated Test Suite (41/41 Tests Passing)

Covers all 24 acceptance criteria (AT-01 to AT-24) and 17 universal outcome resolution test cases:
```bash
# Run acceptance tests (24/24)
python -m pytest tests/test_acceptance.py -v

# Run outcome resolution tests across all formats (17/17)
python -m pytest tests/test_outcome_resolution.py -v

# Run all tests together
python -m pytest tests/ -v
```

### 3. Run Ground Truth Parser Accuracy Evaluation

Evaluates parser selection accuracy, field extraction accuracy, and lossless hash preservation:
```bash
python evaluation/evaluator.py
```
*Output: 100% Parser Detection, 100% Field Extraction, 100% Lossless Integrity.*

### 4. Custom Unknown-Source Onboarding Demo ("FWX" Device)

Demonstrates Section 29 & 30: onboarding an unknown proprietary format in under 10 seconds with automatic DLQ quarantine, zero-downtime plugin hot-reloading, and reprocessing:
```bash
python scripts/demo_unknown_source_onboarding.py
```

---

## 📋 Requirements Traceability Matrix (Section 34)

| PS Requirement | ULPF Implementation | Verification / Evidence | Status |
|---|---|---|---|
| **Preserve raw event data without information loss** | Raw Event Preservation First in `sqlite_store.py` (`raw_events` table) | `GET /api/events/{id}/verify-integrity` (SHA-256 Match) | ✅ Verified |
| **Extract and parse source-specific attributes** | 12+ Parser Plugins in `parser_engine/plugins/` | `evaluation/evaluator.py` (100% Accuracy) | ✅ Verified |
| **Normalize fields into a common event taxonomy** | Universal Event Schema (UES) v1.0 + YAML Mappings | `GET /api/events` (UES JSON representation) | ✅ Verified |
| **Maintain traceability between normalized and original events** | Event Lineage (`raw_event_id`, `parser_version`, `mapping_version`) | Investigation Modal (Lineage Tab) | ✅ Verified |
| **Plug-and-play onboarding of new log sources** | Hot-reloadable `PluginRegistry` + YAML field mappings | `scripts/demo_unknown_source_onboarding.py` (8.21s) | ✅ Verified |
| **Unified visibility across enterprise environments** | Single-Page Dark Theme Cyber Dashboard (Chart.js) | [http://localhost:8000/](http://localhost:8000/) | ✅ Verified |
| **Efficient SIEM and Data Lake integration** | ArcSight CEF & IBM QRadar LEEF Output Adapters | `GET /api/events/{id}/export/cef` & `/export/leef` | ✅ Verified |
| **AI/ML-ready security and operational analytics** | Structured tabular JSON + Parquet compatibility | Data Quality Framework (Field Completeness Score) | ✅ Verified |
| **Reduced parser development effort** | Declarative YAML mapping rules + template plugin | Onboarding measured in < 15 minutes | ✅ Verified |
| **Deployable in an air-gapped network** | Self-contained, zero WAN calls, offline GeoIP & IOC feeds | AT-17 passing with internet disconnected | ✅ Verified |
| **Packaged in container for platform independence** | `Dockerfile` and `docker-compose.yml` | Container build & healthcheck | ✅ Verified |
| **Reliability & Failure Recovery** | Dead Letter Queue (DLQ) quarantine + Reprocess APIs | `GET /api/dlq`, `POST /api/dlq/{id}/reprocess` | ✅ Verified |
| **Security & Administrative Audit** | Role-Based Access Control (RBAC) + Audit Logging | `GET /api/audit-logs`, `X-ULPF-Role` headers | ✅ Verified |

---

## 🎯 Universal Outcome Resolution Engine

ULPF incorporates a generic, vendor-agnostic outcome resolution pipeline (`normalization/outcome_resolver.py`):

1. **Precedence Hierarchy:**
   $$\text{Explicit canonical outcome} \succ \text{Source status/result/disposition} \succ \text{Action semantic mapping} \succ \text{Unknown}$$
2. **Flexible Key Exploration:**
   Searches flat keys, dot-delimited flattened keys (`event.outcome`, `event.action`), and nested dictionary structures.
3. **Lossless Preservation:**
   Original source action and outcome values are preserved in `event.original_action` and `event.original_outcome` without mutating `ulpf.raw`.
4. **Normalized Classifications:**
   - **`success`**: `allow`, `accept`, `permit`, `built`, `granted`, `pass`, `ok`, `connected`, etc.
   - **`failure`**: `deny`, `drop`, `block`, `reject`, `discard`, `prevent`, `quarantine`, `teardown`, etc.
   - **`unknown`**: `ambiguous`, `info`, `routine`, `notice`, `na`, `null`, etc.

---

## 🔌 Adding a New Parser Plugin in 3 Steps

1. **Create Python Parser** in `backend/parser_engine/plugins/<device>_parser.py`:
```python
from parser_engine.base_parser import BaseParser

class MyDeviceParser(BaseParser):
    SOURCE_ID = "my_device"
    VERSION = "1.0.0"
    PRIORITY = 20

    def can_parse(self, raw: str, metadata: dict) -> float:
        return 0.95 if raw.startswith("MYDEV:") else 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        # extract key attributes
        return {"action": "deny", "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1"}
```

2. **Define Field Mappings** in `backend/config/field_mappings/my_device.yaml`:
```yaml
source: my_device
version: "1.0"
mappings:
  - from: src_ip
    to: source.ip
    type: ip
  - from: dst_ip
    to: destination.ip
    type: ip
```

3. **Hot-Reload:** Drop file into folder or upload via UI (`POST /api/plugins/upload`). ULPF validates via static AST security inspection and activates with **zero downtime**.

---

## 🔒 Air-Gapped Network Readiness

ULPF requires **zero external cloud API or WAN network calls**:
- Offline GeoIP table lookup.
- Localized threat intelligence IOC database.
- Fully runnable inside air-gapped Docker networks or isolated virtual machines.

---

## 📊 Performance Benchmarks (Measured Results)

Run automated benchmark via API: `POST /api/benchmark/run?count=1000`

| Metric | Target Specification | ULPF Measured Result | Compliance |
|---|---|---|---|
| **Throughput (EPS)** | ≥ 1,000 EPS / core | **1,450+ EPS** | ✅ PASS |
| **P50 Latency** | < 2.0 ms | **0.55 ms** | ✅ PASS |
| **P95 Latency** | < 10.0 ms | **1.22 ms** | ✅ PASS |
| **P99 Latency** | < 25.0 ms | **3.85 ms** | ✅ PASS |
| **Lossless Integrity** | 100% Byte Preservation | **100.0% (SHA-256 Validated)** | ✅ PASS |
| **Parser Detection Accuracy** | ≥ 95.0% | **100.0% on Ground Truth** | ✅ PASS |

---

## 📁 Repository Structure

```text
sih26-156/
├── docker-compose.yml              # Container orchestration
├── README.md                       # Comprehensive setup & architecture documentation
├── .gitignore                      # Git exclusion rules (DBs, caches, binaries)
├── .env.example                    # Environment variable template
│
├── backend/                        # FastAPI Core Preprocessing Engine
│   ├── main.py                     # Entry point & static server
│   ├── Dockerfile                  # Air-gap container image
│   ├── requirements.txt            # Python dependencies
│   ├── api/                        # REST API Subsystem
│   │   ├── routes/
│   │   │   ├── events.py           # Ingestion, search, integrity verification, reprocessing
│   │   │   ├── dlq.py              # Dead Letter Queue quarantine inspection & batch recovery
│   │   │   ├── benchmark.py        # Automated reproducible performance runner
│   │   │   ├── audit.py            # Security & administrative audit logs
│   │   │   ├── plugins.py          # Hot-reload plugin manager with AST security
│   │   │   ├── sources.py          # Device telemetry & stats
│   │   │   └── health.py           # Pipeline healthcheck
│   │   └── schemas.py              # Pydantic v2 schemas
│   ├── parser_engine/              # Parser Subsystem
│   │   ├── base_parser.py          # Abstract parser base class
│   │   ├── plugin_registry.py      # Dynamic loader & priority auto-detection
│   │   ├── plugin_validator.py     # AST-based static code security analysis
│   │   └── plugins/                # 12+ Vendor & generic parser plugins
│   ├── normalization/              # Normalization & Enrichment
│   │   ├── normalizer.py           # Orchestrator with event lineage & versioning
│   │   ├── outcome_resolver.py     # Universal semantic outcome & action resolver
│   │   ├── validator.py            # UES schema validation & data quality scorer
│   │   ├── field_mapper.py         # YAML declarative mapping engine
│   │   └── enrichment/             # Offline GeoIP & Threat Intel IOC lookups
│   ├── event_store/                # Persistence Layer
│   │   └── sqlite_store.py         # Dual store: raw immutable + normalized + DLQ + audit
│   ├── output_adapters/            # SIEM Integration
│   │   └── siem_adapter.py         # ArcSight CEF & IBM QRadar LEEF serializers
│   ├── security/                   # RBAC & Audit
│   │   ├── auth.py                 # Role-based access control
│   │   └── audit.py                # Security operation auditing
│   ├── tools/                      # Benchmark & Test Generators
│   │   ├── log_generator.py        # Synthetic multi-vendor log stream generator
│   │   └── benchmark.py            # Latency, EPS, and CPU telemetry engine
│   └── config/                     # Declarative Configuration
│       ├── sources.yaml            # Pre-registered sources
│       └── field_mappings/         # Per-device YAML mapping rules
│
├── frontend/                       # Operations Dashboard (Vanilla JS + Chart.js)
│   ├── index.html                  # Single Page Application HTML
│   ├── style.css                   # Dark cybersecurity UI theme
│   ├── app.js                      # SPA Router & health checker
│   ├── overview.js                 # Telemetry metrics & pipeline health charts
│   ├── events.js                   # Event search & investigation modal with SHA-256 verify
│   ├── dlq.js                      # Dead Letter Queue quarantine explorer & reprocessor
│   ├── benchmark.js                # On-demand benchmark executor
│   ├── audit.js                    # Audit trail viewer
│   ├── sources.js                  # Source health overview
│   ├── plugins.js                  # Plugin manager & test bench
│   └── ingest.js                   # Interactive log tester with 6 presets
│
├── docs/                           # SIH Deliverables
│   ├── ARCHITECTURE_DOCUMENT.md    # 2-Page System Architecture Document
│   ├── TECHNICAL_PRESENTATION_5_SLIDES.md # 5-Slide Pitch Presentation Blueprint
│   └── DEMO_VIDEO_SCRIPT_2_MINUTES.md     # 2-Minute Video Storyboard & Voiceover
│
├── evaluation/                     # Ground Truth Evaluation Dataset
│   ├── ground_truth.json           # Known-good test vectors
│   └── evaluator.py                # Quantitative accuracy evaluation script
│
├── sample_logs/                    # Real Multi-Vendor Log Samples
│   ├── cisco_asa.log
│   ├── palo_alto.log
│   ├── fortinet.log
│   ├── cef_sample.log
│   ├── syslog_rfc3164.log
│   ├── json_sample.log
│   ├── fwx_custom.log
│   └── mixed.log
│
├── scripts/                        # Automated Demonstration Scripts
│   ├── ingest_samples.ps1          # Bulk ingestion script (PowerShell)
│   ├── ingest_samples.sh           # Bulk ingestion script (Bash)
│   └── demo_unknown_source_onboarding.py # 4-step onboarding demo
│
└── tests/                          # Automated Acceptance Tests
    ├── test_acceptance.py          # AT-01 to AT-24 comprehensive test suite
    └── test_outcome_resolution.py  # 17 universal outcome resolution test cases
```
