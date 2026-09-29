# Universal Log Pre-processing Framework (ULPF)
## System Architecture Document (Evaluation Copy)
**Problem Statement ID:** 26156 | **Theme:** Cybersecurity & Blockchain | **Organization:** NTRO / NCIIPC

---

### 1. Executive Summary & Problem Context
National security infrastructure and enterprise networks generate multi-gigabyte/sec telemetry across heterogeneous perimeter devices (Cisco ASA, Palo Alto PAN-OS, Fortinet FortiOS, Check Point, Juniper, Linux/Unix Syslog, and custom appliances). These logs arrive in discordant formats (RFC 3164/5424 Syslog, CEF, LEEF, Key-Value, JSON, XML, CSV). This heterogeneity causes:
1. High parser maintenance debt and fragile regex maintenance.
2. Forensic information loss during aggressive parsing.
3. High latency in downstream SIEM/SOC analytics and ML ingestion.
4. Deployment barriers in isolated, air-gapped critical information infrastructure (CII).

**ULPF** resolves this with a modular, vendor-agnostic, lossless, containerized pipeline that auto-detects, parses, enriches, and normalizes disparate streams into a canonical **Universal Event Schema (UES)** in real time.

---

### 2. High-Level Architectural Topology

```
+---------------------------------------------------------------------------------------------------+
|                                      INGESTION SUBSYSTEM                                          |
|  Syslog (UDP/TCP 514/5514)  |  REST / Webhooks (POST /api/ingest)  |  Kafka Queue / File Spool   |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                  PARSER ENGINE & DISCOVERY CORE                                   |
|   1. Heuristic Format Detector (CEF, LEEF, JSON, XML, CSV, RFC5424, RFC3164)                    |
|   2. Hot-Reloadable Plugin Registry (Zero-Downtime dynamic plugin loader)                         |
|   3. Vendor Plugins (Cisco ASA, Palo Alto, Fortinet, Check Point, etc.)                          |
|   4. Fallback Regular Expression & Token Segmenter                                               |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                NORMALIZATION & ENRICHMENT LAYER                                   |
|   • Declarative YAML Field Mapping Rules (Source-specific & Generic Aliases)                      |
|   • Strict Type Coercion (IP, Integer, Float, ISO-8601 UTC Timestamps)                            |
|   • Offline GeoIP Resolution (MaxMind GeoLite2 / Air-Gap Cache)                                   |
|   • Offline IOC & Threat Intelligence Triage (Local feed lookups)                                 |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                    DUAL-PERSISTENCE DATA LAKE                                     |
|   HOT STORE (Real-Time Search & UI)                 COLD STORE (Compliance & Forensics)           |
|   • SQLite WAL Engine / Elasticsearch 8.x           • Compressed Parquet / Object Store (MinIO)   |
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

### 3. Universal Event Schema (UES) Specifications

The UES guarantees zero forensic loss while providing standardized taxonomy alignment:

| Domain | Key Fields | Purpose |
|---|---|---|
| **`ulpf`** | `id` (UUIDv4), `ingest_timestamp`, `raw`, `raw_hash` (SHA-256), `parser_plugin`, `confidence` | **Forensic integrity & audit traceability**. Exact byte preservation without truncation. |
| **`event`** | `action` (e.g. built, deny), `outcome` (success/failure/unknown), `severity` (0-10 normalized), `code` | Standardized execution outcome for SIEM correlation and alerting. |
| **`source`** | `ip`, `port`, `geo` (country, city, ASN), `as` (organization) | Uniform initiator context with offline geo-enrichment. |
| **`destination`** | `ip`, `port`, `domain`, `geo` | Target asset identification. |
| **`network`** | `protocol` (tcp, udp, icmp), `direction` (inbound/outbound), `bytes`, `packets` | Layer 3/4 network accounting. |
| **`threat`** | `indicator`, `matched_feed`, `confidence`, `category` | Inline automated IOC tagging against local threat matrices. |

---

### 4. Critical Engineering Pillars

#### A. 100% Lossless Preservation & Tamper-Evident Traceability
Every ingested event permanently retains its original raw payload in `ulpf.raw`. Concurrently, an inline **SHA-256 checksum (`ulpf.raw_hash`)** is calculated before transformation. In forensic inquiries or legal discovery, analysts can demonstrate zero tampering from wire to storage.

#### B. Plug-and-Play Extensibility (Zero-Downtime Hot Reload)
New perimeter devices are onboarded without restarting the framework:
1. Place a Python parser subclassing `BaseParser` inside `parser_engine/plugins/`.
2. Define declarative translation mappings in `config/field_mappings/<source>.yaml`.
3. The `PluginRegistry` dynamically discovers, prioritizes, and activates the parser in < 50ms.

#### C. Air-Gapped Network Readiness
Critical Infrastructure networks (NCIIPC compliance) cannot query internet-based threat or DNS/GeoIP databases. ULPF is packaged with:
- Completely offline GeoIP resolution tables.
- Localized flat-file / SQLite threat intelligence IOC database.
- Self-contained container image (`docker-compose.yml`) runnable in totally isolated environments without WAN access.

#### D. Scalability & Big Data Integration
The decoupled architecture enables horizontal worker replication across Kafka consumer groups, scaling seamlessly to 10,000+ EPS per lightweight container worker while streaming to central data lakes (Parquet/MinIO) for deep ML modeling and threat hunting.
