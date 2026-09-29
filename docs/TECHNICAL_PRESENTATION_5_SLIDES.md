# ULPF: Technical Presentation
### Universal Log Pre-processing Framework for Next-Gen SIEM & Cybersecurity
**Problem Statement ID:** 26156 | **Theme:** Cybersecurity | **Organization:** NTRO / NCIIPC

---

## 🖥️ SLIDE 1: Title & The Mission
* **Header:** Universal Log Pre-processing Framework (ULPF)
* **Subtitle:** Unified, Lossless, Air-Gapped Ingestion for Heterogeneous Perimeter Telemetry
* **Presenter Information:** Team SIH-26156 | National Technical Research Organisation (NTRO) Track

### Key Bullet Points:
* **The Challenge:** Modern critical information infrastructures (CII) encounter tens of millions of perimeter events daily across multi-vendor firewalls, VPNs, IDS/IPS, and routers.
* **The Reality:** 60%+ of security engineering time is wasted on building and repairing fragile, vendor-specific parsers. Incomplete transformations lead to forensic data loss and blind spots in SIEM/SOAR.
* **Our Solution:** A vendor-agnostic, plugin-driven preprocessing engine that ingests any perimeter log format, standardizes into a Universal Event Schema (UES), preserves 100% of raw data with SHA-256 validation, and operates completely offline in air-gapped zones.

> **Speaker Notes:** "Good morning, respected jury members. Today, national cybersecurity depends on rapid correlation across perimeter devices from Cisco, Palo Alto, Fortinet, Check Point, and custom appliances. Current pipelines either drop vital raw context during parsing or require constant manual parser updates. We present ULPF: a universal, plug-and-play framework built to deliver lossless, standardized, and AI-ready security telemetry at line rate."

---

## 🖥️ SLIDE 2: Core Architecture & Data Pipeline
* **Header:** Architecture: From Ingestion to Standardized Intelligence
* **Visual:** Pipeline Diagram showing (Ingestion Layer -> Format Auto-Detection -> Parser Plugins -> Normalization & Offline Enrichment -> Dual Storage & Egress)

### Key Architecture Highlights:
* **Multi-Protocol Ingestion:** High-speed UDP/TCP Syslog (514/5514), REST API Webhooks, and Kafka message streaming.
* **Auto-Detection Engine:** 10-step heuristic matching (CEF, LEEF, RFC5424/3164 Syslog, JSON, XML, CSV, Vendor Signatures) + Fallback Regex Segmentation.
* **Hot-Reloadable Plugin Engine:** Zero-downtime onboarding of new log formats by dropping modular Python plugins into runtime registry.
* **Offline Threat & Geo Enrichment:** Integrated local MaxMind GeoIP and local IOC Threat Intelligence lookup requiring zero internet connectivity.

> **Speaker Notes:** "Here is the architectural flow of ULPF. Logs enter through Syslog listeners or REST endpoints. Our heuristic format detector identifies the structure in microseconds. It dispatches to the corresponding parser plugin, extracts source attributes, applies declarative YAML mapping rules, and enriches with internal GeoIP and Threat Intel. All without outbound network requests."

---

## 🖥️ SLIDE 3: Universal Event Schema (UES) & The Lossless Guarantee
* **Header:** Standardized Taxonomy Without Forensic Compromise
* **Visual:** Side-by-side comparison of heterogeneous input logs (Cisco ASA, CEF, Fortinet) mapped into the uniform JSON UES structure.

### Key Capabilities:
* **Tamper-Evident Raw Storage:** `ulpf.raw` stores exact byte sequences, verified by `ulpf.raw_hash` (SHA-256) for non-repudiation in forensic investigations.
* **Standardized Outcomes:** Normalizes arbitrary vendor codes into canonical actions (`built`, `deny`, `accept`) and outcomes (`success`, `failure`).
* **Normalized Network & Host Primitives:** Unified typing for `source.ip`, `destination.ip`, ports, protocols, and interface mappings.
* **Bidirectional Traceability:** UUIDv4 generated at ingestion preserves direct linkage between analytics alerts and the underlying physical log string.

> **Speaker Notes:** "The cornerstone of ULPF is our Universal Event Schema. Compliance and forensic readiness demand that we never discard raw log data. ULPF embeds the complete unmodified raw log alongside its cryptographic SHA-256 hash. Whether a log originated from a FortiGate firewall or a legacy Syslog router, the downstream SIEM or ML model queries a single, unified schema."

---

## 🖥️ SLIDE 4: Working Prototype & Live Benchmarks
* **Header:** Production-Ready Prototype & Demonstrated Results
* **Visual:** Screenshot of the dark-themed ULPF Operations Dashboard displaying real-time event charts, ingested sources, and parsed logs.

### Demonstrated Capabilities in Working Prototype:
* **11+ Built-in Parsers:** Cisco ASA, Palo Alto PAN-OS, Fortinet FortiOS, Check Point, CEF (ArcSight), LEEF (QRadar), RFC3164, RFC5424, JSON, CSV, and Fallback.
* **100% Ingestion Success:** Demonstrated 86/86 sample logs successfully parsed across 7 heterogeneous device streams in live testing.
* **Full-Featured Dashboard:** Real-time event outcome metrics, full-text event explorer, source health analytics, and interactive log ingest tester.
* **Sub-5ms End-to-End Latency:** Lightweight, asynchronous Python core delivering low latency and minimal resource overhead.

> **Speaker Notes:** "Our prototype is not a mock-up — it is live right now. We have successfully ingested and parsed 86 multi-vendor perimeter logs across 7 distinct sources with 100% accuracy. The interactive dashboard allows security analysts to inspect normalized fields, view geo-enrichment, copy the raw log, and test new log formats on the fly."

---

## 🖥️ SLIDE 5: Strategic Impact, Air-Gap Readiness & Roadmap
* **Header:** Defense Relevance & Roadmap for National Security
* **Visual:** Matrix comparing Traditional SIEM Ingestion vs. ULPF Deployment.

### Strategic Differentiators:
* **Air-Gap Native:** Packaged with `docker-compose.yml`, self-contained offline threat feeds, and local SQLite/Parquet dual-storage. No internet or external API dependencies.
* **Reduced Parser Development Effort:** Onboard new device logs in under 15 minutes by declaring a YAML mapping file and single-method parser.
* **AI/ML Ready:** Prepares structured tabular features directly compatible with anomaly detection, graph neural networks, and UEBA models.
* **Deployment Roadmap:**
  - *Phase 1 (Current):* Standalone containerized core with 11+ perimeter parsers.
  - *Phase 2:* Distributed Kafka clustering & Apache Parquet cold-lake export.
  - *Phase 3:* LLM-assisted autonomous parser generation for zero-day proprietary log formats.

> **Speaker Notes:** "In conclusion, ULPF fulfills every NTRO problem requirement. It is platform-independent, containerized, air-gap ready, lossless, and dramatically cuts parser maintenance. ULPF turns chaotic perimeter noise into structured, actionable cyber intelligence. Thank you, and we welcome your questions."
