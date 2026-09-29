# ULPF: 2-Minute Demonstration Video Script
### Universal Log Pre-processing Framework (SIH 2026 | PS 26156 | NTRO)
**Total Target Duration:** 120 Seconds (2:00 Minutes)

---

## 🎬 Storyboard & Timestamp Breakdown

| Timestamp | Video Visual (On-Screen Action) | Voiceover Script (Audio) |
|---|---|---|
| **0:00 - 0:15** (15s) | **Opening Title & Problem Context:**<br>Show terminal displaying 5 disparate raw log files (Cisco ASA, Palo Alto CSV, Fortinet key-value, CEF, raw Syslog). Highlight the chaos of unformatted security logs. | *"Perimeter security teams deal with billions of logs daily across firewalls, routers, and VPNs—each with conflicting structures. Building parsers manually creates massive delays and risks losing critical forensic evidence."* |
| **0:15 - 0:35** (20s) | **System Architecture & Startup:**<br>Brief flash of the ULPF architecture diagram. Open terminal, execute `docker-compose up` or start `python -m uvicorn main:app`. Show terminal log: *`Loaded 11 parser plugins`* and *`Syslog receiver listening on port 5514`*. | *"Meet ULPF: the Universal Log Pre-processing Framework. Containerized, air-gap ready, and vendor-agnostic. In one command, ULPF boots with 11 native perimeter parsers and an integrated syslog listener."* |
| **0:35 - 0:55** (20s) | **Live Dashboard & Overview:**<br>Switch browser to `http://localhost:8000`. Show Overview page with dynamic charts (Chart.js): Total Events, Events by Outcome (Donut chart), Events by Source, and Recent Events table. | *"Here is the ULPF Operations Dashboard. In real-time, the system visualizes event throughput, outcome classifications, and per-device breakdown across all active network assets."* |
| **0:55 - 1:20** (25s) | **Lossless Normalization & Forensics:**<br>Navigate to **Event Search** (`#events`). Filter by outcome: `failure`. Click on a Cisco ASA Deny event. Open the modal.<br>• Tab 1: Show the clean, standardized Universal Event Schema JSON.<br>• Tab 2: Click **Raw Log** tab. Show original string and SHA-256 hash. | *"Every incoming log is transformed into our Universal Event Schema, normalizing IPs, ports, and action outcomes. Crucially, ULPF is 100% lossless: the exact original log is preserved alongside its SHA-256 cryptographic hash for tamper-evident compliance."* |
| **1:20 - 1:40** (20s) | **Plug-and-Play Ingestion & Live Parsing:**<br>Navigate to **Ingest Tester** (`#ingest`). Click preset button: **'Load FortiGate Sample'**. Click **'Ingest Log'**.<br>Show instant notification: *`Detected FortinetParser (Confidence: 0.90) | Outcome: Success`*. | *"ULPF makes onboarding plug-and-play. In our Ingest Tester, we paste an unparsed FortiGate log. The heuristic engine auto-detects the format with 90% confidence, enriches geo-coordinates offline, and commits it to the event store in sub-5 milliseconds."* |
| **1:40 - 2:00** (20s) | **Plugin Manager, Air-Gap & Closing:**<br>Navigate to **Plugins** (`#plugins`). Show list of hot-reloadable parsers and the drag-and-drop plugin uploader. Show concluding slide with NTRO theme, GitHub repository link, and key strengths. | *"With zero-downtime hot-reloadable plugins, offline threat-intelligence lookups, and full air-gap compatibility, ULPF turns heterogeneous network noise into actionable, forensic-grade cybersecurity intelligence. Thank you."* |

---

## 💡 Tips for Recording the Video
1. **Screen Resolution:** Record at 1920x1080 (16:9).
2. **Audio Track:** Use a noise-canceling microphone; speak at an energetic, brisk pace (~140 words per minute).
3. **Cursor Visibility:** Enable a soft yellow halo on mouse clicks for visual clarity.
4. **Pre-populated Data:** Run `powershell .\scripts\ingest_samples.ps1` before recording so all charts have data ready from second 0:35.
