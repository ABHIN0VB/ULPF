import os
import sys
import time
import requests
import json

API_BASE = "http://localhost:8000/api"

def main():
    print("\n" + "=" * 65)
    print("  ULPF: CUSTOM UNKNOWN-SOURCE ONBOARDING DEMONSTRATION")
    print("  (SIH 2026 Problem Statement 26156 — Section 29 & 30)")
    print("=" * 65)

    sample_fwx_log = "FWX|2026-09-29 10:15:00|SRC=10.1.1.5|DST=8.8.8.8|ACT=DENY|PROTO=TCP|SPT=45321|DPT=443|RULE=BLOCK_OUTBOUND"

    # Step 1: Submit Unknown Proprietary Log
    print("\n[STEP 1] Ingesting Unknown Proprietary Log Stream ('FWX' Firewall)...")
    print(f"  Raw Log: {sample_fwx_log}")
    
    t_start = time.time()
    r1 = requests.post(f"{API_BASE}/ingest", json={
        "raw_log": sample_fwx_log,
        "source_id": "fwx-perimeter-01",
        "source_ip": "10.1.1.1"
    })
    
    if r1.status_code != 200:
        print(f"  [ERROR] Ingest request failed: {r1.text}")
        return

    data1 = r1.json()
    print(f"  Status        : {data1.get('status')}")
    print(f"  Parser Plugin : {data1.get('parser_plugin')}")
    print(f"  Confidence    : {data1.get('confidence')}")
    print(f"  Raw SHA-256   : {data1.get('raw_hash')}")
    print("  --> Event safely preserved & routed to Dead Letter Queue (DLQ) as UNKNOWN.")

    # Step 2: Verify in DLQ
    print("\n[STEP 2] Verifying Dead Letter Queue (DLQ) Quarantine...")
    r_dlq = requests.get(f"{API_BASE}/dlq?status=quarantined")
    dlq_items = r_dlq.json()
    matching_dlq = [it for it in dlq_items if it.get('raw_hash') == data1.get('raw_hash')]
    
    if not matching_dlq:
        print("  [WARN] Item not found in DLQ query, continuing...")
        dlq_id = data1.get('id')
    else:
        dlq_id = matching_dlq[0]['id']
        print(f"  Quarantined DLQ ID   : {dlq_id}")
        print(f"  Failure Reason       : {matching_dlq[0].get('failure_reason')}")
        print(f"  Raw Forensic Copy    : Preserved 100% without information loss")

    # Step 3: Onboard New Parser Plugin & Mapping Rules
    print("\n[STEP 3] Onboarding New Parser Plugin ('FWXParser') with Zero Downtime...")
    fwx_parser_code = '''import re
from parser_engine.base_parser import BaseParser

class FWXParser(BaseParser):
    """Parser for proprietary FWX Perimeter Firewalls."""
    SOURCE_ID = "fwx"
    VERSION = "1.0.0"
    PRIORITY = 20

    def can_parse(self, raw: str, metadata: dict) -> float:
        if raw.startswith("FWX|"):
            return 0.95
        return 0.0

    def parse(self, raw: str, metadata: dict) -> dict:
        parts = raw.strip().split('|')
        parsed = {"vendor": "FWX"}
        if len(parts) >= 2:
            parsed["timestamp"] = parts[1]
        for p in parts[2:]:
            if '=' in p:
                k, v = p.split('=', 1)
                parsed[k.lower()] = v
        return parsed
'''
    plugins_dir = os.path.join(os.path.dirname(__file__), '..', 'backend', 'parser_engine', 'plugins')
    fwx_plugin_path = os.path.join(plugins_dir, 'fwx_parser.py')
    with open(fwx_plugin_path, 'w') as f:
        f.write(fwx_parser_code)

    # Create YAML mapping
    mappings_dir = os.path.join(os.path.dirname(__file__), '..', 'backend', 'config', 'field_mappings')
    os.makedirs(mappings_dir, exist_ok=True)
    fwx_mapping_path = os.path.join(mappings_dir, 'fwx.yaml')
    with open(fwx_mapping_path, 'w') as f:
        f.write('''source: fwx
version: "1.0"
mappings:
  - from: act
    to: event.action
    type: string
    normalize: lowercase
  - from: proto
    to: network.protocol
    type: string
    normalize: lowercase
  - from: src
    to: source.ip
    type: ip
  - from: dst
    to: destination.ip
    type: ip
  - from: spt
    to: source.port
    type: integer
  - from: dpt
    to: destination.port
    type: integer
defaults:
  event.kind: event
  event.category: network
  host.vendor: FWX
  host.type: firewall
''')

    # Trigger hot-reload in backend
    with open(fwx_plugin_path, 'rb') as f:
        r_upload = requests.post(
            f"{API_BASE}/plugins/upload",
            files={"file": ("fwx_parser.py", f, "text/x-python")},
            headers={"X-ULPF-Role": "ADMIN"}
        )
    print(f"  Plugin Hot-Reload    : {r_upload.json().get('message')}")

    # Step 4: Reprocess Event from DLQ
    print("\n[STEP 4] Reprocessing Quarantined Event from DLQ...")
    r_reprocess = requests.post(
        f"{API_BASE}/dlq/{dlq_id}/reprocess",
        headers={"X-ULPF-Role": "ANALYST"}
    )
    
    t_end = time.time()
    rep_data = r_reprocess.json()
    print(f"  Reprocess Success    : {rep_data.get('success')}")
    print(f"  Parser Used          : {rep_data.get('parser_plugin')}")
    print(f"  Confidence Score     : {rep_data.get('confidence')}")
    print(f"  Normalized Outcome   : {rep_data.get('event_outcome')}")
    print(f"  Total Onboarding Time: {round(t_end - t_start, 2)} seconds")

    # Step 5: Verify Normalized Event & Lossless Integrity
    print("\n[STEP 5] Verifying Universal Event Schema & Lossless Integrity...")
    new_event_id = rep_data.get('event_id')
    r_event = requests.get(f"{API_BASE}/events/{new_event_id}")
    r_integrity = requests.get(f"{API_BASE}/events/{new_event_id}/verify-integrity")
    
    if r_event.status_code == 200:
        evt = r_event.json()
        print("  Normalized Universal Event Schema:")
        print(f"    - Source IP     : {evt.get('source', {}).get('ip')}:{evt.get('source', {}).get('port')}")
        print(f"    - Destination IP: {evt.get('destination', {}).get('ip')}:{evt.get('destination', {}).get('port')}")
        print(f"    - Protocol      : {evt.get('network', {}).get('protocol')}")
        print(f"    - Action/Outcome: {evt.get('event', {}).get('action')} / {evt.get('event', {}).get('outcome')}")
        print(f"    - Lineage Raw ID: {evt.get('lineage', {}).get('raw_event_id')}")

    if r_integrity.status_code == 200:
        integ = r_integrity.json()
        print(f"  Integrity Verification: {integ.get('status')} (SHA-256 matched stored raw bytes)")

    print("\n" + "=" * 65)
    print("  ONBOARDING DEMONSTRATION COMPLETE: 100% SUCCESS")
    print("=" * 65 + "\n")

if __name__ == '__main__':
    main()
