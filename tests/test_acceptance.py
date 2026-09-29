import os
import sys
import pytest
import hashlib
import json
from fastapi.testclient import TestClient

# Put backend on path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_path)

from main import app
from parser_engine.plugin_registry import PluginRegistry
from event_store.sqlite_store import SQLiteEventStore
from normalization.normalizer import normalize
from output_adapters.siem_adapter import SIEMAdapter
from tools.log_generator import SyntheticLogGenerator
from tools.benchmark import PerformanceBenchmark

client = TestClient(app)

# Ensure app is initialized
@pytest.fixture(scope="module", autouse=True)
def init_app():
    test_db = os.path.join(backend_path, "test_acceptance.db")
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass
    app.state.event_store = SQLiteEventStore(test_db)
    app.state.plugin_registry = PluginRegistry()
    app.state.start_time = 0
    yield
    # Cleanup
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass

def test_at01_cisco_asa_normalization():
    raw = "%ASA-6-302013: Built outbound TCP connection 12345 for outside:203.0.113.5/80 (203.0.113.5/80) to inside:10.0.0.100/54321 (10.0.0.100/54321)"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cisco-fw", "source_ip": "10.0.0.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["parser_plugin"] == "CiscoASAParser"
    assert data["event_action"] == "built"
    assert data["event_outcome"] == "success"

def test_at02_fortinet_normalization():
    raw = "date=2026-09-29 time=10:30:00 devname=FGT devid=FGT123 logid=0000000013 type=traffic subtype=forward srcip=192.168.1.10 srcport=54321 dstip=8.8.8.8 dstport=53 proto=17 action=accept"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "fgt-branch"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["parser_plugin"] == "FortinetParser"
    assert data["event_outcome"] == "success"

def test_at03_palo_alto_normalization():
    raw = "1705310200,002201234567,TRAFFIC,end,2049,2026/09/29 10:00:00,192.168.1.10,8.8.8.8,0.0.0.0,0.0.0.0,AllowRule,jdoe,,,ssl,vsys1,trust,untrust,ae1,ae2,Panorama,2026/09/29 10:00:01,1234,1,54321,443,0,0,0x400000,tcp,allow,100,50,50,5,2026/09/29 10:00:00,60,any,0,12345,0x0,US,US,0,3,2,tcp-fin,CORP,jdoe,0,1,2,N/A,0,0,0,0,GP"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "pa-ngfw"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["parser_plugin"] == "PaloAltoParser"

def test_at04_json_normalization():
    raw = json.dumps({"source_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "action": "deny", "port": 443, "protocol": "tcp"})
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cloud-app"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["parser_plugin"] == "JsonParser"
    assert data["event_outcome"] == "failure"

def test_at05_cef_normalization():
    raw = "CEF:0|VendorA|DeviceB|1.0|100|Login Denied|7|src=203.0.113.99 spt=4521 dst=10.0.0.1 dpt=22 proto=TCP act=Deny"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "siem-collector"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["parser_plugin"] == "CEFParser"

def test_at06_unknown_event_preservation():
    unknown_raw = "MY_CUSTOM_DEVICE_OUTPUT: 12345-AB-NOT-RECOGNIZED-RANDOM-DATA"
    resp = client.post("/api/ingest", json={"raw_log": unknown_raw, "source_id": "custom-dev"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "quarantined_dlq"
    # Verify raw event was preserved
    raw_resp = client.get(f"/api/events/{data['id']}/raw")
    assert raw_resp.status_code == 200
    assert raw_resp.json()["raw"] == unknown_raw

def test_at07_malformed_event_routed_to_dlq():
    malformed = "INVALID<<<MALFORMED>>>LOG::;;@@"
    resp = client.post("/api/ingest", json={"raw_log": malformed, "source_id": "broken-stream"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "quarantined_dlq"
    dlq_resp = client.get("/api/dlq?status=quarantined")
    items = dlq_resp.json()
    hashes = [it["raw_hash"] for it in items]
    expected_hash = hashlib.sha256(malformed.encode()).hexdigest()
    assert expected_hash in hashes

def test_at08_raw_event_integrity_verification():
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.50/1234 dst inside:10.0.0.1/443"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "integrity-fw"})
    event_id = resp.json()["id"]
    ver_resp = client.get(f"/api/events/{event_id}/verify-integrity")
    assert ver_resp.status_code == 200
    assert ver_resp.json()["verified"] is True
    assert ver_resp.json()["status"] == "VERIFIED"

def test_at09_duplicate_event_detection():
    raw = "%ASA-6-302013: Built outbound TCP connection 9999 for outside:1.1.1.1/80 to inside:10.0.0.2/1234"
    # First ingest
    r1 = client.post("/api/ingest", json={"raw_log": raw, "source_id": "dedup-src"})
    assert r1.json()["is_duplicate"] is False
    # Immediate second ingest of identical log from same source
    r2 = client.post("/api/ingest", json={"raw_log": raw, "source_id": "dedup-src"})
    assert r2.json()["is_duplicate"] is True

def test_at10_new_parser_onboarded_dynamically():
    sample_code = b"""from parser_engine.base_parser import BaseParser
class DynamicDemoParser(BaseParser):
    SOURCE_ID = "dynamic_demo"
    VERSION = "1.0.0"
    PRIORITY = 20
    def can_parse(self, raw, meta): return 0.99 if raw.startswith("DYNAMIC_DEMO:") else 0.0
    def parse(self, raw, meta): return {"action": "allow", "protocol": "tcp"}
"""
    upload_resp = client.post(
        "/api/plugins/upload",
        files={"file": ("dynamic_demo_parser.py", sample_code, "text/x-python")},
        headers={"X-ULPF-Role": "ADMIN"}
    )
    assert upload_resp.status_code == 200
    # Test that newly uploaded parser immediately parses logs
    test_raw = "DYNAMIC_DEMO: status=ok src=1.2.3.4"
    ingest_resp = client.post("/api/ingest", json={"raw_log": test_raw, "source_id": "dyn"})
    assert ingest_resp.json()["parser_plugin"] == "DynamicDemoParser"

def test_at11_parser_version_recorded():
    raw = "%ASA-6-302013: Built outbound TCP connection 5555 for outside:8.8.8.8/80 to inside:10.0.0.1/80"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "ver-test"})
    evt_id = resp.json()["id"]
    evt = client.get(f"/api/events/{evt_id}").json()
    assert "parser" in evt
    assert "version" in evt["parser"]

def test_at12_schema_version_recorded():
    raw = "%ASA-6-302013: Built outbound TCP connection 5556 for outside:8.8.8.8/80 to inside:10.0.0.1/80"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "ver-test-2"})
    evt_id = resp.json()["id"]
    evt = client.get(f"/api/events/{evt_id}").json()
    assert evt["ulpf"]["schema_name"] == "ULPF"
    assert evt["ulpf"]["schema_version"] == "1.0"

def test_at13_event_lineage_reconstruction():
    raw = "%ASA-6-302013: Built outbound TCP connection 5557 for outside:8.8.8.8/80 to inside:10.0.0.1/80"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "lineage-test"})
    evt_id = resp.json()["id"]
    evt = client.get(f"/api/events/{evt_id}").json()
    lineage = evt["lineage"]
    assert lineage["raw_event_id"] is not None
    assert lineage["parser_version"] is not None
    assert lineage["mapping_version"] is not None

def test_at14_raw_event_retrieval():
    raw = "%ASA-6-302013: Built outbound TCP connection 5558 for outside:8.8.8.8/80 to inside:10.0.0.1/80"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "raw-test"})
    evt_id = resp.json()["id"]
    raw_res = client.get(f"/api/events/{evt_id}/raw")
    assert raw_res.status_code == 200
    assert raw_res.json()["raw"] == raw

def test_at15_events_searchable_by_filters():
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.123/1234 dst inside:10.0.0.1/80"
    client.post("/api/ingest", json={"raw_log": raw, "source_id": "search-src"})
    search_res = client.get("/api/events?src_ip=203.0.113.123")
    assert search_res.status_code == 200
    items = search_res.json()
    assert len(items) >= 1
    assert items[0]["src_ip"] == "203.0.113.123"

def test_at16_siem_cef_leef_generation():
    raw = "%ASA-6-302013: Built outbound TCP connection 7777 for outside:203.0.113.5/80 to inside:10.0.0.100/54321"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "siem-test"})
    evt_id = resp.json()["id"]
    
    cef_res = client.get(f"/api/events/{evt_id}/export/cef")
    assert cef_res.status_code == 200
    assert cef_res.json()["payload"].startswith("CEF:0|")

    leef_res = client.get(f"/api/events/{evt_id}/export/leef")
    assert leef_res.status_code == 200
    assert leef_res.json()["payload"].startswith("LEEF:1.0|")

def test_at17_offline_air_gapped_operation():
    # Verify local GeoIP mock and Threat Intel operate with zero external WAN dependency
    from normalization.enrichment import geoip_mock, threat_intel
    geo = geoip_mock.enrich_ip("203.0.113.5")
    assert geo["country_iso_code"] == "CN"
    ti = threat_intel.check_ip("203.0.113.5")
    assert ti["matched"] is True

def test_at18_docker_artifacts_present():
    root = os.path.abspath(os.path.join(backend_path, ".."))
    assert os.path.exists(os.path.join(root, "docker-compose.yml"))
    assert os.path.exists(os.path.join(backend_path, "Dockerfile"))

def test_at19_synthetic_log_generation():
    logs = SyntheticLogGenerator.generate_batch(50)
    assert len(logs) == 50
    assert "raw_log" in logs[0]
    assert "source_id" in logs[0]

def test_at20_benchmark_execution():
    bench = PerformanceBenchmark.run_benchmark(count=100)
    assert bench["throughput_eps"] > 0
    assert bench["parse_success_percent"] >= 90.0

def test_at21_rbac_enforcement():
    # VIEWER cannot upload plugins
    sample_code = b"print('test')"
    resp = client.post(
        "/api/plugins/upload",
        files={"file": ("test.py", sample_code, "text/x-python")},
        headers={"X-ULPF-Role": "VIEWER"}
    )
    assert resp.status_code == 403

def test_at22_audit_logging():
    resp = client.get("/api/audit-logs", headers={"X-ULPF-Role": "ANALYST"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_at23_parser_failures_preserve_raw_data():
    raw_garbage = "RANDOM_CORRUPTED_BYTES_WITHOUT_PARSER_12345"
    resp = client.post("/api/ingest", json={"raw_log": raw_garbage, "source_id": "fail-preserve"})
    raw_id = resp.json()["id"]
    raw_row = app.state.event_store.get_raw_event(raw_id)
    assert raw_row is not None
    assert raw_row["raw_log"] == raw_garbage

def test_at24_event_reprocessing():
    raw = "%ASA-6-302013: Built outbound TCP connection 8888 for outside:203.0.113.5/80 to inside:10.0.0.100/54321"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "reprocess-src"})
    evt_id = resp.json()["id"]
    rep_res = client.post(f"/api/events/{evt_id}/reprocess", headers={"X-ULPF-Role": "ANALYST"})
    assert rep_res.status_code == 200
    assert rep_res.json()["success"] is True
